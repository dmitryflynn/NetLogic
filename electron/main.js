/**
 * NetLogic — Electron Main Process
 *
 * The desktop app is a thin shell around the SAME React dashboard the `netlogic`
 * web command serves. On launch it spawns the headless NetLogic server
 * (netlogic_server.py — FastAPI + local agent) and loads the dashboard from it,
 * auto-logging-in with the server's generated API key. One frontend everywhere.
 */

const { app, BrowserWindow, shell, ipcMain, Menu } = require('electron');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const http = require('http');

const IS_DEV = process.argv.includes('--dev');
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';

let mainWindow = null;
let serverProcess = null;
let serverInfo = null;   // { url, api_key, port }

// ─── Python runtime resolution ──────────────────────────────────────────────

function getPython() {
  // Prefer system Python with the repo scripts (always latest code).
  const serverScript = path.join(__dirname, '..', 'netlogic_server.py');
  if (!fs.existsSync(serverScript)) return null;

  // On Windows, 'python3' is frequently a Microsoft Store stub (or a different
  // env) that lacks our deps, while 'python' is the real install. Order the
  // candidates accordingly, and — critically — VALIDATE that the interpreter can
  // actually import the server deps before committing to it.
  const order = IS_WIN ? ['python', 'py', 'python3'] : ['python3', 'python'];

  for (const candidate of order) {
    try {
      const r = spawnSync(candidate, ['-c', 'import uvicorn, fastapi'], { timeout: 8000 });
      if (r.status === 0) return { exe: candidate, script: serverScript };
    } catch { /* try next */ }
  }
  // Fallback: any interpreter that runs (the server will surface a clear error
  // about missing deps if it really can't start).
  for (const candidate of order) {
    try {
      const r = spawnSync(candidate, ['--version'], { timeout: 2500 });
      if (r.status === 0) return { exe: candidate, script: serverScript };
    } catch { /* try next */ }
  }
  return null;
}

// ─── Headless server lifecycle ──────────────────────────────────────────────

function startServer() {
  return new Promise((resolve, reject) => {
    const py = getPython();
    if (!py) {
      reject(new Error('Python 3.9+ not found. Install Python and restart NetLogic.'));
      return;
    }
    const env = { ...process.env };
    if (!env.NETLOGIC_PORT) env.NETLOGIC_PORT = '8000';

    console.log(`[server] ${py.exe} ${py.script}`);
    serverProcess = spawn(py.exe, [py.script], { env, stdio: ['ignore', 'pipe', 'pipe'] });

    let buf = '';
    let resolved = false;
    const onReady = (info) => { if (!resolved) { resolved = true; serverInfo = info; resolve(info); } };

    serverProcess.stdout.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const marker = 'NETLOGIC_SERVER ';
      const idx = buf.indexOf(marker);
      if (idx !== -1) {
        const end = buf.indexOf('\n', idx);
        const json = buf.slice(idx + marker.length, end === -1 ? undefined : end).trim();
        try { onReady(JSON.parse(json)); } catch { /* wait for full line */ }
      }
    });
    serverProcess.stderr.on('data', (c) => console.error('[server]', c.toString('utf8').trim()));
    serverProcess.on('error', (e) => { if (!resolved) reject(e); });
    serverProcess.on('close', (code) => {
      serverProcess = null;
      if (!resolved) reject(new Error(`NetLogic server exited (code ${code}) before becoming ready.`));
    });
    setTimeout(() => { if (!resolved) reject(new Error('NetLogic server start timed out.')); }, 60000);
  });
}

function waitForHealth(baseUrl, attempts = 40) {
  return new Promise((resolve) => {
    let n = 0;
    const tick = () => {
      const req = http.get(`${baseUrl}/health`, (res) => {
        res.resume();
        if (res.statusCode === 200) resolve(true);
        else retry();
      });
      req.on('error', retry);
      req.setTimeout(1500, () => { req.destroy(); retry(); });
    };
    const retry = () => { if (++n >= attempts) resolve(false); else setTimeout(tick, 500); };
    tick();
  });
}

function stopServer() {
  if (serverProcess) {
    try { serverProcess.kill(); } catch { /* already gone */ }
    serverProcess = null;
  }
}

// ─── Window management ──────────────────────────────────────────────────────

function dashboardUrl() {
  if (!serverInfo) return 'about:blank';
  // Login is handled by Clerk inside the dashboard — the desktop app just loads
  // the app and the user signs in. (The old ?apikey= auto-login was removed when
  // the API-key login system was retired; the server's api_key is now only a
  // machine credential for agents, never a human login.)
  return serverInfo.url;
}

function createWindow(loadUrl) {
  mainWindow = new BrowserWindow({
    width: 1280, height: 820, minWidth: 960, minHeight: 600,
    backgroundColor: '#0a0d12',
    show: false,
    icon: path.join(__dirname, '..', 'build', 'netlogic.png'),
    // devTools disabled in production builds — a shipped desktop app shouldn't
    // expose DevTools (Ctrl+Shift+I / F12). Still available with `--dev`.
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, devTools: IS_DEV },
  });

  if (!IS_DEV) {
    // Defense-in-depth: even with devTools:false, swallow the DevTools key combos
    // and force-close DevTools if anything manages to open it.
    mainWindow.webContents.on('before-input-event', (event, input) => {
      const key = (input.key || '').toLowerCase();
      const mod = input.control || input.meta;
      if (key === 'f12' || (mod && input.shift && (key === 'i' || key === 'j' || key === 'c'))) {
        event.preventDefault();
      }
    });
    mainWindow.webContents.on('devtools-opened', () => mainWindow.webContents.closeDevTools());
  }

  // The dashboard bundle ships with the app and changes on every update, so a
  // stale HTTP cache must never pin the UI to an old build (which would load an
  // outdated bundle and 401 against the freshly-started server). Clear first.
  mainWindow.webContents.session.clearCache()
    .catch(() => {})
    .finally(() => mainWindow.loadURL(loadUrl));
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (IS_DEV) mainWindow.webContents.openDevTools();
  });
  mainWindow.on('closed', () => { mainWindow = null; });

  // External links open in the OS browser, not inside the app window.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

function showError(message) {
  mainWindow = new BrowserWindow({
    width: 640, height: 360, backgroundColor: '#0a0d12', show: true,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true },
  });
  const html = `
    <body style="background:#0a0d12;color:#cdd9e5;font-family:system-ui,sans-serif;padding:40px">
      <h2 style="color:#ff8c42">NetLogic could not start</h2>
      <p style="color:#6a7a8f;line-height:1.6">${String(message).replace(/</g, '&lt;')}</p>
      <p style="color:#6a7a8f;font-size:12px">Ensure Python 3.9+ is installed and dependencies are available, then relaunch.</p>
    </body>`;
  mainWindow.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
}

// ─── Application menu ─────────────────────────────────────────────────────────

function buildMenu() {
  // Keep an Edit menu so clipboard (cut/copy/paste) works in inputs like the
  // API-key field, plus zoom. Reload / Force Reload / Toggle DevTools are only
  // exposed in --dev; production has no menu path to DevTools.
  const template = [
    ...(IS_MAC ? [{ role: 'appMenu' }] : []),
    { role: 'fileMenu' },
    { role: 'editMenu' },
    {
      label: 'View',
      submenu: [
        { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
        { type: 'separator' }, { role: 'togglefullscreen' },
        ...(IS_DEV
          ? [{ type: 'separator' }, { role: 'reload' }, { role: 'forceReload' }, { role: 'toggleDevTools' }]
          : []),
      ],
    },
    { role: 'windowMenu' },
  ];
  return Menu.buildFromTemplate(template);
}

// ─── App lifecycle ──────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  Menu.setApplicationMenu(buildMenu());
  try {
    const info = await startServer();
    await waitForHealth(info.url);
    createWindow(dashboardUrl());
  } catch (e) {
    console.error('[startup]', e);
    showError(e.message || String(e));
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0 && serverInfo) createWindow(dashboardUrl());
    else mainWindow?.show();
  });
});

app.on('window-all-closed', () => { if (!IS_MAC) app.quit(); });
app.on('before-quit', stopServer);
app.on('quit', stopServer);

// ─── Minimal IPC (informational only; the dashboard talks to the API directly) ──

ipcMain.handle('app:versions', () => ({
  app: app.getVersion(),
  electron: process.versions.electron,
  node: process.versions.node,
  platform: process.platform,
  server: serverInfo ? serverInfo.url : null,
}));
