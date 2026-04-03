/**
 * NetLogic - Electron Main Process
 * Manages app lifecycle, Python subprocess bridge, and IPC communication.
 */

const { app, BrowserWindow, ipcMain, shell, dialog, Menu, Tray, nativeTheme } = require('electron');
const path = require('path');
const { spawn, execFile } = require('child_process');
const fs = require('fs');
const os = require('os');

// ─── Constants ───────────────────────────────────────────────────────────────

const IS_DEV = process.argv.includes('--dev');
const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';

// ─── Python Runtime Resolution ───────────────────────────────────────────────

/**
 * Locate the Python executable to use.
 * Priority: bundled PyInstaller binary → system python3 → python
 */
function getPythonPath() {
  const engineName = IS_WIN ? 'netlogic_engine.exe' : 'netlogic_engine';

  // 1. High Priority: System Python + netlogic.py script (ensure latest code)
  const scriptPath = path.join(__dirname, '..', 'netlogic.py');
  if (fs.existsSync(scriptPath)) {
    for (const candidate of ['python', 'python3', 'py']) {
      try {
        const result = require('child_process').spawnSync(
          candidate, ['--version'], { timeout: 2000 }
        );
        if (result.status === 0) {
          console.log(`[python] Using system ${candidate} with script: ${scriptPath}`);
          return { exe: candidate, script: scriptPath };
        }
      } catch { }
    }
  }

  // 2. Low Priority: Bundled engine (fallback for standalone production installs)
  const candidateDirs = [
    process.resourcesPath,
    path.join(process.resourcesPath, 'python_dist'),
    path.join(__dirname, '..', 'python_dist'),
    path.join(__dirname, '..'),
    path.dirname(app.getPath('exe')),
    path.join(path.dirname(app.getPath('exe')), 'resources', 'python_dist'),
    path.join(path.dirname(app.getPath('exe')), 'resources'),
  ];

  for (const dir of candidateDirs) {
    const enginePath = path.join(dir, engineName);
    if (fs.existsSync(enginePath)) {
      console.log(`[python] Using bundled engine at: ${enginePath}`);
      return { exe: enginePath, script: null };
    }
  }

  return null;
}

// ─── Window Management ────────────────────────────────────────────────────────

let mainWindow = null;
let tray = null;
let activeScanProcess = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 600,
    frame: false,           // Custom titlebar
    transparent: false,
    backgroundColor: '#0a0d12',
    show: false,
    icon: path.join(__dirname, '..', 'netlogic.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    titleBarStyle: IS_MAC ? 'hiddenInset' : 'hidden',
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (IS_DEV) mainWindow.webContents.openDevTools();
  });

  mainWindow.on('close', (e) => {
    // Keep running in tray if a scan is active
    if (activeScanProcess && !app.isQuitting) {
      e.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => { mainWindow = null; });
  return mainWindow;
}

function createTray() {
  const iconPath = path.join(__dirname, '..', 'netlogic.png');
  if (!fs.existsSync(iconPath)) return;

  tray = new Tray(iconPath);
  const menu = Menu.buildFromTemplate([
    { label: 'Show NetLogic', click: () => { mainWindow?.show(); } },
    { type: 'separator' },
    { label: 'Quit', click: () => { app.isQuitting = true; app.quit(); } },
  ]);
  tray.setToolTip('NetLogic');
  tray.setContextMenu(menu);
  tray.on('double-click', () => mainWindow?.show());
}

// ─── Python Subprocess Bridge ─────────────────────────────────────────────────

/**
 * Launch a scan via Python subprocess, streaming JSON events back to renderer.
 * The Python engine emits newline-delimited JSON objects:
 *   {"type": "port", "data": {...}}
 *   {"type": "vuln", "data": {...}}
 *   {"type": "osint", "data": {...}}
 *   {"type": "done", "data": {...}}
 *   {"type": "error", "message": "..."}
 */
function startScan(event, config) {
  if (activeScanProcess) {
    console.log('[scan] already running, aborting second start');
    return;
  }

  const python = getPythonPath();
  if (!python) {
    event.reply('scan:error', { message: 'Python not found. Install Python 3.9+ and restart.' });
    return;
  }

  const args = buildPythonArgs(config, python.script);
  const cmd = python.exe;

  console.log(`[scan] ${cmd} ${args.join(' ')}`);

  try {
    activeScanProcess = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } catch (err) {
    event.reply('scan:error', { message: `Failed to start scanner: ${err.message}` });
    return;
  }

  let buffer = '';

  activeScanProcess.stdout.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep partial line

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const msg = JSON.parse(trimmed);
        routeScanMessage(event, msg);
      } catch {
        // Non-JSON line (debug output) — send as log
        event.reply('scan:log', { text: trimmed });
      }
    }
  });

  activeScanProcess.stderr.on('data', (chunk) => {
    const text = chunk.toString('utf8').trim();
    if (text) event.reply('scan:log', { text, level: 'warn' });
  });

  activeScanProcess.on('close', (code) => {
    activeScanProcess = null;
    event.reply('scan:done', { exitCode: code });
  });

  activeScanProcess.on('error', (err) => {
    activeScanProcess = null;
    event.reply('scan:error', { message: err.message });
  });

  event.reply('scan:started', { target: config.target });
}

function buildPythonArgs(config, scriptPath) {
  const args = [];
  if (scriptPath) args.push(scriptPath);

  args.push(config.target);
  args.push('--json-stream');
  args.push('--ports', config.portSet || 'quick');
  if (config.full) args.push('--full');
  if (config.osint) args.push('--osint');
  if (config.tls) args.push('--tls');
  if (config.headers) args.push('--headers');
  if (config.dns) args.push('--dns');
  if (config.stack) args.push('--stack');
  if (config.takeover) args.push('--takeover');
  if (config.probe) args.push('--probe');
  if (config.cidr) args.push('--cidr');
  if (config.timeout) args.push('--timeout', String(config.timeout));
  if (config.threads) args.push('--threads', String(config.threads));
  if (config.minCvss) args.push('--min-cvss', String(config.minCvss));
  args.push('--no-color');

  return args;
}

function routeScanMessage(event, msg) {
  switch (msg.type) {
    case 'port': event.reply('scan:port', msg.data); break;
    case 'vuln': event.reply('scan:vuln', msg.data); break;
    case 'osint': event.reply('scan:osint', msg.data); break;
    case 'host': event.reply('scan:host', msg.data); break;
    case 'progress': event.reply('scan:progress', msg.data); break;
    case 'tls': event.reply('scan:tls', msg.data); break;
    case 'headers': event.reply('scan:headers', msg.data); break;
    case 'stack': event.reply('scan:stack', msg.data); break;
    case 'dns': event.reply('scan:dns', msg.data); break;
    case 'takeover': event.reply('scan:takeover', msg.data); break;
    case 'service_probes': event.reply('scan:service-probes', msg.data); break;
    case 'log': event.reply('scan:log', msg.data); break;
    case 'error': event.reply('scan:error', { message: msg.message }); break;
    case 'done': event.reply('scan:done', msg.data); break;
    default: event.reply('scan:log', { text: JSON.stringify(msg) });
  }
}

function stopScan() {
  if (activeScanProcess) {
    activeScanProcess.kill('SIGKILL');  // Aggressive kill to prevent ghost logs
    activeScanProcess = null;
    return true;
  }
  return false;
}

// ─── Report Export ────────────────────────────────────────────────────────────

async function exportReport(event, { format, data }) {
  const filters = {
    json: [{ name: 'JSON', extensions: ['json'] }],
    html: [{ name: 'HTML Report', extensions: ['html'] }],
    csv: [{ name: 'CSV', extensions: ['csv'] }],
  };

  const result = await dialog.showSaveDialog(mainWindow, {
    title: 'Save NetLogic Report',
    defaultPath: `netlogic_${data.target}_${Date.now()}.${format}`,
    filters: filters[format] || filters.json,
  });

  if (result.canceled) return { saved: false };

  try {
    let content = '';
    if (format === 'json') {
      content = JSON.stringify(data, null, 2);
    } else if (format === 'html') {
      content = generateHTMLReport(data);
    } else if (format === 'csv') {
      content = generateCSV(data);
    }
    fs.writeFileSync(result.filePath, content, 'utf8');
    shell.showItemInFolder(result.filePath);
    return { saved: true, path: result.filePath };
  } catch (err) {
    return { saved: false, error: err.message };
  }
}

function generateCSV(data) {
  const rows = [['CVE ID', 'Severity', 'CVSS', 'Port', 'Service', 'Product', 'Version', 'Description']];
  for (const vuln of (data.vulnerabilities || [])) {
    for (const cve of (vuln.cves || [])) {
      rows.push([
        cve.id, cve.severity, cve.cvss_score,
        vuln.port, vuln.service, vuln.product || '', vuln.version || '',
        `"${(cve.description || '').replace(/"/g, '""')}"`,
      ]);
    }
  }
  return rows.map(r => r.join(',')).join('\n');
}

function generateHTMLReport(data) {
  // Delegate to Python for full report, or generate inline
  const ports = (data.ports || []);
  const vulns = (data.vulnerabilities || []);
  const critical = vulns.flatMap(v => v.cves || []).filter(c => c.severity === 'CRITICAL').length;
  const high = vulns.flatMap(v => v.cves || []).filter(c => c.severity === 'HIGH').length;

  const portRows = ports.map(p => `
    <tr>
      <td>${p.port}</td><td>${p.service || '–'}</td>
      <td>${(p.banner?.product || '') + ' ' + (p.banner?.version || '')}</td>
      <td>${p.tls ? '✓' : '–'}</td>
    </tr>`).join('');

  const vulnRows = vulns.flatMap(vm =>
    (vm.cves || []).map(cve => `
    <tr>
      <td><code>${cve.id}</code></td>
      <td style="color:${cve.severity === 'CRITICAL' ? '#f85149' : cve.severity === 'HIGH' ? '#ff7b72' : '#e3b341'}">${cve.severity}</td>
      <td>${cve.cvss_score}</td>
      <td>${vm.port}/${vm.service}</td>
      <td>${cve.description?.slice(0, 100)}…</td>
    </tr>`)
  ).join('');

  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>NetLogic Report — ${data.target}</title>
<style>
body{font-family:system-ui;background:#0d1117;color:#e6edf3;padding:2rem}
h1{color:#58a6ff}table{width:100%;border-collapse:collapse;margin:1rem 0}
th{background:#161b22;padding:.6rem;text-align:left;color:#7d8590}
td{padding:.5rem;border-bottom:1px solid #21262d}
.stat{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 2rem;margin:.5rem;text-align:center}
.num{font-size:2rem;font-weight:700;color:#58a6ff}.red{color:#f85149}.orange{color:#ff7b72}
</style></head><body>
<h1>NetLogic Security Report</h1>
<p>Target: <strong>${data.target}</strong> · IP: ${data.ip || '?'} · ${new Date().toISOString()}</p>
<div>
  <div class="stat"><div class="num">${ports.length}</div>Open Ports</div>
  <div class="stat"><div class="num red">${critical}</div>Critical CVEs</div>
  <div class="stat"><div class="num orange">${high}</div>High CVEs</div>
</div>
<h2>Open Ports</h2>
<table><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>TLS</th></tr></thead>
<tbody>${portRows || '<tr><td colspan="4">No open ports</td></tr>'}</tbody></table>
<h2>Vulnerabilities</h2>
<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Port</th><th>Description</th></tr></thead>
<tbody>${vulnRows || '<tr><td colspan="5" style="color:#3fb950">No vulnerabilities found.</td></tr>'}</tbody></table>
<p style="color:#7d8590;font-size:.8rem;margin-top:2rem">Generated by NetLogic — authorized use only.</p>
</body></html>`;
}

// ─── IPC Handlers ─────────────────────────────────────────────────────────────

ipcMain.on('scan:start', (event, config) => startScan(event, config));
ipcMain.on('scan:stop', (event) => { stopScan(); event.reply('scan:stopped'); });
ipcMain.handle('report:export', (event, payload) => exportReport(event, payload));
ipcMain.handle('app:versions', () => ({
  app: app.getVersion(),
  electron: process.versions.electron,
  node: process.versions.node,
  platform: process.platform,
}));
ipcMain.handle('python:check', () => {
  const p = getPythonPath();
  return { available: !!p, path: p?.exe };
});

// Window controls (custom titlebar)
ipcMain.on('window:minimize', () => mainWindow?.minimize());
ipcMain.on('window:maximize', () => {
  if (mainWindow?.isMaximized()) mainWindow.restore();
  else mainWindow?.maximize();
});
ipcMain.on('window:close', () => {
  app.isQuitting = true;
  mainWindow?.close();
});

// ─── App Lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
    else mainWindow?.show();
  });
});

app.on('window-all-closed', () => {
  if (!IS_MAC) app.quit();
});

app.on('before-quit', () => {
  app.isQuitting = true;
  if (activeScanProcess) activeScanProcess.kill();
});