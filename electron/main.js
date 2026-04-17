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
    // Prioritize python3 specifically (important for Linux/Mac where 'python' is often 2.7)
    for (const candidate of ['python3', 'python', 'py']) {
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
let isStoppingManual = false;

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
    icon: path.join(__dirname, '..', 'build', 'netlogic.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
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
  const iconPath = path.join(__dirname, '..', 'build', 'netlogic.png');
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
    isStoppingManual = false;
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
    if (!isStoppingManual) {
      event.reply('scan:done', { exitCode: code });
    }
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
    isStoppingManual = true;
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

  const result = await dialog.showSaveDialog(mainWindow || null, {
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
  const target = data.target || 'unknown';
  const ip = data.ip || '0.0.0.0';
  const host = data.hostname || 'unknown';
  const headers = ['Target', 'IP', 'Hostname', 'Type/ID', 'Severity', 'Score', 'Port', 'Service', 'Detail/Description', 'Remediation'];
  const rows = [headers];
  
  // Vulnerabilities (CVEs)
  for (const vuln of (data.vulnerabilities || [])) {
    for (const cve of (vuln.cves || [])) {
      rows.push([
        target, ip, host,
        cve.id || 'CVE',
        cve.severity || 'INFO',
        cve.cvss_score || '0.0',
        vuln.port || '0',
        vuln.service || 'unknown',
        `"${(cve.description || '').replace(/"/g, '""')}"`,
        `"${(cve.remediation || 'Apply security updates.').replace(/"/g, '""')}"`
      ]);
    }
  }

  // Audit Findings (Headers, TLS, WAF, DNS)
  for (const f of (data.audit || [])) {
    rows.push([
      target, ip, host,
      f.type || 'AUDIT',
      f.severity || 'INFO',
      '-',
      '0',
      'host',
      `"${f.title}: ${(f.detail || '').replace(/"/g, '""')}"`,
      `"${(f.remediation || '').replace(/"/g, '""')}"`
    ]);
  }

  return rows.map(r => r.join(',')).join('\r\n');
}

function generateHTMLReport(data) {
  const ports = (data.ports || []);
  const vulns = (data.vulnerabilities || []).flatMap(vm =>
    (vm.cves || []).map(cve => ({ ...cve, port: vm.port, service: vm.service }))
  ).sort((a,b) => (b.cvss_score || 0) - (a.cvss_score || 0));
  const audit = (data.audit || []);

  const criticalCount = vulns.filter(c => c.severity === 'CRITICAL').length;
  const highCount = vulns.filter(c => c.severity === 'HIGH').length;
  
  // Calculate risk score same as app
  const maxCvss = Math.max(0, ...vulns.map(c => c.cvss_score || 0));
  const hasExploit = vulns.some(v => v.exploit_available);
  const riskScore = Math.min(maxCvss * (hasExploit ? 1.1 : 1.0), 10.0);
  const riskColor = riskScore >= 9 ? '#ff4444' : riskScore >= 7 ? '#ff8c42' : riskScore >= 4 ? '#ffcc44' : '#44dd88';

  const portRows = ports.map(p => `
    <tr>
      <td><span class="p-num">${p.port}</span></td>
      <td>${p.service || 'unknown'}</td>
      <td class="v-str">${(p.banner?.product || '') + ' ' + (p.banner?.version || '')}</td>
      <td>${p.tls ? '<span class="tls-yes">✓ TLS</span>' : '<span class="tls-no">─</span>'}</td>
    </tr>`).join('');

  const vulnCards = vulns.map(cve => {
    const sev = (cve.severity || 'UNKNOWN').toUpperCase();
    return `
    <div class="card">
      <div class="card-header">
        <span class="badge sev-${sev}">${sev}</span>
        <span class="cve-id">${cve.id || '–'}</span>
        <span class="cvss">CVSS ${cve.cvss_score?.toFixed(1) || '?'}</span>
      </div>
      <div class="card-body">
        <div class="desc">${cve.description || ''}</div>
        <div class="meta">
          <span>Port ${cve.port}/${cve.service || '?'}</span>
          ${cve.remediation ? `<div class="remediation"><strong>Remediation:</strong> ${cve.remediation}</div>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');

  const auditCards = audit.map(f => `
    <div class="card audit-card">
      <div class="card-header">
        <span class="badge audit-badge">${f.type}</span>
        <span class="cve-id">${f.title}</span>
        <span class="cvss">${f.severity}</span>
      </div>
      <div class="card-body">
        <div class="desc pre">${f.detail}</div>
        <div class="meta">
          <div class="remediation ok"><strong>Remediation:</strong> ${f.remediation}</div>
        </div>
      </div>
    </div>`).join('');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NetLogic Report — ${data.target}</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #080b10; --panel: #0d1117; --surface: #131820; --border: #1e2840;
      --text: #cdd9e5; --text-dim: #6a7a8f; --accent: #00d4ff;
      --critical: #ff4444; --high: #ff8c42; --medium: #ffcc44; --low: #44dd88; --info: #66aaff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 13px; line-height: 1.6; padding: 40px; }
    .container { max-width: 1000px; margin: 0 auto; }
    
    header { margin-bottom: 40px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }
    h1 { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 24px; color: #fff; letter-spacing: 0.05em; margin-bottom: 10px; }
    h1 span { color: var(--accent); }
    .target-info { color: var(--text-dim); font-size: 11px; }

    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
    .stat-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
    .stat-num { font-family: 'Syne', sans-serif; font-size: 32px; font-weight: 800; color: var(--accent); display: block; }
    .stat-num.red { color: var(--critical); } .stat-num.orange { color: var(--high); }
    .stat-lbl { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-dim); }

    .risk-section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 30px; }
    .risk-header { display: flex; justify-content: space-between; margin-bottom: 10px; font-size: 11px; }
    .risk-bar { height: 8px; background: #1a2030; border-radius: 4px; overflow: hidden; }
    .risk-fill { height: 100%; border-radius: 4px; transition: width 1s; width: ${riskScore * 10}%; background: linear-gradient(90deg, var(--low), var(--medium), var(--high), var(--critical)); }

    h2 { font-family: 'Syne', sans-serif; font-size: 14px; text-transform: uppercase; letter-spacing: 0.15em; color: var(--text-dim); margin: 40px 0 15px; border-left: 3px solid var(--accent); padding-left: 12px; }
    
    table { width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 20px; }
    th { background: var(--surface); padding: 12px; text-align: left; font-size: 10px; text-transform: uppercase; color: var(--text-dim); border-bottom: 1px solid var(--border); }
    td { padding: 12px; border-bottom: 1px solid #151e2e; }
    .p-num { color: var(--accent); font-weight: 600; }
    .v-str { color: var(--text-dim); font-size: 11px; }
    .tls-yes { color: var(--low); font-size: 11px; } .tls-no { color: var(--text-dim); opacity: 0.5; }

    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 15px; overflow: hidden; }
    .card-header { background: var(--surface); padding: 10px 15px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid var(--border); }
    .badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
    .sev-CRITICAL { background: rgba(255, 68, 68, 0.1); color: var(--critical); border: 1px solid var(--critical); }
    .sev-HIGH { background: rgba(255, 140, 66, 0.1); color: var(--high); border: 1px solid var(--high); }
    .sev-MEDIUM { background: rgba(255, 204, 68, 0.1); color: var(--medium); border: 1px solid var(--medium); }
    .sev-LOW { background: rgba(68, 221, 136, 0.1); color: var(--low); border: 1px solid var(--low); }
    .cve-id { font-weight: 600; color: #fff; }
    .cvss { margin-left: auto; font-size: 11px; color: var(--text-dim); }
    .card-body { padding: 15px; }
    .desc { font-size: 12px; color: var(--text); margin-bottom: 12px; }
    .pre { white-space: pre-wrap; font-size: 10px; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; }
    .meta { font-size: 11px; color: var(--text-dim); display: flex; flex-direction: column; gap: 8px; }
    .remediation { color: var(--medium); border-top: 1px solid #1a2030; padding-top: 10px; margin-top: 5px; }
    .remediation.ok { color: var(--low); }
    .audit-card { border-left: 4px solid var(--info); }
    .audit-badge { background: rgba(102, 170, 255, 0.1); color: var(--info); border: 1px solid var(--info); }

    footer { margin-top: 60px; text-align: center; font-size: 10px; color: var(--text-dim); border-top: 1px solid var(--border); padding-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>NET<span>LOGIC</span> SECURITY REPORT</h1>
      <div class="target-info">
        TARGET: ${data.target} &nbsp;//&nbsp; 
        IP: ${data.ip || 'UNKNOWN'} &nbsp;//&nbsp; 
        TIME: ${new Date().toISOString().replace('T', ' ').slice(0, 19)}
      </div>
    </header>

    <div class="summary-grid">
      <div class="stat-card"><span class="stat-num">${ports.length}</span><span class="stat-lbl">Open Ports</span></div>
      <div class="stat-card"><span class="stat-num red">${criticalCount}</span><span class="stat-lbl">Critical</span></div>
      <div class="stat-card"><span class="stat-num orange">${highCount}</span><span class="stat-lbl">High</span></div>
      <div class="stat-card"><span class="stat-num">${vulns.length}</span><span class="stat-lbl">Total CVEs</span></div>
    </div>

    <div class="risk-section">
      <div class="risk-header">
        <span class="stat-lbl">OVERALL RISK SCORE</span>
        <span class="stat-num" style="font-size: 14px; color: ${riskColor}">${riskScore.toFixed(1)} / 10.0</span>
      </div>
      <div class="risk-bar">
        <div class="risk-fill"></div>
      </div>
    </div>

    ${ports.length > 0 ? `
    <h2>Target Infrastructure</h2>
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>TLS</th></tr></thead>
      <tbody>${portRows}</tbody>
    </table>` : ''}

    ${vulns.length > 0 ? `
    <h2>Vulnerability Assessment</h2>
    <div class="vuln-list">${vulnCards}</div>` : ''}

    ${audit.length > 0 ? `
    <h2>Security Configuration Audit</h2>
    <div class="audit-list">${auditCards}</div>` : ''}

    <footer>
      NETLOGIC v2.0.0 &nbsp;//&nbsp; AUTHORIZED SECURITY ASSESSMENT &nbsp;//&nbsp; CONFIDENTIAL
    </footer>
  </div>
</body>
</html>`;
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