/**
 * NetLogic Preload — Secure context bridge between renderer and main process.
 * Only exposes explicitly defined APIs to the renderer (no full Node access).
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('netlogic', {
  // ── Scan Control ────────────────────────────────────────────────────────────
  startScan: (config) => ipcRenderer.send('scan:start', config),
  stopScan:  ()       => ipcRenderer.send('scan:stop'),

  // ── Scan Event Listeners ────────────────────────────────────────────────────
  onScanStarted:  (cb) => ipcRenderer.on('scan:started',  (_, d) => cb(d)),
  onScanPort:     (cb) => ipcRenderer.on('scan:port',     (_, d) => cb(d)),
  onScanVuln:     (cb) => ipcRenderer.on('scan:vuln',     (_, d) => cb(d)),
  onScanOSINT:    (cb) => ipcRenderer.on('scan:osint',    (_, d) => cb(d)),
  onScanHost:     (cb) => ipcRenderer.on('scan:host',     (_, d) => cb(d)),
  onScanProgress: (cb) => ipcRenderer.on('scan:progress', (_, d) => cb(d)),
  onScanDone:     (cb) => ipcRenderer.on('scan:done',     (_, d) => cb(d)),
  onScanStopped:  (cb) => ipcRenderer.on('scan:stopped',  (_, d) => cb(d)),
  onScanError:    (cb) => ipcRenderer.on('scan:error',    (_, d) => cb(d)),
  onScanLog:      (cb) => ipcRenderer.on('scan:log',      (_, d) => cb(d)),

  // Remove all scan listeners (call before starting new scan)
  removeAllScanListeners: () => {
    for (const ch of ['scan:started','scan:port','scan:vuln','scan:osint',
                       'scan:host','scan:progress','scan:done','scan:stopped',
                       'scan:error','scan:log']) {
      ipcRenderer.removeAllListeners(ch);
    }
  },

  // ── Reports ─────────────────────────────────────────────────────────────────
  exportReport: (payload) => ipcRenderer.invoke('report:export', payload),

  // ── System Info ─────────────────────────────────────────────────────────────
  getVersions:   () => ipcRenderer.invoke('app:versions'),
  checkPython:   () => ipcRenderer.invoke('python:check'),

  // ── Window Controls ─────────────────────────────────────────────────────────
  minimize:  () => ipcRenderer.send('window:minimize'),
  maximize:  () => ipcRenderer.send('window:maximize'),
  closeApp:  () => ipcRenderer.send('window:close'),
});
