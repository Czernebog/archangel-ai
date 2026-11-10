'use strict';
const { app, BrowserWindow, Menu, shell, dialog, session } = require('electron');
const SITE = 'https://archangel-ai-czernebog.onrender.com/';
const SITE_ORIGIN = new URL(SITE).origin;
let mainWindow;
const isSite = url => {
  try { return new URL(url).origin === SITE_ORIGIN; } catch { return false; }
};
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280, height: 830, minWidth: 390, minHeight: 560,
    backgroundColor: '#090909', show: false, title: 'ARCHANGEL AI ПОМОЩЬ',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false, contextIsolation: true, sandbox: true,
      webSecurity: true, webviewTag: false, devTools: true
    }
  });
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url).catch(() => {});
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isSite(url)) {
      event.preventDefault();
      if (/^https:\/\//.test(url)) shell.openExternal(url).catch(() => {});
    }
  });
  mainWindow.webContents.on('did-fail-load', (_event, code, desc, _url, isMainFrame) => {
    if (!isMainFrame || code === -3) return;
    const choice = dialog.showMessageBoxSync(mainWindow, {
      type: 'warning', title: 'ARCHANGEL AI',
      message: 'Нет подключения к серверу ARCHANGEL.',
      detail: 'Проверь интернет и доступность сайта.\n' + String(desc || ''),
      buttons: ['Повторить', 'Закрыть'], defaultId: 0
    });
    if (choice === 0) mainWindow.loadURL(SITE);
  });
  mainWindow.loadURL(SITE);
}
app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const sameOrigin = isSite(details.requestingUrl || webContents.getURL());
    callback(sameOrigin && permission === 'media');
  });
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
