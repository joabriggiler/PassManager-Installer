const { app, BrowserWindow, ipcMain, Menu } = require('electron');

const path = require('path');

if (!app.isPackaged && process.env.ELECTRON_RELOAD === '1') {
    require('electron-reloader')(module);
}

let win; // Declaramos la variable fuera para tener acceso global en este archivo

function createWindow() {
    win = new BrowserWindow({
        width: 400,
        height: 700,
        minWidth: 350,
        minHeight: 500,
        resizable: true,
        frame: false,
        icon: path.join(__dirname, 'favicon.ico'),
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: true,
            devTools: false,
        }
    });

    win.loadFile(path.join(__dirname, 'index.html'));
    if (!app.isPackaged) {
        //win.webContents.openDevTools();
    }

    // (Opcional) elimina el menú para evitar "Reload" desde menú
    Menu.setApplicationMenu(null);

    // Bloquear recarga por teclado (Ctrl+Shift+R / Ctrl+R / F5) y DevTools
    win.webContents.on('before-input-event', (event, input) => {
        if (input.type !== 'keyDown') return;

        const isMac = process.platform === 'darwin';
        const ctrlOrCmd = isMac ? input.meta : input.control;
        const key = (input.key || '').toLowerCase();

        // Reload shortcuts
        if ((ctrlOrCmd && key === 'r') || key === 'f5') {
            event.preventDefault();
            return;
        }

        // Hard reload (Ctrl+Shift+R)
        if (ctrlOrCmd && input.shift && key === 'r') {
            event.preventDefault();
            return;
        }

        // (Recomendado) Bloquear DevTools shortcuts
        if (key === 'f12' || (ctrlOrCmd && input.shift && ['i', 'j', 'c'].includes(key))) {
            event.preventDefault();
            return;
        }
    });

    // SOLUCIÓN AL BUG DE INPUTS: Forzar foco al restaurar o maximizar
    win.on('restore', () => win.webContents.focus());
    win.on('maximize', () => win.webContents.focus());
    win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    win.webContents.on("will-navigate", (e) => e.preventDefault());
    win.webContents.on("devtools-opened", () => {
        win.webContents.closeDevTools();
    });
}

app.whenReady().then(createWindow);

// Lógica mejorada usando la instancia 'win' directamente
ipcMain.on('minimize-app', () => {
    if (win) win.minimize();
});

ipcMain.on('maximize-app', () => {
    if (!win) return;
    if (win.isMaximized()) {
        win.unmaximize();
    } else {
        win.maximize();
    }
    // Forzamos que el contenido web recupere el foco tras el cambio de tamaño
    win.webContents.focus();
});

ipcMain.on('close-app', () => {
    app.quit();
});