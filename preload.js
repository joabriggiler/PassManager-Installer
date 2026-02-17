const { contextBridge, ipcRenderer, clipboard } = require("electron");

contextBridge.exposeInMainWorld("pm", {
    window: {
        minimize: () => ipcRenderer.send("minimize-app"),
        maximize: () => ipcRenderer.send("maximize-app"),
        close: () => ipcRenderer.send("close-app"),
    },
    clipboard: {
        writeText: (t) => clipboard.writeText(String(t ?? "")),
    },
});