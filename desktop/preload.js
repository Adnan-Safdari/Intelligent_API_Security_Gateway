const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("iasg", {
  getState: () => ipcRenderer.invoke("get-state"),
  onStatus: (callback) => ipcRenderer.on("status", (_event, status) => callback(status)),
  onLog: (callback) => ipcRenderer.on("log", (_event, lines) => callback(lines)),
  retry: () => ipcRenderer.send("retry"),
  openDocker: () => ipcRenderer.send("open-docker"),
  startDocker: () => ipcRenderer.send("start-docker"),
  openHelp: (url) => ipcRenderer.send("open-help", url),
  openDashboard: () => ipcRenderer.send("open-dashboard"),
});
