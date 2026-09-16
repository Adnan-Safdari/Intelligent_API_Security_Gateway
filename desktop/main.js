const { app, BrowserWindow, Menu, ipcMain, shell } = require("electron");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { fileURLToPath } = require("node:url");

// Stamped by the release workflow, so a fork's build follows the fork's releases.
const REPO =
  require("./package.json").iasgRepo || "Adnan-Safdari/Intelligent_API_Security_Gateway";
const RELEASE_API =
  process.env.IASG_RELEASE_API || `https://api.github.com/repos/${REPO}/releases/latest`;
const COMPOSE_ASSET = "docker-compose.release.yml";
const PROJECT = "iasg";
const DASHBOARD = "http://127.0.0.1:5177";
const DOCKER_DOWNLOAD = "https://www.docker.com/products/docker-desktop/";
const HEALTH_TIMEOUT_MS = 5 * 60 * 1000;
const LOG_LINES = 200;

const dataDir = app.getPath("userData");
const STATE_FILE = path.join(dataDir, "state.json");
const COMPOSE_FILE = path.join(dataDir, "compose.yml");
const NEXT_COMPOSE_FILE = path.join(dataDir, "compose.next.yml");

// Apps launched from Finder get a minimal PATH that does not include docker.
if (process.platform === "darwin") {
  process.env.PATH = [
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
    process.env.PATH,
  ].join(":");
} else if (process.platform === "win32") {
  process.env.PATH = `${process.env.PATH};C:\\Program Files\\Docker\\Docker\\resources\\bin`;
}

let win = null;
let status = { phase: "checking", message: "Starting…" };
let logBuffer = [];
let busy = false;
let stackStarted = false;
let quitting = false;
let launcherUpdate = null;

// `win?.` is not enough: closing the window destroys the BrowserWindow but
// leaves the variable pointing at it, and every property access on a destroyed
// object throws "Object has been destroyed". That is reachable during quit --
// window-all-closed fires after the window is gone -- so the handler that stops
// the containers threw before it got to them.
function liveWindow() {
  return win && !win.isDestroyed() ? win : null;
}

function setStatus(phase, message) {
  status = { phase, message };
  liveWindow()?.webContents.send("status", status);
}

function log(text) {
  const lines = String(text).split(/\r?\n/).filter((line) => line.trim());
  if (lines.length === 0) return;
  logBuffer = logBuffer.concat(lines).slice(-LOG_LINES);
  liveWindow()?.webContents.send("log", lines);
}

function docker(args, { version, quiet = false } = {}) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    if (version) env.IASG_VERSION = version;
    let child;
    try {
      child = spawn("docker", args, { env });
    } catch (err) {
      resolve({ code: -1, output: err.message });
      return;
    }
    let output = "";
    const collect = (chunk) => {
      output += chunk;
      if (!quiet) log(chunk.toString());
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.on("error", (err) => resolve({ code: -1, output: err.message }));
    child.on("close", (code) => resolve({ code, output }));
  });
}

function compose(file, args, version) {
  return docker(["compose", "-p", PROJECT, "-f", file, ...args], { version });
}

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
  } catch {
    return {};
  }
}

// file:// URLs let a release be simulated locally without publishing one.
async function fetchText(url) {
  if (url.startsWith("file:")) return fs.readFileSync(fileURLToPath(url), "utf8");
  const res = await fetch(url, {
    headers: { "User-Agent": "iasg-desktop", Accept: "application/vnd.github+json" },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`);
  return res.text();
}

function isNewer(candidate, current) {
  const a = candidate.split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
  const b = current.split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  }
  return false;
}

// Returns the version to run: the latest release when it downloads cleanly,
// otherwise whatever ran last time.
async function resolveVersion() {
  const state = readState();
  let release = null;
  try {
    release = JSON.parse(await fetchText(RELEASE_API));
  } catch (err) {
    log(`Could not check for updates: ${err.message}`);
  }

  if (release?.tag_name) {
    const version = release.tag_name.replace(/^v/, "");
    if (app.isPackaged && isNewer(version, app.getVersion())) {
      launcherUpdate = { version, url: release.html_url };
      buildMenu();
    }

    const asset = (release.assets || []).find((a) => a.name === COMPOSE_ASSET);
    const needsDownload = version !== state.version || !fs.existsSync(COMPOSE_FILE);
    if (needsDownload && !asset) {
      log(`Release ${release.tag_name} has no ${COMPOSE_ASSET}; keeping the current version.`);
    } else if (needsDownload) {
      setStatus("updating", `Downloading IASG ${version}. The first download can take several minutes.`);
      try {
        fs.mkdirSync(dataDir, { recursive: true });
        fs.writeFileSync(NEXT_COMPOSE_FILE, await fetchText(asset.browser_download_url));
        const pull = process.env.IASG_SKIP_PULL
          ? { code: 0 }
          : await compose(NEXT_COMPOSE_FILE, ["pull"], version);
        if (pull.code === 0) {
          fs.renameSync(NEXT_COMPOSE_FILE, COMPOSE_FILE);
          fs.writeFileSync(STATE_FILE, JSON.stringify({ version }));
          return version;
        }
        log("Downloading the update failed; keeping the current version.");
      } catch (err) {
        log(`Update failed: ${err.message}`);
      }
      fs.rmSync(NEXT_COMPOSE_FILE, { force: true });
    }
  }

  if (state.version && fs.existsSync(COMPOSE_FILE)) return state.version;
  throw new Error(
    "IASG has not been downloaded yet and GitHub could not be reached. Check your internet connection, then press Retry.",
  );
}

async function dashboardHealthy() {
  try {
    const res = await fetch(`${DASHBOARD}/api/health`, { signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}

async function waitForDashboard() {
  const deadline = Date.now() + HEALTH_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (quitting) return false;
    if (await dashboardHealthy()) return true;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return false;
}

async function boot() {
  if (busy || quitting) return;
  busy = true;
  try {
    showStatusPage();
    setStatus("checking", "Checking Docker…");
    if ((await docker(["--version"], { quiet: true })).code !== 0) {
      setStatus("no-docker", "Docker Desktop is not installed. Install it, start it, then press Retry.");
      return;
    }
    if ((await docker(["info"], { quiet: true })).code !== 0) {
      setStatus("docker-stopped", "Docker Desktop is not running. Start it, wait until it says it is running, then press Retry.");
      return;
    }
    if ((await docker(["compose", "version"], { quiet: true })).code !== 0) {
      setStatus("error", "Docker Compose is missing. Update Docker Desktop, then press Retry.");
      return;
    }

    setStatus("checking", "Checking for updates…");
    let version;
    try {
      version = await resolveVersion();
    } catch (err) {
      setStatus("error", err.message);
      return;
    }

    setStatus("starting", `Starting IASG ${version}…`);
    stackStarted = true;
    const up = await compose(COMPOSE_FILE, ["up", "-d", "--remove-orphans"], version);
    if (up.code !== 0) {
      setStatus(
        "error",
        "The containers did not start. If the log mentions a port, something else is using 5177, 8082, 5175 or 5002.",
      );
      return;
    }

    setStatus("waiting", "Waiting for the dashboard to come up…");
    if (!(await waitForDashboard())) {
      if (quitting) return;
      await compose(COMPOSE_FILE, ["logs", "--tail", "100"], version);
      setStatus("error", "The dashboard did not come up within 5 minutes. The log below shows why.");
      return;
    }

    setStatus("ready", `IASG ${version} is running.`);
    liveWindow()?.loadURL(DASHBOARD);
  } finally {
    busy = false;
  }
}

function showStatusPage() {
  const live = liveWindow();
  if (live && !live.webContents.getURL().startsWith("file:")) {
    live.loadFile(path.join(__dirname, "status.html"));
  }
}

function buildMenu() {
  const iasgMenu = [
    { label: "Open Dashboard", click: () => status.phase === "ready" && liveWindow()?.loadURL(DASHBOARD) },
    { label: "Show Status and Logs", click: showStatusPage },
    { label: "Restart", click: boot },
  ];
  if (launcherUpdate) {
    iasgMenu.push(
      { type: "separator" },
      {
        label: `Download Launcher ${launcherUpdate.version}…`,
        click: () => shell.openExternal(launcherUpdate.url),
      },
    );
  }
  iasgMenu.push({ type: "separator" }, { label: "Stop IASG and Quit", accelerator: "CmdOrCtrl+Q", click: () => app.quit() });

  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      ...(process.platform === "darwin" ? [{ role: "appMenu" }] : []),
      { label: "IASG", submenu: iasgMenu },
      { role: "editMenu" },
      { role: "viewMenu" },
    ]),
  );
}

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 900,
    title: "IASG",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  const allowed = (url) => url.startsWith(`${DASHBOARD}/`) || url === DASHBOARD || url.startsWith("file:");
  win.webContents.on("will-navigate", (event, url) => {
    if (!allowed(url)) {
      event.preventDefault();
      if (/^https?:/.test(url)) shell.openExternal(url);
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  win.loadFile(path.join(__dirname, "status.html"));
}

ipcMain.handle("get-state", () => ({ status, log: logBuffer }));
ipcMain.on("retry", () => boot());
ipcMain.on("open-docker", () => shell.openExternal(DOCKER_DOWNLOAD));
ipcMain.on("open-dashboard", () => status.phase === "ready" && liveWindow()?.loadURL(DASHBOARD));

app.whenReady().then(() => {
  buildMenu();
  createWindow();
  boot();
});

app.on("window-all-closed", () => app.quit());

// Stop the containers before exiting, keeping their data volumes.
app.on("before-quit", (event) => {
  if (quitting || !stackStarted) return;
  event.preventDefault();
  quitting = true;
  showStatusPage();
  setStatus("stopping", "Stopping IASG…");
  // The compose file requires IASG_VERSION even to tear down.
  compose(COMPOSE_FILE, ["down"], readState().version).finally(() => app.exit(0));
});
