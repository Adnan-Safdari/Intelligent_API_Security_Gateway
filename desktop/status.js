const statusEl = document.getElementById("status");
const messageEl = document.getElementById("message");
const logEl = document.getElementById("log");
const retryBtn = document.getElementById("retry");
const setupEl = document.getElementById("setup");
const dashboardBtn = document.getElementById("dashboard");
const detailsEl = document.getElementById("details");

const FAILED = new Set(["error", "no-docker", "docker-stopped"]);
// Waiting on Docker is not a failure to retry: the app watches for it.
const WAITING_ON_DOCKER = new Set(["no-docker", "docker-stopped"]);

const WINDOWS_GUIDE = "https://docs.docker.com/desktop/setup/install/windows-install/";
const WSL_GUIDE = "https://learn.microsoft.com/windows/wsl/install";

// Builds elements from [tag, props, ...children]; strings become text nodes.
// Nothing here is parsed as HTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "onClick") node.addEventListener("click", value);
    else node[key] = value;
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

const button = (label, onClick, primary = false) =>
  el("button", { type: "button", className: primary ? "primary" : "", onClick }, label);

const waiting = () =>
  el("p", { className: "waiting" }, "This window is watching for Docker and continues on its own. No need to press anything.");

function windowsTroubleshooting() {
  return el(
    "details",
    {},
    el("summary", {}, "Docker Desktop shows an error about WSL or virtualization"),
    el(
      "ul",
      {},
      el("li", {}, "“WSL needs updating” or “WSL 2 installation is incomplete”: open PowerShell as administrator, run ",
        el("code", {}, "wsl --update"), ", then quit and reopen Docker Desktop."),
      el("li", {}, "WSL is not installed at all: in PowerShell as administrator run ",
        el("code", {}, "wsl --install"), ", then restart Windows."),
      el("li", {}, "“Virtualization support not detected”: virtualization is switched off in the PC’s firmware. Restart into the BIOS/UEFI settings and enable Intel VT-x or AMD-V (sometimes called SVM), then start Windows again."),
    ),
    el(
      "div",
      { className: "links" },
      button("Docker’s Windows install guide", () => window.iasg.openHelp(WINDOWS_GUIDE)),
      button("Microsoft’s WSL guide", () => window.iasg.openHelp(WSL_GUIDE)),
    ),
  );
}

function installSteps({ platform, installer }) {
  const download = button(`Download Docker Desktop ${installer.label}`, () => window.iasg.openDocker(), true);

  if (platform === "win32") {
    return [
      el("h2", {}, "Install Docker Desktop"),
      el("p", { className: "note" },
        "On Windows, Docker Desktop runs on WSL 2 (Windows Subsystem for Linux). The installer sets it up for you, but it needs administrator rights and a restart."),
      el(
        "ol",
        {},
        el("li", {}, download, " About 600 MB."),
        el("li", {}, "Run the installer. Keep “Use WSL 2 instead of Hyper-V” ticked."),
        el("li", {}, "Restart Windows when the installer asks, then open IASG again."),
        el("li", {}, "Open Docker Desktop and accept its terms. Signing in is optional."),
        el("li", {}, "Wait until Docker Desktop shows “Engine running”."),
      ),
      waiting(),
      windowsTroubleshooting(),
    ];
  }

  if (platform === "darwin") {
    return [
      el("h2", {}, "Install Docker Desktop"),
      el(
        "ol",
        {},
        el("li", {}, download, " About 600 MB."),
        el("li", {}, "Open the downloaded file and drag Docker into Applications."),
        el("li", {}, "Open Docker from Applications and accept its terms. Signing in is optional."),
        el("li", {}, "Wait until Docker Desktop shows “Engine running”."),
      ),
      waiting(),
    ];
  }

  return [
    el("h2", {}, "Install Docker"),
    el("ol", {},
      el("li", {}, button("Docker’s install guide for Linux", () => window.iasg.openDocker(), true)),
      el("li", {}, "Start Docker, then make sure your user can run ", el("code", {}, "docker info"), " without sudo."),
    ),
    waiting(),
  ];
}

function linuxStartSteps() {
  const command = (text) => el("code", {}, text);
  return [
    el("h2", {}, "Start Docker"),
    el(
      "ol",
      {},
      el("li", {}, "Start the Docker service: ", command("sudo systemctl start docker"), ". With Docker Desktop, open it from your applications instead."),
      el("li", {}, "Let your user run Docker without sudo: ", command("sudo usermod -aG docker $USER"), ", then log out and back in."),
      el("li", {}, "Check that ", command("docker info"), " works in a terminal without sudo."),
    ),
    waiting(),
  ];
}

function startSteps({ platform }) {
  if (platform === "linux") return linuxStartSteps();
  return [
    el("h2", {}, "Waiting for Docker Desktop"),
    el("p", { className: "note" },
      "The first start takes a minute or two. If this is Docker Desktop’s first run, it asks you to accept its terms before it starts."),
    el("div", { className: "links" }, button("Show Docker Desktop", () => window.iasg.startDocker())),
    waiting(),
    platform === "win32" ? windowsTroubleshooting() : null,
  ];
}

// Rebuilt only when what it shows changes, so an expanded troubleshooting
// section is not collapsed again by the next status update.
let setupKey = "";
function renderSetup(status) {
  const key = WAITING_ON_DOCKER.has(status.phase) ? `${status.phase}:${status.platform}` : "";
  if (key === setupKey) return;
  setupKey = key;
  const steps =
    status.phase === "no-docker" ? installSteps(status) : status.phase === "docker-stopped" ? startSteps(status) : [];
  // replaceChildren prints null as the text "null"; platform-specific parts are
  // null where they do not apply.
  setupEl.replaceChildren(...steps.filter(Boolean));
  setupEl.hidden = !key;
}

function renderStatus(status) {
  const { phase, message } = status;
  messageEl.textContent = message;
  statusEl.dataset.tone = phase === "error" ? "bad" : phase === "ready" ? "good" : "busy";
  retryBtn.hidden = !FAILED.has(phase) && phase !== "ready";
  retryBtn.textContent = phase === "ready" ? "Restart" : WAITING_ON_DOCKER.has(phase) ? "Check now" : "Retry";
  retryBtn.className = WAITING_ON_DOCKER.has(phase) ? "" : "primary";
  dashboardBtn.hidden = phase !== "ready";
  renderSetup(status);
  if (phase === "error") detailsEl.open = true;
}

function appendLog(lines) {
  const nearBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
  logEl.textContent = (logEl.textContent ? `${logEl.textContent}\n` : "") + lines.join("\n");
  const all = logEl.textContent.split("\n");
  if (all.length > 200) logEl.textContent = all.slice(-200).join("\n");
  if (nearBottom) logEl.scrollTop = logEl.scrollHeight;
}

retryBtn.addEventListener("click", () => window.iasg.retry());
dashboardBtn.addEventListener("click", () => window.iasg.openDashboard());

window.iasg.onStatus(renderStatus);
window.iasg.onLog(appendLog);
window.iasg.getState().then(({ status, log }) => {
  renderStatus(status);
  if (log.length) appendLog(log);
});
