const statusEl = document.getElementById("status");
const messageEl = document.getElementById("message");
const logEl = document.getElementById("log");
const retryBtn = document.getElementById("retry");
const dockerBtn = document.getElementById("docker");
const dashboardBtn = document.getElementById("dashboard");
const detailsEl = document.getElementById("details");

const FAILED = new Set(["error", "no-docker", "docker-stopped"]);

function renderStatus({ phase, message }) {
  messageEl.textContent = message;
  statusEl.dataset.tone = FAILED.has(phase) ? "bad" : phase === "ready" ? "good" : "busy";
  retryBtn.hidden = !FAILED.has(phase) && phase !== "ready";
  retryBtn.textContent = phase === "ready" ? "Restart" : "Retry";
  dockerBtn.hidden = phase !== "no-docker";
  dashboardBtn.hidden = phase !== "ready";
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
dockerBtn.addEventListener("click", () => window.iasg.openDocker());
dashboardBtn.addEventListener("click", () => window.iasg.openDashboard());

window.iasg.onStatus(renderStatus);
window.iasg.onLog(appendLog);
window.iasg.getState().then(({ status, log }) => {
  renderStatus(status);
  if (log.length) appendLog(log);
});
