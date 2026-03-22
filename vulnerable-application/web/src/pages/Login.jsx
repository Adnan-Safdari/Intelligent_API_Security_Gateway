import { useState } from "react";
import { login } from "../services/api";

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("demo");
  const [password, setPassword] = useState("password123");
  const [log, setLog] = useState([]);
  const [loading, setLoading] = useState(false);
  const [attackRunning, setAttackRunning] = useState(false);

  const pushLog = (msg, type = "info") => {
    const ts = new Date().toISOString().split("T")[1].slice(0, 12);
    setLog((prev) => [{ ts, msg, type }, ...prev].slice(0, 80));
  };

  const handleLogin = async () => {
    setLoading(true);
    pushLog(`POST /login  user="${username}"`, "info");
    try {
      const { status, ok, data } = await login(username, password);
      if (ok) {
        pushLog(`✔ ${status} — ${JSON.stringify(data)}`, "ok");
        onLoginSuccess?.();
      } else {
        pushLog(`✘ ${status} — ${JSON.stringify(data)}`, "err");
      }
    } catch (e) {
      pushLog(`✘ Network error: ${e.message}`, "err");
    }
    setLoading(false);
  };

  const handleSpamAttack = async () => {
    setAttackRunning(true);
    pushLog("🔥 SPAM ATTACK — 50 requests fired", "warn");
    const requests = Array.from({ length: 50 }, (_, i) =>
      login(`attacker_${i}`, "wrong_pass")
        .then(({ status }) => pushLog(`req#${i + 1} → ${status}`, status === 200 ? "ok" : "err"))
        .catch(() => pushLog(`req#${i + 1} → ERR`, "err"))
    );
    await Promise.allSettled(requests);
    pushLog("🔥 Spam attack complete", "warn");
    setAttackRunning(false);
  };

  const handleSlowAttack = async () => {
    setAttackRunning(true);
    pushLog("🐢 SLOW ATTACK — 20 requests @ 100ms delay", "warn");
    for (let i = 0; i < 20; i++) {
      login(`slow_${i}`, "wrong_pass")
        .then(({ status }) => pushLog(`slow#${i + 1} → ${status}`, status === 200 ? "ok" : "err"))
        .catch(() => pushLog(`slow#${i + 1} → ERR`, "err"));
      await sleep(100);
    }
    pushLog("🐢 Slow attack complete", "warn");
    setAttackRunning(false);
  };

  return (
    <div className="page">
      <div className="panel">
        <div className="panel-header">
          <span className="badge">AUTH</span>
          <h2>Login Endpoint</h2>
          <span className="endpoint">POST /login</span>
        </div>

        <div className="form-group">
          <label>USERNAME</label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="username"
          />
        </div>
        <div className="form-group">
          <label>PASSWORD</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password"
          />
        </div>

        <div className="btn-row">
          <button className="btn btn-primary" onClick={handleLogin} disabled={loading || attackRunning}>
            {loading ? "Sending…" : "▶ Login"}
          </button>
          <button className="btn btn-attack" onClick={handleSpamAttack} disabled={loading || attackRunning}>
            🔥 Spam Login Attack
          </button>
          <button className="btn btn-slow" onClick={handleSlowAttack} disabled={loading || attackRunning}>
            🐢 Slow Attack
          </button>
        </div>
      </div>

      <div className="log-panel">
        <div className="log-header">
          <span>TRAFFIC LOG</span>
          <button className="btn-clear" onClick={() => setLog([])}>CLEAR</button>
        </div>
        <div className="log-body">
          {log.length === 0 && <div className="log-empty">— no requests yet —</div>}
          {log.map((entry, i) => (
            <div key={i} className={`log-line log-${entry.type}`}>
              <span className="log-ts">{entry.ts}</span>
              <span>{entry.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
