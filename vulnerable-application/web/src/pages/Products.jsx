import { useState, useEffect } from "react";
import { getProducts } from "../services/api";

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

export default function Products() {
  const [products, setProducts] = useState([]);
  const [log, setLog] = useState([]);
  const [loading, setLoading] = useState(false);
  const [attackRunning, setAttackRunning] = useState(false);

  const pushLog = (msg, type = "info") => {
    const ts = new Date().toISOString().split("T")[1].slice(0, 12);
    setLog((prev) => [{ ts, msg, type }, ...prev].slice(0, 120));
  };

  const fetchProducts = async () => {
    setLoading(true);
    pushLog("GET /products", "info");
    try {
      const { status, ok, data } = await getProducts();
      if (ok) {
        setProducts(Array.isArray(data) ? data : []);
        pushLog(`✔ ${status} — ${Array.isArray(data) ? data.length : 0} products`, "ok");
      } else {
        pushLog(`✘ ${status} — failed`, "err");
      }
    } catch (e) {
      pushLog(`✘ Network error: ${e.message}`, "err");
    }
    setLoading(false);
  };

  useEffect(() => { fetchProducts(); }, []);

  const handleSpamAttack = async () => {
    setAttackRunning(true);
    pushLog("🔥 SPAM ATTACK — 100 requests fired", "warn");
    const requests = Array.from({ length: 100 }, (_, i) =>
      getProducts()
        .then(({ status }) => pushLog(`req#${String(i + 1).padStart(3, "0")} → ${status}`, status === 200 ? "ok" : "err"))
        .catch(() => pushLog(`req#${String(i + 1).padStart(3, "0")} → ERR`, "err"))
    );
    await Promise.allSettled(requests);
    pushLog("🔥 Spam attack complete", "warn");
    setAttackRunning(false);
  };

  const handleSlowAttack = async () => {
    setAttackRunning(true);
    pushLog("🐢 SLOW ATTACK — 20 requests @ 100ms delay", "warn");
    for (let i = 0; i < 20; i++) {
      getProducts()
        .then(({ status }) => pushLog(`slow#${String(i + 1).padStart(2, "0")} → ${status}`, status === 200 ? "ok" : "err"))
        .catch(() => pushLog(`slow#${String(i + 1).padStart(2, "0")} → ERR`, "err"));
      await sleep(100);
    }
    pushLog("🐢 Slow attack complete", "warn");
    setAttackRunning(false);
  };

  return (
    <div className="page">
      <div className="panel">
        <div className="panel-header">
          <span className="badge badge-blue">DATA</span>
          <h2>Products Endpoint</h2>
          <span className="endpoint">GET /products</span>
        </div>

        <div className="btn-row">
          <button className="btn btn-primary" onClick={fetchProducts} disabled={loading || attackRunning}>
            {loading ? "Loading…" : "↻ Reload Products"}
          </button>
          <button className="btn btn-attack" onClick={handleSpamAttack} disabled={loading || attackRunning}>
            🔥 Spam Products API
          </button>
          <button className="btn btn-slow" onClick={handleSlowAttack} disabled={loading || attackRunning}>
            🐢 Slow Attack
          </button>
        </div>

        <div className="product-grid">
          {products.length === 0 && !loading && (
            <div className="empty-state">No products — check gateway connection</div>
          )}
          {products.map((p, i) => (
            <div className="product-card" key={p.id ?? i}>
              <div className="product-id">#{String(p.id ?? i).padStart(3, "0")}</div>
              <div className="product-name">{p.name ?? p.title ?? JSON.stringify(p)}</div>
              {p.price != null && <div className="product-price">${p.price}</div>}
            </div>
          ))}
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
