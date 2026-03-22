import { useState } from "react";
import Login from "./pages/Login";
import Products from "./pages/Products";
import "./App.css";

export default function App() {
  const [page, setPage] = useState("login");

  return (
    <div className="app">
      {/* Scanline overlay */}
      <div className="scanlines" aria-hidden="true" />

      <header className="app-header">
        <div className="header-left">
          <div className="logo-mark">⬡</div>
          <div>
            <div className="app-title">Intelligent API Security Gateway</div>
            <div className="app-sub">Attack Demonstration Console · localhost:8080</div>
          </div>
        </div>

        <nav className="nav">
          <button
            className={`nav-btn ${page === "login" ? "active" : ""}`}
            onClick={() => setPage("login")}
          >
            AUTH
          </button>
          <button
            className={`nav-btn ${page === "products" ? "active" : ""}`}
            onClick={() => setPage("products")}
          >
            PRODUCTS
          </button>
        </nav>

        <div className="status-indicator">
          <span className="dot" />
          GATEWAY ACTIVE
        </div>
      </header>

      <main className="app-main">
        {page === "login" && <Login onLoginSuccess={() => setPage("products")} />}
        {page === "products" && <Products />}
      </main>

      <footer className="app-footer">
        <span>INTELLIGENT API SECURITY GATEWAY</span>
        <span>ALL TRAFFIC ROUTED VIA GATEWAY PORT 8080</span>
        <span>DEMO BUILD — NOT FOR PRODUCTION</span>
      </footer>
    </div>
  );
}
