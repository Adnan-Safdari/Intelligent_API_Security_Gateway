"use client";

import { useEffect, useState } from "react";

const STORAGE_KEY = "iasg-dismissed-setup-checks";

// Dismissal is remembered against what the check saw, not just its id. Hiding
// "172.18.0.5 is most of the traffic" should not also hide a later warning
// about a different address, or about a route that only just went missing.
function fingerprint(check) {
  return `${check.id}:${(check.items || []).map((item) => item.label).join("|")}`;
}

function readDismissed() {
  try {
    return new Set(JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"));
  } catch {
    return new Set();
  }
}

export function SetupWarnings({ checks = [] }) {
  // Empty until mounted, so the server render and the first client render
  // agree; storage is only readable in the browser.
  const [dismissed, setDismissed] = useState(() => new Set());
  useEffect(() => setDismissed(readDismissed()), []);

  const visible = checks.filter((check) => !dismissed.has(fingerprint(check)));
  if (!visible.length) return null;

  const dismiss = (check) => {
    const next = new Set(dismissed).add(fingerprint(check));
    setDismissed(next);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...next]));
    } catch {
      // Storage blocked: the warning is hidden for this visit only.
    }
  };

  return (
    <section className="setup-warnings" aria-label="Setup warnings">
      {visible.map((check) => (
        <div className="notice warn setup-warning" role="status" key={check.id}>
          <div className="setup-warning-body">
            <strong>{check.title}</strong>
            <p>{check.detail}</p>
            {check.items?.length ? (
              <ul>
                {check.items.map((item) => (
                  <li key={item.label}>
                    <code>{item.label}</code>
                    <span>{item.value}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
          <button type="button" className="act small" onClick={() => dismiss(check)}>
            Dismiss
          </button>
        </div>
      ))}
    </section>
  );
}
