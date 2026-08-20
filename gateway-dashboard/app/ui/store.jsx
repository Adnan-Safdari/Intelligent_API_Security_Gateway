"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { actionLabel } from "./format";

/**
 * One poller for the whole console.
 *
 * It lives in the layout rather than in a page, so moving between pages does
 * not restart the clock or blank the screen: the data is already there when
 * the next page renders. Pausing stops the timer everywhere at once, which is
 * the only behaviour that makes sense when the pause button is in the header.
 */
const LiveContext = createContext(null);

const EMPTY_OVERVIEW = {
  redis: false,
  stats: { requests: 0, alerts: 0, decisions: {}, signals: {} },
  attackers: [],
  events: [],
  sources: [],
  site: null,
};

const EMPTY_PLANE = {
  redis: false,
  campaigns: [],
  policies: [],
  alerts: [],
  learned: [],
  heartbeat: { alive: false },
  active: 0,
};

const EMPTY_HISTORY = { available: false, campaigns: [], byType: [], total: 0 };

export function LiveProvider({ children, me }) {
  const [overview, setOverview] = useState(EMPTY_OVERVIEW);
  const [plane, setPlane] = useState(EMPTY_PLANE);
  const [history, setHistory] = useState(EMPTY_HISTORY);
  const [paused, setPaused] = useState(false);
  const [busy, setBusy] = useState("");
  const [toast, setToast] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);

  const refresh = useCallback(async () => {
    try {
      // Independent reads: the gateway's telemetry and the agent's
      // conclusions. Either can be empty without the other being wrong.
      const [a, b] = await Promise.all([
        fetch("/api/overview", { cache: "no-store" }).then((r) => r.json()),
        fetch("/api/campaigns", { cache: "no-store" }).then((r) => r.json()),
      ]);
      setOverview(a);
      setPlane(b);
      setUpdatedAt(new Date());
    } catch {
      setOverview((prev) => ({ ...prev, redis: false }));
    }
  }, []);

  const refreshHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/history", { cache: "no-store" });
      setHistory(await res.json());
    } catch {
      /* the panel reports its own unavailability */
    }
  }, []);

  useEffect(() => {
    refresh();
    // Paused still loads once, so arriving on a page while paused shows data.
    const id = paused ? null : setInterval(refresh, 2500);
    return () => id && clearInterval(id);
  }, [paused, refresh]);

  useEffect(() => {
    refreshHistory();
    // The record only changes when a campaign does; 30s is generous.
    const id = paused ? null : setInterval(refreshHistory, 30_000);
    return () => id && clearInterval(id);
  }, [paused, refreshHistory]);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(id);
  }, [toast]);

  // Declared before instruct uses it: a dependency array is evaluated while
  // the component body runs, so a const declared further down is still in its
  // temporal dead zone.
  const canAct = me ? me.role === "operator" || me.role === "admin" : false;

  /**
   * Send the agent an instruction about some addresses.
   *
   * Never call this an enforcement path: it writes to the override stream, and
   * the agent applies it on its next cycle after the same allowlist and
   * collateral checks its own decisions face.
   */
  const instruct = useCallback(async (ips, action, label, reason) => {
    const targets = [...new Set(ips)].filter(Boolean);
    if (!targets.length) return false;

    if (!canAct) {
      setToast({
        tone: "bad",
        text: "your account can read the console but not change enforcement",
      });
      return false;
    }

    setBusy(`${label}:${action}`);
    try {
      const results = await Promise.all(
        targets.map((ip) =>
          fetch("/api/overrides", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              ip,
              action,
              actor: "dashboard",
              reason: reason || `${actionLabel(action)} set from the console`,
            }),
          }).then((r) => r.json()),
        ),
      );

      const failed = results.filter((r) => !r.ok);
      if (failed.length) {
        setToast({
          tone: "bad",
          text: `${failed.length} of ${targets.length} rejected: ${failed[0].error}`,
        });
        return false;
      }

      setToast({
        tone: "good",
        text: `${actionLabel(action)} queued for ${targets.length} ${
          targets.length === 1 ? "address" : "addresses"
        } — applies next cycle`,
      });
      return true;
    } catch (err) {
      setToast({ tone: "bad", text: `could not reach the gateway: ${err.message}` });
      return false;
    } finally {
      setBusy("");
    }
  }, [canAct]);

  const value = useMemo(
    () => ({
      me,
      // Convenience only. The server checks the role on every write, so a
      // viewer who forges a request is refused there, not here.
      canAct,
      overview,
      plane,
      history,
      paused,
      setPaused,
      busy,
      toast,
      setToast,
      updatedAt,
      instruct,
      refresh,
      // Read straight off the payloads so a page never has to guess a default.
      stats: overview.stats || EMPTY_OVERVIEW.stats,
      events: overview.events || [],
      sources: overview.sources || [],
      attackers: overview.attackers || [],
      campaigns: plane.campaigns || [],
      policies: plane.policies || [],
      escalations: plane.alerts || [],
      learned: plane.learned || [],
      beat: plane.heartbeat || { alive: false },
    }),
    [me, canAct, overview, plane, history, paused, busy, toast, updatedAt, instruct, refresh],
  );

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive() {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used inside <LiveProvider>");
  return ctx;
}
