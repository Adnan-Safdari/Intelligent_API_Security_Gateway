export const MODE_OPTIONS = Object.freeze([
  Object.freeze({
    value: "monitor",
    label: "Monitor",
    heading: "Monitor only",
    behaviour: "Learn, score, correlate, and show recommendations. Never write an enforcing gateway policy.",
  }),
  Object.freeze({
    value: "manual",
    label: "Manual",
    heading: "Analyst approval required",
    behaviour: "Create pending recommendations. An analyst must approve, edit, or reject before enforcement.",
  }),
  Object.freeze({
    value: "automatic",
    label: "Automatic",
    heading: "Automatic bounded enforcement",
    behaviour: "Automatically apply only guardrail-compliant throttle or temporary-block policies.",
    mlNote: "ML-only anomalies remain monitor-only.",
  }),
]);

export function modeCopy(mode) {
  return MODE_OPTIONS.find((option) => option.value === mode) || MODE_OPTIONS[0];
}

export function effectiveModeText(mode) {
  return "Current effective mode: " + modeCopy(mode).heading;
}
