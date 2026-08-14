package policy

import (
	"context"
	"net/http"
)

type outcomeKey struct{}

// Outcome is the enforcement action applied to this request.
// Telemetry reads it after the chain returns so iasg:events records
// temp_block / throttle / allow instead of always "allow".
type Outcome struct {
	Action string
}

// AttachOutcome puts a mutable outcome on the request. Call once, outermost.
func AttachOutcome(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), outcomeKey{}, &Outcome{Action: "allow"}))
}

// Record stores the action the enforcer applied.
func Record(r *http.Request, action string) {
	if action == "" {
		return
	}
	if v, ok := r.Context().Value(outcomeKey{}).(*Outcome); ok {
		v.Action = action
	}
}

// Applied is the action recorded for this request, or "allow".
func Applied(r *http.Request) string {
	if v, ok := r.Context().Value(outcomeKey{}).(*Outcome); ok && v.Action != "" {
		return v.Action
	}
	return "allow"
}
