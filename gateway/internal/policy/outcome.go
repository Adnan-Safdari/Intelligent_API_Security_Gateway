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
	Match  *Match
}

// Match keeps the policy that applied separate from the eventual HTTP outcome:
// an allowed request under a throttle policy still matched that policy.
type Match struct {
	PolicyID          string  `json:"policy_id,omitempty"`
	CampaignID        string  `json:"campaign_id,omitempty"`
	Action            string  `json:"action"`
	Source            string  `json:"source"`
	ClientIP          string  `json:"client_ip"`
	Route             string  `json:"route"`
	Method            string  `json:"method"`
	RequestsPerMinute int     `json:"requests_per_minute"`
	Reason            string  `json:"reason"`
	Outcome           string  `json:"outcome"`
	RiskScore         float64 `json:"risk_score,omitempty"`
	Confidence        float64 `json:"confidence,omitempty"`
	Mode              string  `json:"mode,omitempty"`
	IssuedBy          string  `json:"issued_by,omitempty"`
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

func RecordMatch(r *http.Request, match Match) {
	if v, ok := r.Context().Value(outcomeKey{}).(*Outcome); ok {
		v.Match = &match
	}
}

func Matched(r *http.Request) *Match {
	if v, ok := r.Context().Value(outcomeKey{}).(*Outcome); ok {
		return v.Match
	}
	return nil
}
