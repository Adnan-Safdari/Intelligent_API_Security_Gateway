package telemetry

import (
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Event is one request's security record.
// Redis keeps a capped recent window; Postgres will store history later.
// The isolated agent should read this shape from both stores.
type Event struct {
	RequestID string    `json:"requestId"`
	Timestamp time.Time `json:"ts"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`

	// RouteTemplate is the configured template Path matched, or
	// UnmatchedRoute. Without it every resource identifier looks like a
	// different endpoint, so a client reading twenty products is
	// indistinguishable from one walking twenty unrelated paths.
	RouteTemplate string `json:"routeTemplate"`

	Query     string             `json:"query,omitempty"`
	Status    int                `json:"status"`
	UserAgent string             `json:"userAgent,omitempty"`
	Decision  string             `json:"decision"` // allow, throttle, temp_block, or escalate
	Policy    *policy.Match      `json:"policy,omitempty"`
	RiskScore int                `json:"riskScore"`
	Fired     []string           `json:"fired"`
	Signals   []signals.Evidence `json:"signals"`
	Snippet   string             `json:"snippet,omitempty"`

	// ResponseOrigin says who wrote Status: the backend, or the gateway
	// answering by itself. Derived from whether the backend was actually
	// asked, because a 413 from the body cap and a 400 from an unreadable
	// body are otherwise indistinguishable from backend statuses.
	ResponseOrigin string `json:"responseOrigin"`

	// GatewayReason names why the gateway answered without asking.
	GatewayReason string `json:"gatewayReason,omitempty"`

	UpstreamAttempted bool   `json:"upstreamAttempted"`
	UpstreamOutcome   string `json:"upstreamOutcome,omitempty"`

	// Nullable on purpose. A call that timed out has no status and no
	// duration, and a JSON zero would read as a measurement rather than as
	// the absence of one.
	UpstreamStatus     *int   `json:"upstreamStatus"`
	UpstreamDurationMS *int64 `json:"upstreamDurationMs"`
	ResponseBodyBytes  *int64 `json:"responseBodyBytes"`

	// RequestBodyBytes distinguishes a confirmed empty body (zero) from one
	// that was refused or unreadable (null).
	RequestBodyBytes *int64 `json:"requestBodyBytes"`

	// BackendMS is the backend call, which is what its name always claimed and
	// what the console displays. It reads 0 when there was no completed call,
	// so it conflates zero with unknown -- acceptable for a display column,
	// which is why the anomaly features read UpstreamDurationMS instead.
	BackendMS int64 `json:"backendMs"`

	// GatewayMS is the whole chain: every middleware, every detector and the
	// backend call inside them. This is the number BackendMS used to hold.
	GatewayMS int64 `json:"gatewayMs"`
}
