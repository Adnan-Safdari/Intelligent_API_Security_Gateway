package telemetry

import (
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/signals"
)

// Event is one request's security record.
// Redis keeps a capped recent window; Postgres will store history later.
// The isolated agent should read this shape from both stores.
type Event struct {
	RequestID string             `json:"requestId"`
	Timestamp time.Time          `json:"ts"`
	IP        string             `json:"ip"`
	Method    string             `json:"method"`
	Path      string             `json:"path"`
	Query     string             `json:"query,omitempty"`
	Status    int                `json:"status"`
	UserAgent string             `json:"userAgent,omitempty"`
	Decision  string             `json:"decision"` // allow, throttle, temp_block, or escalate
	RiskScore int                `json:"riskScore"`
	Fired     []string           `json:"fired"`
	Signals   []signals.Evidence `json:"signals"`
	Snippet   string             `json:"snippet,omitempty"`
	BackendMS int64              `json:"backendMs"`
}
