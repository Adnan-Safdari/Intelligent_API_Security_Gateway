package interfaces

import gatewayContext "github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/context"

type Signal struct {
	Name       string
	Severity   int
	Confidence float64
	Metadata   map[string]interface{}
}

type SignalEngine interface {
	Evaluate(ctx *gatewayContext.RequestContext) ([]Signal, error)
}

type TrustEngine interface {
	Score(signals []Signal) (float64, error)
}

type Action string

const (
	ALLOW    Action = "ALLOW"
	THROTTLE Action = "THROTTLE"
	BLOCK    Action = "BLOCK"
)

type EnforcementEngine interface {
	Decide(score float64) Action
}
