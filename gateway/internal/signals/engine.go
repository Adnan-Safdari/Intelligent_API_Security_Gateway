package signals

import (
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/context"
)

// Signal is the generic signal type returned by the engine.
type Signal struct {
	Name       string
	Severity   int
	Confidence float64
	Metadata   map[string]any
}

// Engine is currently a placeholder for future signal detectors.
type Engine struct{}

// NewEngine creates an empty signal engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Evaluate currently returns no signals.
func (e *Engine) Evaluate(ctx *context.RequestContext) ([]Signal, error) {
	return nil, nil
}
