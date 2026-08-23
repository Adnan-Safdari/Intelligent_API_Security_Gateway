package policy

import "sync/atomic"

// Gate wraps a Lookuper with a switch.
//
// The chain is built once at boot, so a source cannot be added or removed
// later. Turning the control plane's decisions on and off from the console is
// therefore a matter of ignoring a source that is still there and still
// refreshing, rather than tearing it down: the store keeps its snapshot warm,
// and switching back on enforces immediately instead of after the next refresh.
type Gate struct {
	inner Lookuper
	on    atomic.Bool
}

func NewGate(inner Lookuper, on bool) *Gate {
	g := &Gate{inner: inner}
	g.on.Store(on)
	return g
}

// Set turns the source on or off.
func (g *Gate) Set(on bool) {
	if g != nil {
		g.on.Store(on)
	}
}

// On reports whether the source is currently consulted.
func (g *Gate) On() bool { return g != nil && g.on.Load() }

func (g *Gate) Lookup(ip string) (Decision, bool) {
	if g == nil || !g.on.Load() || g.inner == nil {
		return Decision{}, false
	}
	return g.inner.Lookup(ip)
}
