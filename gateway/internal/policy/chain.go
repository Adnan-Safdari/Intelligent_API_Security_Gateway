package policy

// Chain looks decisions up in several sources, in order, and returns the first
// one found.
//
// There are two sources and the order between them is a deliberate choice: the
// control plane comes first, the gateway's own reflex second.
//
// The reflex exists because the control plane is slow -- a decision takes up to
// one agent cycle plus one snapshot refresh to arrive. It is a stopgap held by
// a component that knows only what one detector saw. The control plane, by the
// time it has an opinion, has correlated an address with others, weighed a
// campaign's history, taken account of any human override, and passed the
// whole thing through simulation.
//
// So once the agent has decided something about an address, that decision
// wins, including when it is *less* severe. An agent that has looked at the
// evidence and chosen to throttle rather than block is not to be overruled by
// a reflex that fired before anyone had thought about it -- and this is also
// how a human override reaches an address the gateway blocked by itself.
type Chain []Lookuper

func (c Chain) Lookup(ip string) (Decision, bool) {
	for _, source := range c {
		if source == nil {
			continue
		}
		if decision, found := source.Lookup(ip); found {
			return decision, true
		}
	}
	return Decision{}, false
}
