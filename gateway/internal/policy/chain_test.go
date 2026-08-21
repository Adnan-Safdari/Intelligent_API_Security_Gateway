package policy

import "testing"

type fake map[string]Decision

func (f fake) Lookup(ip string) (Decision, bool) {
	d, ok := f[ip]
	return d, ok
}

func TestChainReturnsTheFirstSourceThatHasAnOpinion(t *testing.T) {
	agent := fake{"203.0.113.1": {Action: ActionThrottle}}
	reflex := fake{"203.0.113.2": {Action: ActionTempBlock}}

	chain := Chain{agent, reflex}

	if d, ok := chain.Lookup("203.0.113.1"); !ok || d.Action != ActionThrottle {
		t.Errorf("agent decision = %+v %v, want throttle", d, ok)
	}
	if d, ok := chain.Lookup("203.0.113.2"); !ok || d.Action != ActionTempBlock {
		t.Errorf("reflex decision = %+v %v, want temp_block", d, ok)
	}
	if _, ok := chain.Lookup("203.0.113.3"); ok {
		t.Error("an address neither source knows about was given a decision")
	}
}

func TestTheAgentOutranksTheReflexEvenWhenItIsLenient(t *testing.T) {
	// The reflex fired before anyone had thought about this address. The agent
	// has since correlated it, weighed the campaign, and chosen to throttle.
	// The considered decision wins -- this is also how a human override reaches
	// an address the gateway blocked by itself.
	agent := fake{"203.0.113.9": {Action: ActionThrottle, Reason: "considered"}}
	reflex := fake{"203.0.113.9": {Action: ActionTempBlock, Reason: "reflex"}}

	d, ok := Chain{agent, reflex}.Lookup("203.0.113.9")
	if !ok {
		t.Fatal("no decision")
	}
	if d.Action != ActionThrottle || d.Reason != "considered" {
		t.Errorf("got %+v, want the agent's throttle to win", d)
	}
}

func TestChainSkipsMissingSources(t *testing.T) {
	// Policy enforcement off, reflex on, is a supported combination and must
	// not depend on the order the sources happen to be appended in.
	reflex := fake{"203.0.113.4": {Action: ActionTempBlock}}

	if _, ok := (Chain{nil, reflex}).Lookup("203.0.113.4"); !ok {
		t.Error("a nil source hid the one that had an answer")
	}
	if _, ok := (Chain{}).Lookup("203.0.113.4"); ok {
		t.Error("an empty chain returned a decision")
	}
}
