package signals

// Collector gathers Evidence from every registered detector for one IP.
// The decision engine will call Collect(ip) instead of talking to detectors
// individually.
type Collector struct {
	detectors []Detector
}

func NewCollector(detectors ...Detector) *Collector {
	return &Collector{detectors: detectors}
}

func (c *Collector) Collect(ip string) []Evidence {
	return c.collect(ip, "")
}

// collect gathers evidence for an IP. With a request id, detectors that
// describe a single request are asked only for that request's evidence;
// windowed detectors always report their rolling state, which stays true
// whether or not this particular request reached them.
func (c *Collector) collect(ip, requestID string) []Evidence {
	if c == nil {
		return nil
	}
	out := make([]Evidence, 0, len(c.detectors))
	for _, d := range c.detectors {
		if d == nil {
			continue
		}
		if requestID != "" {
			if scoped, ok := d.(RequestScoped); ok {
				out = append(out, scoped.MetricsFor(ip, requestID))
				continue
			}
		}
		out = append(out, d.Metrics(ip))
	}
	return out
}

// Snapshot is one Collect() plus derived totals for telemetry / scoring.
type Snapshot struct {
	Evidence   []Evidence
	TotalScore int
	Fired      []string
}

func (c *Collector) Snapshot(ip string) Snapshot {
	return summarize(c.Collect(ip))
}

// SnapshotFor is Snapshot for a single request, so what telemetry records is
// what that request actually carried rather than what the address did last.
func (c *Collector) SnapshotFor(ip, requestID string) Snapshot {
	return summarize(c.collect(ip, requestID))
}

func summarize(evs []Evidence) Snapshot {
	snap := Snapshot{Evidence: evs}
	for _, ev := range evs {
		snap.TotalScore += ev.Score
		if ev.ThresholdCross {
			snap.Fired = append(snap.Fired, ev.Signal)
			if ev.AttackType != "" && ev.AttackType != ev.Signal {
				snap.Fired = append(snap.Fired, ev.AttackType)
			}
		}
	}
	// Individual signals contribute on a 0-100 scale, but several can fire on
	// one request. Telemetry exposes one risk score, so retain the combined
	// evidence while keeping that public value on its documented 0-100 scale.
	snap.TotalScore = clampScore(snap.TotalScore)
	return snap
}

// TotalScore is the combined detector score, bounded to the 0-100 risk scale.
func (c *Collector) TotalScore(ip string) int {
	return c.Snapshot(ip).TotalScore
}
