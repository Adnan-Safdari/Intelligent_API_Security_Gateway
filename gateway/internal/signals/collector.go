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
	if c == nil {
		return nil
	}
	out := make([]Evidence, 0, len(c.detectors))
	for _, d := range c.detectors {
		if d == nil {
			continue
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
	evs := c.Collect(ip)
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
	return snap
}

// TotalScore sums detector scores. Useful as a first-pass risk input.
func (c *Collector) TotalScore(ip string) int {
	return c.Snapshot(ip).TotalScore
}
