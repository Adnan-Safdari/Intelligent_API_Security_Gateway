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

// TotalScore sums detector scores. Useful as a first-pass risk input.
func (c *Collector) TotalScore(ip string) int {
	total := 0
	for _, ev := range c.Collect(ip) {
		total += ev.Score
	}
	return total
}
