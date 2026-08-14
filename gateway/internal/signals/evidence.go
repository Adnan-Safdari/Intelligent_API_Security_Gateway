package signals

import "time"

// Signal names returned by Evidence.Signal. The decision engine keys off these.
const (
	SignalFlood      = "api_flooding"
	SignalSQLi       = "sql_injection"
	SignalTraversal  = "enumeration_path_traversal"
	SignalBruteForce = "brute_force"
)

// Evidence is the standardized output every detector exposes via Metrics(ip).
// Detectors never enforce policy; they only fill this struct. A future
// decision engine will sum Score values and inspect ThresholdCross.
type Evidence struct {
	Signal         string         `json:"signal"`
	Score          int            `json:"score"`          // 0-100 contribution for this signal
	ThresholdCross bool           `json:"thresholdCross"` // true when this detector considers the signal fired
	AttackType     string         `json:"attackType"`     // detector-specific label, empty when clean
	Details        map[string]any `json:"details,omitempty"`
}

// Detector is the contract every attack signal implements so a collector
// or decision engine can treat them uniformly.
type Detector interface {
	Name() string
	Metrics(ip string) Evidence
}

var (
	_ Detector = (*FloodDetector)(nil)
	_ Detector = (*SQLiDetector)(nil)
	_ Detector = (*TraversalEnumDetector)(nil)
	_ Detector = (*BruteForceDetector)(nil)
)

const lastEvidenceTTL = 5 * time.Minute

// Int reads a numeric detail. Missing or wrong-typed keys return 0.
func (e Evidence) Int(key string) int {
	if e.Details == nil {
		return 0
	}
	switch v := e.Details[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// Bool reads a boolean detail. Missing or wrong-typed keys return false.
func (e Evidence) Bool(key string) bool {
	if e.Details == nil {
		return false
	}
	v, _ := e.Details[key].(bool)
	return v
}

// Strings reads a string-slice detail. Missing or wrong-typed keys return nil.
func (e Evidence) Strings(key string) []string {
	if e.Details == nil {
		return nil
	}
	v, _ := e.Details[key].([]string)
	return v
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// ratioScore maps count vs threshold onto 0-100.
// Below threshold: a weak proportional signal (0-30).
// At/above threshold: 60, 2x: 80, 5x: 100.
func ratioScore(count, threshold int) int {
	if threshold <= 0 || count <= 0 {
		return 0
	}
	if count < threshold {
		return count * 30 / threshold
	}
	if count >= threshold*5 {
		return 100
	}
	if count >= threshold*2 {
		return 80
	}
	return 60
}
