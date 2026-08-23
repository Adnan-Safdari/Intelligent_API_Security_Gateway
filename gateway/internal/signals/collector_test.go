package signals

import "testing"

type fixedScoreDetector struct {
	name  string
	score int
}

func (d fixedScoreDetector) Name() string { return d.name }

func (d fixedScoreDetector) Metrics(string) Evidence {
	return Evidence{Signal: d.name, Score: d.score}
}

func TestCollectorTotalScoreIsAlwaysBounded(t *testing.T) {
	tests := []struct {
		name   string
		scores []int
		want   int
	}{
		{name: "combined signals cap at 100", scores: []int{80, 50}, want: 100},
		{name: "negative input cannot make risk negative", scores: []int{-25}, want: 0},
		{name: "ordinary combined score is preserved", scores: []int{20, 30}, want: 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectors := make([]Detector, 0, len(tt.scores))
			for i, score := range tt.scores {
				detectors = append(detectors, fixedScoreDetector{name: string(rune('a' + i)), score: score})
			}

			if got := NewCollector(detectors...).TotalScore("203.0.113.5"); got != tt.want {
				t.Fatalf("TotalScore() = %d, want %d", got, tt.want)
			}
		})
	}
}
