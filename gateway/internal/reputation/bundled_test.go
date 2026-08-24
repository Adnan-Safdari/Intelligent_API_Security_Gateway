package reputation

import "testing"

// The list that ships with the repository has to parse, or the gateway refuses
// to start. Cheap to assert, and it fails on the commit that broke it rather
// than the next time someone boots.
func TestBundledListParses(t *testing.T) {
	networks, err := LoadFile("../../configs/reputation.txt")
	if err != nil {
		t.Fatalf("bundled list must parse: %v", err)
	}

	feed := New()
	feed.Replace(networks, "bundled")

	if !feed.Contains("203.0.113.66") {
		t.Error("the documented demo address should be listed")
	}
	// Deliberately a single /32: the demos and test scripts drive traffic from
	// 203.0.113.0/24, and listing the range would flag all of them.
	if feed.Contains("203.0.113.67") {
		t.Error("only the demo /32 should be listed, not the whole range")
	}
}
