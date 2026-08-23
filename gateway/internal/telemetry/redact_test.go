package telemetry

import "testing"

func TestRedactQueryMasksKnownSecretKeys(t *testing.T) {
	got := RedactQuery("category=keyboards&API_KEY=demo-value&access_token=another-value")
	want := "API_KEY=%5Bredacted%5D&access_token=%5Bredacted%5D&category=keyboards"
	if got != want {
		t.Fatalf("RedactQuery() = %q, want %q", got, want)
	}
}

func TestRedactQueryDoesNotExposeMalformedInput(t *testing.T) {
	if got := RedactQuery("token=%ZZ"); got != "[unparseable query redacted]" {
		t.Fatalf("RedactQuery() = %q", got)
	}
}
