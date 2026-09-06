package reputation

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAcceptsTheShapesAListIsWrittenIn(t *testing.T) {
	list := `
# a comment on its own line
203.0.113.66            # a bare address, with a trailing comment
198.51.100.0/24         # a CIDR

192.0.2.5,scanner       # "address,reason", as some public feeds ship
192.0.2.6	tor-exit    # the same with a tab
2001:db8::1             # v6
`
	networks, err := Parse(strings.NewReader(list))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(networks) != 5 {
		t.Fatalf("want 5 networks, got %d: %v", len(networks), networks)
	}
}

func TestParseRefusesABadEntryRatherThanSkippingIt(t *testing.T) {
	// Quietly dropping this line is how a list ends up shorter than the person
	// maintaining it believes, so the parse has to fail.
	_, err := Parse(strings.NewReader("203.0.113.1\nnot-an-address\n"))
	if err == nil {
		t.Fatal("expected an error for a malformed entry")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error should name the line, got %v", err)
	}
}

func TestContains(t *testing.T) {
	feed := New()
	networks, err := Parse(strings.NewReader("203.0.113.66\n198.51.100.0/24\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	feed.Replace(networks, "test")

	cases := map[string]bool{
		"203.0.113.66":  true,  // the bare address, as /32
		"203.0.113.67":  false, // neighbour, deliberately not covered
		"198.51.100.99": true,  // inside the CIDR
		"8.8.8.8":       false,
		"nonsense":      false, // unparseable is not listed
		"":              false,
	}
	for ip, want := range cases {
		if got := feed.Contains(ip); got != want {
			t.Errorf("Contains(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestAnEmptyFeedIsNeverAHit(t *testing.T) {
	if New().Contains("203.0.113.66") {
		t.Error("an empty feed listed an address")
	}
	var nilFeed *Feed
	if nilFeed.Contains("203.0.113.66") || nilFeed.Len() != 0 {
		t.Error("a nil feed should answer no, not panic")
	}
}

func writeList(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reputation.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoaderReadsTheBundledFile(t *testing.T) {
	feed := New()
	path := writeList(t, "203.0.113.66\n198.51.100.0/24\n")

	if err := NewLoader(feed).Load(Source{Path: path}); err != nil {
		t.Fatalf("load: %v", err)
	}
	if feed.Len() != 2 {
		t.Fatalf("want 2 networks, got %d", feed.Len())
	}
	if !strings.Contains(feed.Describe(), "reputation.txt") {
		t.Errorf("Describe should name the source, got %q", feed.Describe())
	}
}

func TestABrokenBundledFileIsAnError(t *testing.T) {
	// It is checked in, so a bad entry is a mistake someone can fix.
	err := NewLoader(New()).Load(Source{Path: writeList(t, "203.0.113.1\ngarbage\n")})
	if err == nil {
		t.Fatal("expected an error for an unparseable bundled file")
	}
}

func TestRemoteEntriesAreAddedToTheBundledOnes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.7\n192.0.2.8\n"))
	}))
	defer server.Close()

	feed := New()
	err := NewLoader(feed).Load(Source{
		Path: writeList(t, "203.0.113.66\n"), URL: server.URL, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Union, not replacement: switching a remote feed on must not drop the
	// entries someone checked in on purpose.
	if !feed.Contains("203.0.113.66") {
		t.Error("bundled entry was lost when a remote feed was added")
	}
	if !feed.Contains("192.0.2.7") {
		t.Error("remote entry was not added")
	}
}

func TestAFailedRefreshKeepsTheLastGoodRemoteList(t *testing.T) {
	answer := "192.0.2.7\n"
	fail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(answer))
	}))
	defer server.Close()

	feed := New()
	loader := NewLoader(feed)
	src := Source{Path: writeList(t, "203.0.113.66\n"), URL: server.URL, Timeout: 2 * time.Second}

	if err := loader.Load(src); err != nil {
		t.Fatalf("first load: %v", err)
	}

	fail = true
	if err := loader.Load(src); err != nil {
		t.Fatalf("a failed fetch must not fail the load: %v", err)
	}

	// A feed that emptied itself because a server had a bad minute would stop
	// recognising every attacker on it.
	if !feed.Contains("192.0.2.7") {
		t.Error("last good remote list was discarded on a failed refresh")
	}
	if !feed.Contains("203.0.113.66") {
		t.Error("bundled list was lost on a failed refresh")
	}
}

func TestAnUnreachableFeedStillLoadsTheBundledList(t *testing.T) {
	feed := New()
	err := NewLoader(feed).Load(Source{
		Path: writeList(t, "203.0.113.66\n"),
		URL:  "http://127.0.0.1:1/never",
		// Short: the point is that failure is survivable, not that it is slow.
		Timeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("an unreachable feed must not fail the load: %v", err)
	}
	if !feed.Contains("203.0.113.66") {
		t.Error("bundled list should still load when the remote feed is down")
	}
}
