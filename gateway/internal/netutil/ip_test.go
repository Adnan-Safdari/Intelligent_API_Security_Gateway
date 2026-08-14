package netutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func request(remoteAddr string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range forwarded {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func mustResolver(t *testing.T, cidrs ...string) *Resolver {
	t.Helper()
	res, err := NewResolver(cidrs)
	if err != nil {
		t.Fatalf("NewResolver(%v): %v", cidrs, err)
	}
	return res
}

func TestPeerIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5:54321": "203.0.113.5",
		"[2001:db8::1]:443": "2001:db8::1",
		"203.0.113.5":       "203.0.113.5", // no port: returned unchanged
	}
	for in, want := range cases {
		if got := PeerIP(in); got != want {
			t.Errorf("PeerIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// The default must be to ignore the header entirely. Anyone can set it.
func TestHeaderIgnoredWhenNoProxiesTrusted(t *testing.T) {
	res := mustResolver(t)

	got := res.Resolve(request("203.0.113.5:1234", "198.51.100.99"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want the peer address -- header must not be believed", got)
	}
}

// An attacker connecting directly cannot pin blame on someone else.
func TestHeaderIgnoredFromUntrustedPeer(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("203.0.113.5:1234", "198.51.100.99"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want 203.0.113.5 -- an untrusted peer's header must be ignored", got)
	}
}

func TestHeaderUsedFromTrustedProxy(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("10.0.0.7:1234", "203.0.113.5"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want the forwarded client 203.0.113.5", got)
	}
}

// Two proxies in front: the real client is the first untrusted hop from the right.
func TestProxyChainWalksToRealClient(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("10.0.0.7:1234", "203.0.113.5, 10.0.0.9, 10.0.0.8"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want 203.0.113.5", got)
	}
}

// The attack this whole design exists to stop: a caller pre-seeds the header
// with a victim's address, hoping that IP gets blamed and blocked. The proxy
// appends the caller's real address on the right, so the rightmost untrusted
// hop is still the caller.
func TestSpoofedLeadingHopIsNotBelieved(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("10.0.0.7:1234", "198.51.100.1, 203.0.113.5"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want the real caller 203.0.113.5, not the spoofed 198.51.100.1", got)
	}
}

func TestFallsBackToPeerWhenEveryHopIsTrusted(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("10.0.0.7:1234", "10.0.0.9, 10.0.0.8"))
	if got != "10.0.0.7" {
		t.Fatalf("got %q, want the peer 10.0.0.7", got)
	}
}

func TestTrustedProxyWithoutHeaderUsesPeer(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	if got := res.Resolve(request("10.0.0.7:1234")); got != "10.0.0.7" {
		t.Fatalf("got %q, want 10.0.0.7", got)
	}
}

func TestMalformedHopsAreSkipped(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("10.0.0.7:1234", "203.0.113.5, not-an-ip"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want 203.0.113.5", got)
	}
}

// Some proxies send several headers rather than one comma-separated list.
func TestRepeatedHeadersAreFlattened(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	got := res.Resolve(request("10.0.0.7:1234", "203.0.113.5", "10.0.0.8"))
	if got != "203.0.113.5" {
		t.Fatalf("got %q, want 203.0.113.5", got)
	}
}

func TestIPv6ProxyAndClient(t *testing.T) {
	// /64, not /32: a /32 would also contain the client below, making every
	// hop trusted and correctly falling through to the peer.
	res := mustResolver(t, "2001:db8::/64")

	got := res.Resolve(request("[2001:db8::7]:1234", "2001:db8:cafe::1, 2001:db8::8"))
	if got != "2001:db8:cafe::1" {
		t.Fatalf("got %q, want 2001:db8:cafe::1", got)
	}
}

func TestBareAddressIsAcceptedAsCIDR(t *testing.T) {
	res := mustResolver(t, "127.0.0.1")

	if !res.Trusts("127.0.0.1") {
		t.Fatal("a bare address should be accepted and trusted")
	}
	if res.Trusts("127.0.0.2") {
		t.Fatal("a bare address must not widen to its subnet")
	}
}

func TestInvalidConfigIsRejected(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "10.0.0.0/99", "banana/24"} {
		if _, err := NewResolver([]string{bad}); err == nil {
			t.Errorf("NewResolver(%q) should have failed", bad)
		}
	}
}

func TestEmptyEntriesAreIgnored(t *testing.T) {
	res, err := NewResolver([]string{"", "  ", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("blank entries should be skipped, got %v", err)
	}
	if !res.Trusts("10.0.0.1") {
		t.Fatal("the real entry should still be trusted")
	}
}

// Without the middleware, behaviour must match the old peer-address logic.
func TestClientIPFallsBackToPeer(t *testing.T) {
	if got := ClientIP(request("203.0.113.5:1234", "198.51.100.99")); got != "203.0.113.5" {
		t.Fatalf("got %q, want 203.0.113.5", got)
	}
}

func TestMiddlewarePutsResolvedIPOnContext(t *testing.T) {
	res := mustResolver(t, "10.0.0.0/8")

	var seen string
	handler := res.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ClientIP(r)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), request("10.0.0.7:1234", "203.0.113.5"))

	if seen != "203.0.113.5" {
		t.Fatalf("handler saw %q, want 203.0.113.5", seen)
	}
}
