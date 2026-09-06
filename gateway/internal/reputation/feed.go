/*
Package reputation holds the set of addresses already known to be malicious.

Every other detector in this gateway is behavioural: it counts requests,
failures or pattern matches, and needs the attacker to act repeatedly before it
knows anything. Reputation is a standing fact about an address instead, which
makes it the one signal that can answer on the first request.

The list is a union of two sources. A file ships with the repository and always
loads; an optional URL is fetched on an interval and added to it. Union rather
than replacement so that turning on a remote feed can only ever widen what is
known -- switching one on must not silently drop the entries someone checked in
on purpose.
*/
package reputation

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
)

// maxFeedBytes caps a remote response. A feed is a text list of addresses; a
// reply far larger than that is a misconfigured URL or a hostile one, and
// reading it whole would be the gateway attacking its own memory.
const maxFeedBytes = 8 << 20 // 8MB

// Feed is the loaded list, swapped whole so a refresh never interrupts a
// lookup. Reads are lock-free; the refresher is the only writer.
type Feed struct {
	loaded atomic.Pointer[snapshot]
}

// snapshot is one complete list and where it came from. Kept together so the
// description can never disagree with the networks it describes.
type snapshot struct {
	networks []*net.IPNet
	origin   string
	at       time.Time
}

func New() *Feed {
	f := &Feed{}
	f.loaded.Store(&snapshot{origin: "empty", at: time.Now()})
	return f
}

// Contains reports whether the address is listed. An address that will not
// parse is not listed -- the same answer netutil gives everywhere else.
func (f *Feed) Contains(ip string) bool {
	if f == nil {
		return false
	}
	return netutil.NetworksContain(f.loaded.Load().networks, ip)
}

func (f *Feed) Len() int {
	if f == nil {
		return 0
	}
	return len(f.loaded.Load().networks)
}

// Describe says what is loaded and from where, for the startup line and the
// console. Worth printing: a feed that silently loaded nothing looks exactly
// like a feed where no attacker is listed.
func (f *Feed) Describe() string {
	if f == nil {
		return "no reputation feed"
	}
	s := f.loaded.Load()
	return fmt.Sprintf("%d networks from %s", len(s.networks), s.origin)
}

// Replace swaps in a new list. Callers hold the old one until they return.
func (f *Feed) Replace(networks []*net.IPNet, origin string) {
	f.loaded.Store(&snapshot{networks: networks, origin: origin, at: time.Now()})
}

// Parse reads a list: one CIDR or bare address per line, # comments and blank
// lines ignored. Entries go through netutil.ParseCIDRs so this list agrees
// with the trusted-proxy and exempt lists about what a written entry means.
//
// One bad line fails the whole parse. A feed is a security control, and
// quietly skipping the entry that would not parse is how a list ends up
// shorter than the person maintaining it believes.
func Parse(r io.Reader) ([]*net.IPNet, error) {
	var entries []string

	scanner := bufio.NewScanner(io.LimitReader(r, maxFeedBytes))
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		// Some public feeds carry "address,reason" or "address<TAB>reason".
		// Take the address and ignore the rest rather than rejecting the file.
		if i := strings.IndexAny(text, ", \t"); i >= 0 {
			text = text[:i]
		}
		if _, err := netutil.ParseCIDRs([]string{text}, "reputation entry"); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		entries = append(entries, text)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read feed: %w", err)
	}

	return netutil.ParseCIDRs(entries, "reputation entry")
}

func LoadFile(path string) ([]*net.IPNet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open reputation feed %s: %w", path, err)
	}
	defer file.Close()

	networks, err := Parse(file)
	if err != nil {
		return nil, fmt.Errorf("parse reputation feed %s: %w", path, err)
	}
	return networks, nil
}

func Fetch(url string, timeout time.Duration) ([]*net.IPNet, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch reputation feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch reputation feed: %s", resp.Status)
	}
	networks, err := Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse reputation feed from %s: %w", url, err)
	}
	return networks, nil
}
