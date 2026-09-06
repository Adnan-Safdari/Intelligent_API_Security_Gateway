package reputation

import (
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Source says where the list comes from.
type Source struct {
	// Path is the checked-in list. Always loaded when set.
	Path string
	// URL is an optional live feed, added to whatever Path holds.
	URL string
	// RefreshInterval is how often URL is re-fetched. Zero means never.
	RefreshInterval time.Duration
	// Timeout bounds one fetch.
	Timeout time.Duration
}

// Loader keeps a Feed up to date from a Source.
//
// The two halves are remembered separately so a failed fetch is survivable:
// the file entries are reloaded from disk and the last remote list that did
// parse stays in force. A feed that emptied itself because a server had a bad
// minute would quietly stop recognising every attacker on it, which is the
// failure this exists to avoid.
type Loader struct {
	feed *Feed

	mu         sync.Mutex
	lastRemote []*net.IPNet
	haveRemote bool
	warned     bool
}

func NewLoader(feed *Feed) *Loader { return &Loader{feed: feed} }

// Load rebuilds the list once.
//
// A file that will not parse is an error: it is checked in, so a broken entry
// is a mistake someone can fix. A URL that will not answer is not an error --
// it is a network, and the gateway keeps running on what it already had.
func (l *Loader) Load(src Source) error {
	var networks []*net.IPNet
	var origins []string

	if src.Path != "" {
		fromFile, err := LoadFile(src.Path)
		if err != nil {
			return err
		}
		networks = append(networks, fromFile...)
		origins = append(origins, filepath.Base(src.Path))
	}

	if src.URL != "" {
		remote, err := Fetch(src.URL, src.Timeout)

		l.mu.Lock()
		switch {
		case err == nil:
			l.lastRemote, l.haveRemote, l.warned = remote, true, false
		case l.haveRemote:
			remote = l.lastRemote
			if !l.warned {
				log.Printf("[reputation] feed refresh failed, keeping last good list: %v", err)
				l.warned = true
			}
		default:
			remote = nil
			if !l.warned {
				log.Printf("[reputation] feed unavailable, using the bundled list only: %v", err)
				l.warned = true
			}
		}
		haveRemote := l.haveRemote
		l.mu.Unlock()

		networks = append(networks, remote...)
		if haveRemote {
			origins = append(origins, src.URL)
		}
	}

	if len(origins) == 0 {
		origins = append(origins, "empty")
	}
	l.feed.Replace(networks, strings.Join(origins, " + "))
	return nil
}

// Start refreshes in the background until stop closes. Only the remote half
// can change between ticks, so this does nothing without a URL and an
// interval -- a bundled-only feed needs no goroutine.
func (l *Loader) Start(src Source, stop <-chan struct{}) {
	if src.URL == "" || src.RefreshInterval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(src.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				// Errors are already logged and survived inside Load.
				if err := l.Load(src); err != nil {
					log.Printf("[reputation] refresh failed: %v", err)
				}
			}
		}
	}()
}
