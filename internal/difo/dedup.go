package difo

import (
	"net/url"
	"sort"
	"strings"
)

// Deduper collapses near-duplicate URLs the way `uro` does: URLs that share a
// host, path and the same set of query-parameter names are considered the same
// and only the first one seen is kept. It is safe for concurrent-free, single
// goroutine streaming use.
type Deduper struct {
	seen map[string]struct{}
}

// NewDeduper returns an empty Deduper.
func NewDeduper() *Deduper {
	return &Deduper{seen: make(map[string]struct{})}
}

// Add returns true if rawURL is new (and records it), or false if an equivalent
// URL has already been seen.
func (d *Deduper) Add(rawURL string) bool {
	key := dedupKey(rawURL)
	if _, ok := d.seen[key]; ok {
		return false
	}
	d.seen[key] = struct{}{}
	return true
}

// dedupKey normalizes a URL down to host + path + sorted query-parameter names.
// Scheme and query *values* are ignored so that only structurally distinct URLs
// survive.
func dedupKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(rawURL))
	}

	host := strings.ToLower(u.Host)
	path := u.Path
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	b.WriteString(host)
	b.WriteString(path)

	if u.RawQuery != "" {
		keys := make([]string, 0)
		for k := range u.Query() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("?")
		b.WriteString(strings.Join(keys, "&"))
	}
	return b.String()
}
