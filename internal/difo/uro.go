package difo

import (
	"net/url"
	"regexp"
	"strings"
)

// This file reimplements the decluttering behaviour of `uro`
// (github.com/s0md3v/uro and the Go port github.com/szybnev/uro-go) so DIFO can
// thin out a raw Wayback dump without shelling out to an external binary.
//
// It removes:
//   - static assets by extension (css/png/js-style noise),
//   - incremental URLs that differ only in a numeric path segment
//     (/api/users/123 vs /api/users/456 collapse to one),
//   - human-written content such as blog/post/docs paths,
//   - URLs on an already-seen path that add no new parameter name.

// uroStaticBlacklist is uro's default extension blacklist, applied only when the
// caller sets neither a whitelist nor a custom blacklist.
var uroStaticBlacklist = []string{
	"css", "png", "jpg", "jpeg", "svg", "ico", "webp", "scss", "tif", "tiff",
	"ttf", "otf", "woff", "woff2", "gif", "pdf", "bmp", "eot", "mp3", "mp4", "avi",
}

// uroVulnParams is the set of parameter names uro treats as potentially
// vulnerable (used by the "vuln" filter). This mirrors the common subset of
// uro's list: redirect/SSRF, file/path, command and SQL-style names.
var uroVulnParams = []string{
	"file", "document", "folder", "root", "path", "pg", "style", "pdf",
	"template", "php_path", "doc", "url", "uri", "redirect", "redirect_uri",
	"redirect_url", "return", "returnurl", "return_url", "next", "continue",
	"dest", "destination", "go", "goto", "out", "view", "to", "image_url",
	"callback", "jsonp", "domain", "window", "cmd", "exec", "command", "execute",
	"ping", "query", "jump", "code", "reg", "do", "func", "arg", "option",
	"load", "process", "step", "read", "feature", "function", "req", "feed",
	"host", "port", "proxy", "site", "ip", "id", "page", "search", "action",
	"keyword", "q", "s", "sort", "order", "where", "select", "report", "role",
	"update", "download", "filename", "dir", "show", "debug", "test", "admin",
}

// UROOptions configures the decluttering processor.
type UROOptions struct {
	Whitelist   []string // keep only these extensions (plus extensionless)
	Blacklist   []string // drop these extensions (overrides the default static list)
	HasParams   bool     // keep only URLs with a query string
	NoParams    bool     // keep only URLs without a query string
	HasExt      bool     // keep only URLs with a file extension
	NoExt       bool     // keep only URLs without a file extension
	AllExts     bool     // disable extension filtering entirely
	KeepContent bool     // keep blog/post/docs-style content paths
	KeepSlash   bool     // keep trailing slashes (default: strip)
	Vuln        bool     // keep only URLs with a potentially vulnerable parameter
}

// Processor declutters a stream of URLs. It is stateful and NOT safe for
// concurrent use; feed URLs one at a time.
type Processor struct {
	opts       UROOptions
	whitelist  map[string]struct{}
	blacklist  map[string]struct{}
	vulnParams map[string]struct{}

	reInt     *regexp.Regexp
	reContent *regexp.Regexp

	hosts       map[string]*hostState
	contentSeen map[string]struct{} // cached content path prefixes already dropped
}

type hostState struct {
	paths        map[string]*pathState
	patternsSeen map[string]struct{}
}

type pathState struct {
	paramsSeen map[string]struct{}
}

// NewProcessor builds a uro-compatible processor from the given options.
func NewProcessor(opts UROOptions) *Processor {
	p := &Processor{
		opts:        opts,
		reInt:       regexp.MustCompile(`/\d+([?/]|$)`),
		reContent:   regexp.MustCompile(`(?i)(post|blog)s?|docs|support/|/(\d{4}|pages?)/\d+/`),
		hosts:       make(map[string]*hostState),
		contentSeen: make(map[string]struct{}),
	}

	if len(opts.Whitelist) > 0 {
		p.whitelist = toExtSet(opts.Whitelist)
	}
	switch {
	case len(opts.Blacklist) > 0:
		p.blacklist = toExtSet(opts.Blacklist)
	case p.whitelist == nil:
		p.blacklist = toExtSet(uroStaticBlacklist)
	}

	p.vulnParams = make(map[string]struct{}, len(uroVulnParams))
	for _, v := range uroVulnParams {
		p.vulnParams[v] = struct{}{}
	}
	return p
}

func toExtSet(exts []string) map[string]struct{} {
	m := make(map[string]struct{}, len(exts))
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(e, ".")))
		if e != "" {
			m[e] = struct{}{}
		}
	}
	return m
}

// Keep decides whether rawURL survives decluttering. When it returns true the
// returned string is the normalized URL to emit (trailing slash handling
// applied). When false, rawURL should be dropped.
func (p *Processor) Keep(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL, false
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	ext := Ext(rawURL)
	hasQuery := u.RawQuery != ""

	// --- parameter / extension presence filters ---
	if p.opts.HasParams && !hasQuery {
		return rawURL, false
	}
	if p.opts.NoParams && hasQuery {
		return rawURL, false
	}
	if p.opts.HasExt && ext == "" {
		return rawURL, false
	}
	if p.opts.NoExt && ext != "" {
		return rawURL, false
	}

	// --- extension allow/deny ---
	if !p.opts.AllExts && ext != "" {
		if p.whitelist != nil {
			if _, ok := p.whitelist[ext]; !ok {
				return rawURL, false
			}
		} else if p.blacklist != nil {
			if _, ok := p.blacklist[ext]; ok {
				return rawURL, false
			}
		}
	}

	// --- vuln parameter filter ---
	if p.opts.Vuln {
		if !p.hasVulnParam(u) {
			return rawURL, false
		}
	}

	// --- human-written content ---
	if !p.opts.KeepContent && p.isContent(path) {
		return rawURL, false
	}

	// --- structural dedup ---
	hs := p.hosts[u.Host]
	if hs == nil {
		hs = &hostState{paths: make(map[string]*pathState), patternsSeen: make(map[string]struct{})}
		p.hosts[u.Host] = hs
	}

	if p.reInt.MatchString(path) {
		pattern := p.createPattern(path)
		if _, seen := hs.patternsSeen[pattern]; seen {
			return rawURL, false
		}
		hs.patternsSeen[pattern] = struct{}{}
		return p.normalize(u), true
	}

	ps := hs.paths[path]
	if ps == nil {
		ps = &pathState{paramsSeen: make(map[string]struct{})}
		hs.paths[path] = ps
		p.recordParams(ps, u)
		return p.normalize(u), true
	}

	// Path already seen: keep only if it introduces a new parameter name.
	if p.introducesNewParam(ps, u) {
		p.recordParams(ps, u)
		return p.normalize(u), true
	}
	return rawURL, false
}

func (p *Processor) hasVulnParam(u *url.URL) bool {
	for k := range u.Query() {
		if _, ok := p.vulnParams[strings.ToLower(k)]; ok {
			return true
		}
	}
	return false
}

// isContent reports whether path looks like human-written content. Matching
// prefixes are cached so sibling paths are dropped cheaply.
func (p *Processor) isContent(path string) bool {
	for prefix := range p.contentSeen {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	if p.reContent.MatchString(path) {
		p.contentSeen[contentPrefix(path)] = struct{}{}
		return true
	}
	for _, seg := range strings.Split(path, "/") {
		if strings.Count(seg, "-") > 3 {
			p.contentSeen[contentPrefix(path)] = struct{}{}
			return true
		}
	}
	return false
}

func contentPrefix(path string) string {
	segs := strings.Split(path, "/")
	if len(segs) > 2 {
		return strings.Join(segs[:3], "/")
	}
	return path
}

func (p *Processor) recordParams(ps *pathState, u *url.URL) {
	for k := range u.Query() {
		ps.paramsSeen[k] = struct{}{}
	}
}

func (p *Processor) introducesNewParam(ps *pathState, u *url.URL) bool {
	for k := range u.Query() {
		if _, ok := ps.paramsSeen[k]; !ok {
			return true
		}
	}
	return false
}

// createPattern replaces every all-digit path segment up to the last numeric
// one with \d+, quoting the rest, so incremental URLs collapse to one pattern.
func (p *Processor) createPattern(path string) string {
	segs := strings.Split(path, "/")
	last := -1
	for i, s := range segs {
		if s != "" && isAllDigits(s) {
			last = i
		}
	}
	if last == -1 {
		return regexp.QuoteMeta(path)
	}
	parts := make([]string, 0, last+1)
	for i := 0; i <= last; i++ {
		if segs[i] != "" && isAllDigits(segs[i]) {
			parts = append(parts, `\d+`)
		} else {
			parts = append(parts, regexp.QuoteMeta(segs[i]))
		}
	}
	return strings.Join(parts, "/")
}

func (p *Processor) normalize(u *url.URL) string {
	s := u.String()
	if !p.opts.KeepSlash && u.RawQuery == "" && strings.HasSuffix(s, "/") && len(s) > len(u.Scheme)+3 {
		s = strings.TrimRight(s, "/")
	}
	return s
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
