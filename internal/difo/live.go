package difo

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// This file implements "live" capture: fetching the CURRENT .js a domain serves
// right now, straight from the origin (not the archive). Combined with the
// archived downloads it gives evidence of both the historical and the present
// state. It is the scriptable equivalent of a browser "resource saver" for the
// statically-referenced scripts; see the limitation note in Run's output.

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/125.0 Safari/537.36"

var (
	reScriptSrc  = regexp.MustCompile(`(?i)<script[^>]*\ssrc\s*=\s*["']([^"']+)["']`)
	reLinkHref   = regexp.MustCompile(`(?i)<link[^>]*\shref\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']`)
	reAnyJSQuote = regexp.MustCompile(`["']([^"'\s<>]+\.js(?:\?[^"']*)?)["']`)
	// reChunkPair matches a webpack/Angular chunk-map entry like 76:"a1b2c3..."
	// or "common":"deadbeef...", which reconstructs to <id>.<hash>.js.
	reChunkPair = regexp.MustCompile(`["']?([\w-]+)["']?\s*:\s*["']([0-9a-f]{8,32})["']`)
	// CSS references in HTML and inside CSS (@import / url()).
	reLinkCss     = regexp.MustCompile(`(?i)<link[^>]*\shref\s*=\s*["']([^"']+\.css(?:\?[^"']*)?)["']`)
	reAnyCssQuote = regexp.MustCompile(`["']([^"'\s<>]+\.css(?:\?[^"']*)?)["']`)
	// sourceMappingURL comment in JS (//# ...) and CSS (/*# ... */).
	reSourceMap = regexp.MustCompile(`(?i)sourceMappingURL=\s*([^\s'"*)]+)`)
)

// LiveFetcher discovers and downloads a domain's current scripts.
type LiveFetcher struct {
	http  *http.Client
	dl    *Downloader
	ua    string
	retry retryConfig
}

// NewLiveFetcher builds a live fetcher sharing the download size limit and retry
// policy.
func NewLiveFetcher(cfg Config, note func(int, time.Duration, int, int)) *LiveFetcher {
	retry := defaultRetry(cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	retry.notify = note
	dl := NewDownloader(cfg.Timeout, cfg.MaxSize, cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	dl.Retry.notify = note
	dl.UserAgent = browserUA
	return &LiveFetcher{
		http:  &http.Client{Timeout: cfg.Timeout},
		dl:    dl,
		ua:    browserUA,
		retry: retry,
	}
}

// DiscoverAssets fetches pageURL and returns the absolute .js and .css URLs it
// references (script src, stylesheet links, and any quoted *.js / *.css).
func (lf *LiveFetcher) DiscoverAssets(ctx context.Context, pageURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", lf.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := doWithRetry(lf.http, req, lf.retry)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("live page HTTP %d", resp.StatusCode)
	}

	// Resolve relative URLs against the final URL after redirects.
	base := resp.Request.URL
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	html := string(body)

	seen := map[string]struct{}{}
	var out []string
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "data:") {
			return
		}
		u, err := base.Parse(ref)
		if err != nil {
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return
		}
		u.Fragment = ""
		s := u.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, re := range []*regexp.Regexp{reScriptSrc, reLinkHref, reAnyJSQuote, reLinkCss, reAnyCssQuote} {
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			add(m[1])
		}
	}
	return out, nil
}

// extractCssRefs scans CSS text for @import and url(...) references to other
// .css files, resolved against base.
func extractCssRefs(css string, base *url.URL) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range reAnyCssQuote.FindAllStringSubmatch(css, -1) {
		ref := strings.TrimSpace(m[1])
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Fragment = ""
		if s := u.String(); func() bool { _, ok := seen[s]; return !ok }() {
			seen[u.String()] = struct{}{}
			out = append(out, u.String())
		}
	}
	return out
}

// extractSourceMap returns the absolute sourceMappingURL referenced in a JS or
// CSS file, if any, resolved against base.
func extractSourceMap(text string, base *url.URL) (string, bool) {
	m := reSourceMap.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	ref := strings.TrimSpace(m[1])
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return "", false
	}
	u, err := base.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	u.Fragment = ""
	return u.String(), true
}

// fetchSave downloads rawURL's current bytes to a "_live" area under outDir and
// returns the written path and the content (for recursive scanning).
func (lf *LiveFetcher) fetchSave(ctx context.Context, rawURL, outDir, stamp string) (string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", lf.ua)

	resp, err := doWithRetry(lf.http, req, lf.retry)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("live HTTP %d", resp.StatusCode)
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, lf.dl.MaxSize))
	if err != nil {
		return "", nil, err
	}

	dest := liveDestPath(outDir, rawURL, stamp)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(dest, content, 0o644); err != nil {
		return "", nil, err
	}
	return dest, content, nil
}

// extractJSRefs scans JavaScript (or HTML) text for further .js URLs: quoted
// paths ending in .js, and webpack/Angular chunk-map entries reconstructed as
// <id>.<hash>.js. Each is resolved against base (the containing file's URL, so
// sibling chunks resolve correctly).
func extractJSRefs(text string, base *url.URL) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "data:") {
			return
		}
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		u.Fragment = ""
		s := u.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, m := range reAnyJSQuote.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range reChunkPair.FindAllStringSubmatch(text, -1) {
		add(m[1] + "." + m[2] + ".js")
	}
	return out
}

// liveDestPath mirrors destPath but files live under a "_live" folder and are
// named with the capture time (now) so live copies never collide with archived
// ones.
func liveDestPath(outDir, rawURL, stamp string) string {
	host := "unknown-host"
	p := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		if u.Host != "" {
			host = u.Host
		}
		if u.Path != "" {
			p = u.Path
		}
	}
	name := path.Base(p)
	if name == "" || name == "/" || name == "." {
		name = "index"
	}

	parts := []string{outDir, sanitizeComponent(host), "_live"}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if seg != "" {
			parts = append(parts, sanitizeComponent(seg))
		}
	}
	dir := filepath.Join(parts...)
	fname := sanitizeComponent("live_" + stamp + "_" + name)
	return filepath.Join(dir, fname)
}

// liveCapture discovers the assets the live domain references now (.js, .css
// and their sourcemaps by default) and downloads each one's current bytes. It
// seeds from the domain root and from every host seen in the findings, then
// recursively follows webpack/Angular chunks and sourceMappingURL references.
func liveCapture(ctx context.Context, domain string, findings []Finding, cfg Config, ui *UI) (files int, bytes int64) {
	lf := NewLiveFetcher(cfg, retryNotifier(ui, cfg.Silent))
	stamp := time.Now().UTC().Format("20060102150405")

	allowed := map[string]struct{}{}
	for _, a := range cfg.LiveAssets {
		if a = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(a, "."))); a != "" {
			allowed[a] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		allowed = map[string]struct{}{"js": {}, "css": {}, "map": {}}
	}
	wantMaps := func() bool { _, ok := allowed["map"]; return ok }()

	maxFetch := cfg.LiveMax
	if maxFetch <= 0 {
		maxFetch = 1000
	}

	// typeAllowed keeps only the asset extensions we were asked to capture.
	typeAllowed := func(u string) bool {
		_, ok := allowed[Ext(u)]
		return ok
	}
	// accept applies the same-site and type filters to a candidate.
	accept := func(u string) bool {
		if !typeAllowed(u) {
			return false
		}
		if cfg.LiveExternal {
			return true
		}
		pu, err := url.Parse(u)
		return err == nil && sameSite(pu.Host, domain)
	}

	// Seed pages: the domain root plus each finding host's root.
	seeds := map[string]struct{}{"https://" + domain + "/": {}}
	for _, f := range findings {
		if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
			seeds[u.Scheme+"://"+u.Host+"/"] = struct{}{}
		}
	}

	cand := map[string]struct{}{}
	for seed := range seeds {
		assets, err := lf.DiscoverAssets(ctx, seed)
		if err != nil {
			if !cfg.Silent {
				ui.Dim("    live: could not read %s (%v)", seed, err)
			}
			continue
		}
		for _, a := range assets {
			cand[a] = struct{}{}
		}
	}
	for _, f := range findings { // also re-fetch archived asset findings live
		cand[f.URL] = struct{}{}
	}

	var urls []string
	for u := range cand {
		if accept(u) {
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)

	if !cfg.Silent {
		ui.Info("%s: live capture — %d entry asset(s); following chunks & sourcemaps ...", domain, len(urls))
	}

	// BFS: download each asset, scan its bytes for more assets (chunks, imported
	// CSS, sourcemaps), and follow them (filtered, bounded, deduped).
	visited := map[string]struct{}{}
	queue := append([]string(nil), urls...)
	enqueue := func(ref string) {
		if _, done := visited[ref]; done {
			return
		}
		if accept(ref) {
			queue = append(queue, ref)
		}
	}

	for len(queue) > 0 && files < maxFetch {
		u := queue[0]
		queue = queue[1:]
		if _, done := visited[u]; done {
			continue
		}
		visited[u] = struct{}{}

		dest, content, err := lf.fetchSave(ctx, u, cfg.OutDir, stamp)
		if err != nil {
			if !cfg.Silent {
				ui.Dim("    live skip %s (%v)", u, err)
			}
			continue
		}
		files++
		bytes += int64(len(content))
		if !cfg.Silent {
			ui.Saved("live-now", int64(len(content)), dest)
		}

		base, err := url.Parse(u)
		if err != nil {
			continue
		}
		ext := Ext(u)
		text := string(content)

		switch ext {
		case "js":
			for _, ref := range extractJSRefs(text, base) {
				enqueue(ref)
			}
		case "css":
			for _, ref := range extractCssRefs(text, base) {
				enqueue(ref)
			}
		}
		// Follow (or guess) the sourcemap for code files.
		if wantMaps && (ext == "js" || ext == "css") {
			if sm, ok := extractSourceMap(text, base); ok {
				enqueue(sm)
			} else {
				enqueue(u + ".map") // many builds ship the .map but strip the comment
			}
		}
	}

	if files >= maxFetch && !cfg.Silent {
		ui.Warn("%s: live capture hit the %d-asset limit (-live-max); some may remain", domain, maxFetch)
	}
	return files, bytes
}

// sameSite reports whether host belongs to the target domain (the target itself
// or a subdomain of its last two labels, e.g. *.vivaaerobus.com for a target of
// facturacion.vivaaerobus.com).
func sameSite(host, target string) bool {
	host = strings.ToLower(host)
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	base := baseDomain(target)
	return host == target || host == base || strings.HasSuffix(host, "."+base)
}

// baseDomain returns the last two labels of a domain (a simple heuristic, not a
// full public-suffix lookup).
func baseDomain(domain string) string {
	labels := strings.Split(strings.ToLower(domain), ".")
	if len(labels) <= 2 {
		return strings.Join(labels, ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
