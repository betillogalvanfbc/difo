package difo

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config holds everything needed for one DIFO run.
type Config struct {
	Version string

	// Targets
	Domains     []string
	IncludeSubs bool
	Collapse    string
	MatchType   string
	Limit       int
	From        string
	To          string

	// URL sources: any of "wayback", "otx", "commoncrawl" (aliases: wb, cc,
	// alienvault, all). Defaults to wayback.
	Sources   []string
	CCIndexes int // number of recent Common Crawl indexes to query

	// Matching
	Extensions []string
	Keywords   []string
	MatchAll   bool // report every URL (disable sensitive filtering)

	// Decluttering (uro-compatible)
	UseURO bool
	URO    UROOptions

	// Snapshots
	Snapshot    bool
	Concurrency int

	// Download of archived file content
	Download     bool
	OutDir       string // directory to save downloaded files into
	StatusFilter string // CDX statuscode filter, e.g. "200" or "200,301" or "any"
	MaxSize      int64  // max bytes per downloaded file (<=0 = unlimited)
	LatestOnly   bool   // download only the newest version instead of every distinct one
	DownloadConc int    // concurrency for downloads

	// Live capture: fetch the domain's CURRENT assets from the live origin
	Live         bool
	LiveExternal bool     // include third-party/external asset hosts
	LiveAssets   []string // asset types to capture: js, css, map (default all)
	LiveMax      int      // max assets to fetch in the recursive crawl

	// Output
	HitFile  string // write findings here
	DumpFile string // write the full (optionally decluttered) URL list here
	JSON     bool
	Silent   bool
	NoColor  bool

	// HTTP
	Timeout   time.Duration
	UserAgent string
	Retries   int           // retries on 429/5xx (per request)
	RetryBase time.Duration // base backoff
	RateDelay time.Duration // polite fixed delay before each request
}

// Finding is a single interesting URL plus its resolved snapshot (if requested).
type Finding struct {
	Domain   string    `json:"domain"`
	URL      string    `json:"url"`
	Match    string    `json:"match"`
	Ext      string    `json:"ext,omitempty"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Run executes the full pipeline for all configured domains.
func Run(ctx context.Context, cfg Config) error {
	ui := NewUI(cfg.NoColor)
	if !cfg.Silent {
		ui.Banner(cfg.Version)
	}

	matcher := NewMatcher(cfg.Extensions, cfg.Keywords, cfg.MatchAll)
	note := retryNotifier(ui, cfg.Silent)
	cdx := NewCDXClient(cfg.Timeout, cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	cdx.Retry.notify = note

	sources := buildSources(cfg, cdx, note)
	if !cfg.Silent {
		names := make([]string, len(sources))
		for i, s := range sources {
			names[i] = s.Name()
		}
		ui.Info("Sources: %s", strings.Join(names, ", "))
	}

	// Optional output files.
	hitW, closeHit, err := openWriter(cfg.HitFile)
	if err != nil {
		return err
	}
	defer closeHit()

	dumpW, closeDump, err := openWriter(cfg.DumpFile)
	if err != nil {
		return err
	}
	defer closeDump()

	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()

	var allFindings []Finding
	var totalRetrieved, totalKept, totalHits int
	var totalFiles, totalVersions int
	var totalBytes int64
	var totalLive int
	var totalLiveBytes int64
	perExt := map[string]int{}

	for _, domain := range cfg.Domains {
		if !cfg.Silent {
			ui.Info("Target: %s", bold(ui, domain))
		}

		var proc *Processor
		if cfg.UseURO {
			proc = NewProcessor(cfg.URO)
		}
		hitDedup := NewDeduper()
		exactSeen := make(map[string]struct{}) // cross-source exact-URL dedup

		var domainFindings []Finding
		var retrieved, kept int

		// process handles one URL from any source through the shared pipeline.
		process := func(rawURL string) bool {
			// Global limit across all sources.
			if cfg.Limit > 0 && retrieved >= cfg.Limit {
				return false
			}
			// Skip URLs already seen from another source.
			if _, dup := exactSeen[rawURL]; dup {
				return true
			}
			exactSeen[rawURL] = struct{}{}
			retrieved++

			matched, label := matcher.Match(rawURL)

			// Full-list output (dump / -all mode). Sensitive hits always survive
			// decluttering so a backup file is never silently dropped.
			emit := rawURL
			keep := true
			if proc != nil {
				if norm, ok := proc.Keep(rawURL); ok {
					emit = norm
				} else if !matched {
					keep = false
				}
			}
			if keep {
				kept++
				if dumpW != nil {
					fmt.Fprintln(dumpW, emit)
				}
				if cfg.MatchAll {
					// Stream every URL immediately so a downstream pipe
					// (| httpx | naabu | nuclei) can start at once.
					fmt.Fprintln(stdout, emit)
					stdout.Flush()
				}
			}

			if !matched || cfg.MatchAll {
				return true
			}
			if !hitDedup.Add(rawURL) {
				return true
			}

			f := Finding{Domain: domain, URL: rawURL, Match: label, Ext: Ext(rawURL)}
			domainFindings = append(domainFindings, f)

			// Stream the plain URL to stdout (and the hit file) as soon as it is
			// found, line-flushed, for live pipelines. JSON output is emitted
			// later because it may carry snapshot data resolved after the stream.
			if !cfg.JSON {
				fmt.Fprintln(stdout, f.URL)
				stdout.Flush()
				if hitW != nil {
					fmt.Fprintln(hitW, f.URL)
				}
			}
			return true
		}

		for _, src := range sources {
			if !cfg.Silent {
				ui.Dim("    [%s] fetching known URLs ...", src.Name())
			}
			if err := src.Fetch(ctx, domain, cfg.IncludeSubs, process); err != nil {
				ui.Err("%s [%s]: %v", domain, src.Name(), err)
			}
		}

		totalRetrieved += retrieved
		totalKept += kept

		if !cfg.Silent {
			ui.Good("%s: retrieved %s URLs from %d source(s)", domain, comma(retrieved), len(sources))
			if cfg.UseURO {
				ui.Good("%s: %s URLs after uro declutter", domain, comma(kept))
			}
		}

		// Resolve snapshots (concurrently) if requested.
		if cfg.Snapshot && len(domainFindings) > 0 {
			resolveSnapshots(ctx, domainFindings, cfg, ui)
		}

		// Finalize findings for this domain. Plain URLs were already streamed to
		// stdout/hit-file during the scan; here we emit JSON (which may include
		// snapshot data) and the human-readable stderr view.
		for i := range domainFindings {
			f := domainFindings[i]
			totalHits++
			perExt[nonEmpty(f.Match)]++

			if cfg.JSON {
				b, _ := json.Marshal(f)
				fmt.Fprintln(stdout, string(b))
				if hitW != nil {
					fmt.Fprintln(hitW, f.URL)
				}
			}
			if !cfg.Silent {
				ui.Hit(f.Match, f.URL)
				if cfg.Snapshot && f.Snapshot != nil {
					ui.SnapshotLine(*f.Snapshot)
				}
			}
		}
		allFindings = append(allFindings, domainFindings...)
		stdout.Flush()

		// Download archived file content for this domain's findings.
		if cfg.Download && !cfg.MatchAll && len(domainFindings) > 0 {
			if !cfg.Silent {
				ui.Info("%s: downloading archived content (status %s) to %s/", domain, cfg.StatusFilter, cfg.OutDir)
			}
			files, versions, bytes := downloadLoot(ctx, domainFindings, cfg, ui)
			totalFiles += files
			totalVersions += versions
			totalBytes += bytes
		}

		// Capture the domain's CURRENT scripts from the live origin.
		if cfg.Live {
			if !cfg.Silent {
				ui.Info("%s: capturing live scripts from origin to %s/", domain, cfg.OutDir)
			}
			lf, lb := liveCapture(ctx, domain, domainFindings, cfg, ui)
			totalLive += lf
			totalLiveBytes += lb
		}
	}

	if !cfg.Silent {
		printSummary(ui, totalRetrieved, totalKept, totalHits, perExt, cfg)
		if cfg.Download {
			ui.Good("downloaded %s archived files (%s unique content versions) · %s",
				comma(totalFiles), comma(totalVersions), humanBytes(totalBytes))
		}
		if cfg.Live {
			ui.Good("captured %s live script(s) · %s", comma(totalLive), humanBytes(totalLiveBytes))
		}
		if cfg.Download || cfg.Live {
			ui.Dim("    saved under: %s", cfg.OutDir)
		}
	}
	_ = allFindings
	return nil
}

// downloadLoot enumerates all archived captures of each finding, keeps one per
// distinct content digest, downloads them, then dedupes again by the SHA1 of
// the downloaded bytes so only genuinely distinct content is kept (one copy per
// real version); unchanged files download once. Saves run concurrently.
func downloadLoot(ctx context.Context, findings []Finding, cfg Config, ui *UI) (files, versions int, bytes int64) {
	cdx := NewCDXClient(cfg.Timeout, cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	dl := NewDownloader(cfg.Timeout, cfg.MaxSize, cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	note := retryNotifier(ui, cfg.Silent)
	cdx.Retry.notify = note
	dl.Retry.notify = note
	if cfg.UserAgent != "" {
		dl.UserAgent = cfg.UserAgent
	}

	conc := cfg.DownloadConc
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := range findings {
		f := findings[i]
		wg.Add(1)
		sem <- struct{}{}
		go func(f Finding) {
			defer wg.Done()
			defer func() { <-sem }()

			caps, err := cdx.Captures(ctx, f.URL, cfg.StatusFilter, cfg.From, cfg.To, cfg.UserAgent)
			if err != nil {
				mu.Lock()
				if !cfg.Silent {
					ui.Err("captures %s: %v", f.URL, err)
				}
				mu.Unlock()
				return
			}

			// Sort newest-first so that when several captures share content, the
			// most recent one is the copy we keep (both for digest and content
			// dedup below).
			sort.Slice(caps, func(i, j int) bool { return caps[i].Timestamp > caps[j].Timestamp })

			uniq := UniqueByDigest(caps)
			if cfg.LatestOnly {
				if c, ok := Latest(uniq); ok {
					uniq = []Capture{c}
				}
			}

			// contentSeen dedupes by the SHA1 of the actually-downloaded bytes,
			// so captures with differing CDX digests but identical content (e.g.
			// gzip vs plain) are kept only once. It is goroutine-local to this
			// finding, so no locking is needed for it.
			contentSeen := make(map[string]struct{})

			for _, c := range uniq {
				dest, n, sum, err := dl.Fetch(ctx, c, cfg.OutDir)
				if err != nil {
					mu.Lock()
					if !cfg.Silent {
						ui.Err("download %s @ %s: %v", f.URL, c.Timestamp, err)
					}
					mu.Unlock()
					continue
				}
				if sum != "" {
					if _, dup := contentSeen[sum]; dup {
						os.Remove(dest) // identical content already saved for this URL
						continue
					}
					contentSeen[sum] = struct{}{}
				}
				mu.Lock()
				files++
				versions++
				bytes += n
				if !cfg.Silent {
					ui.Saved(c.Timestamp, n, dest)
				}
				mu.Unlock()
			}
		}(f)
	}
	wg.Wait()
	return files, versions, bytes
}

func resolveSnapshots(ctx context.Context, findings []Finding, cfg Config, ui *UI) {
	resolver := NewSnapshotResolver(cfg.Timeout, cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	resolver.Retry.notify = retryNotifier(ui, cfg.Silent)
	if cfg.UserAgent != "" {
		resolver.UserAgent = cfg.UserAgent
	}

	conc := cfg.Concurrency
	if conc < 1 {
		conc = 1
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i := range findings {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			snap, err := resolver.Closest(ctx, findings[i].URL)
			if err == nil {
				findings[i].Snapshot = &snap
			}
		}(i)
	}
	wg.Wait()
}

func printSummary(ui *UI, retrieved, kept, hits int, perExt map[string]int, cfg Config) {
	fmt.Fprintln(os.Stderr)
	ui.Info("Summary")
	ui.Dim("    retrieved : %s", comma(retrieved))
	if cfg.UseURO {
		ui.Dim("    decluttered: %s", comma(kept))
	}
	if cfg.MatchAll {
		return
	}
	if hits == 0 {
		ui.Warn("no potentially sensitive URLs found")
		return
	}
	ui.Warn("%s potentially sensitive URLs found", comma(hits))

	// Sort extension buckets by count desc for a readable breakdown.
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range perExt {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].v != sorted[j].v {
			return sorted[i].v > sorted[j].v
		}
		return sorted[i].k < sorted[j].k
	})
	for _, e := range sorted {
		ui.Dim("    %-12s %d", e.k, e.v)
	}
}

func openWriter(path string) (*bufio.Writer, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("creating %s: %w", path, err)
	}
	w := bufio.NewWriter(f)
	closer := func() {
		w.Flush()
		f.Close()
	}
	return w, closer, nil
}

func nonEmpty(s string) string {
	if s == "" {
		return "match"
	}
	return s
}

func bold(ui *UI, s string) string { return ui.paint(cBold, s) }

// retryNotifier returns a callback that reports backoff waits to the UI, or nil
// when silent.
func retryNotifier(ui *UI, silent bool) func(int, time.Duration, int, int) {
	if silent {
		return nil
	}
	return func(status int, wait time.Duration, attempt, max int) {
		switch {
		case status == 429:
			ui.Warn("rate-limited (429) — waiting %s, retry %d/%d", wait.Round(time.Second), attempt+1, max)
		case status == 0:
			ui.Warn("network error — waiting %s, retry %d/%d", wait.Round(time.Second), attempt+1, max)
		default:
			ui.Warn("upstream HTTP %d — waiting %s, retry %d/%d", status, wait.Round(time.Second), attempt+1, max)
		}
	}
}

// humanBytes formats a byte count as a human-readable size.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// comma formats an int with thousands separators.
func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}
