package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"difo/internal/difo"
)

const version = "1.0.0"

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	// Ctrl-C cancels in-flight HTTP work cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := difo.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags() (difo.Config, error) {
	var (
		domain    = flag.String("d", "", "single target domain (e.g. example.com)")
		listFile  = flag.String("l", "", "file with one target domain per line")
		sources   = flag.String("sources", "wayback", "URL sources: wayback,otx,commoncrawl (aliases: wb,cc,alienvault) or 'all'")
		ccIndexes = flag.Int("cc-indexes", 3, "number of recent Common Crawl indexes to query")
		subs      = flag.Bool("subs", true, "include subdomains (*.domain)")
		collapse  = flag.String("collapse", "urlkey", "CDX collapse field")
		matchType = flag.String("mt", "", "CDX matchType: exact|prefix|host|domain")
		limit     = flag.Int("limit", 0, "max results from CDX (0 = no limit)")
		from      = flag.String("from", "", "earliest capture date (YYYYMMDD)")
		to        = flag.String("to", "", "latest capture date (YYYYMMDD)")

		extCSV    = flag.String("ext", "", "override sensitive extensions (comma-separated)")
		addExtCSV = flag.String("add-ext", "", "add extensions to the defaults (comma-separated)")
		kwCSV     = flag.String("kw", "", "override sensitive keywords (comma-separated)")
		addKwCSV  = flag.String("add-kw", "", "add keywords to the defaults (comma-separated)")
		matchAll  = flag.Bool("all", false, "output every URL instead of only sensitive ones")

		useURO    = flag.Bool("uro", true, "declutter results (uro-compatible)")
		whitelist = flag.String("w", "", "uro: keep only these extensions (comma-separated)")
		blacklist = flag.String("b", "", "uro: drop these extensions (comma-separated)")
		hasParams = flag.Bool("hasparams", false, "uro: keep only URLs with query params")
		noParams  = flag.Bool("noparams", false, "uro: keep only URLs without query params")
		hasExt    = flag.Bool("hasext", false, "uro: keep only URLs with a file extension")
		noExt     = flag.Bool("noext", false, "uro: keep only URLs without a file extension")
		allExts   = flag.Bool("allexts", false, "uro: disable extension filtering")
		keepCont  = flag.Bool("keepcontent", false, "uro: keep blog/post/docs content paths")
		keepSlash = flag.Bool("keepslash", false, "uro: keep trailing slashes")
		vuln      = flag.Bool("vuln", false, "uro: keep only URLs with vulnerable-looking params")

		snapshot = flag.Bool("snapshot", false, "resolve the closest Wayback snapshot for each finding")
		conc     = flag.Int("c", 20, "concurrency for snapshot resolution")

		download   = flag.Bool("download", false, "download archived file content for each finding")
		outDir     = flag.String("outdir", "loot", "directory to save downloaded files into")
		status     = flag.String("status", "200", "CDX status code filter for downloads: e.g. 200, 200,301, or any")
		maxSizeMB  = flag.Int("max-size", 25, "max size per downloaded file in MB (0 = unlimited)")
		latestOnly = flag.Bool("latest", false, "download only the newest version instead of every distinct one")
		dlConc     = flag.Int("dc", 5, "concurrency for downloads")

		live       = flag.Bool("live", false, "also download the domain's CURRENT assets from the live origin")
		liveExt    = flag.Bool("live-external", false, "include third-party/external asset hosts in live capture")
		liveAssets = flag.String("live-assets", "js,css,map", "live asset types to capture (comma: js,css,map)")
		liveMax    = flag.Int("live-max", 1000, "max assets to fetch in the recursive live crawl")

		hitFile  = flag.String("o", "", "write findings (URLs) to this file")
		dumpFile = flag.String("dump", "", "write the full URL list to this file")
		jsonOut  = flag.Bool("json", false, "emit findings as JSON lines on stdout")
		silent   = flag.Bool("silent", false, "only print result URLs to stdout (no banner/UI)")
		noColor  = flag.Bool("no-color", false, "disable ANSI colors")

		timeoutS = flag.Int("timeout", 60, "HTTP timeout in seconds")
		ua       = flag.String("ua", "", "custom User-Agent header")
		retries  = flag.Int("retries", 4, "retries on HTTP 429/5xx (exponential backoff)")
		retryBS  = flag.Int("retry-base", 2, "base backoff in seconds (doubles each retry)")
		delayMS  = flag.Int("delay", 0, "polite delay before each request, in milliseconds")
		showVer  = flag.Bool("version", false, "print version and exit")
	)

	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("difo", version)
		os.Exit(0)
	}

	domains := collectDomains(*domain, *listFile, flag.Args())
	if len(domains) == 0 {
		usage()
		return difo.Config{}, fmt.Errorf("no target domain provided")
	}

	// Build extension list.
	exts := difo.DefaultExtensions
	if *extCSV != "" {
		exts = splitCSV(*extCSV)
	}
	exts = append(exts, splitCSV(*addExtCSV)...)

	// Build keyword list.
	kws := difo.DefaultKeywords
	if *kwCSV != "" {
		kws = splitCSV(*kwCSV)
	}
	kws = append(kws, splitCSV(*addKwCSV)...)

	cfg := difo.Config{
		Version:     version,
		Domains:     domains,
		Sources:     splitCSV(*sources),
		CCIndexes:   *ccIndexes,
		IncludeSubs: *subs,
		Collapse:    *collapse,
		MatchType:   *matchType,
		Limit:       *limit,
		From:        *from,
		To:          *to,
		Extensions:  exts,
		Keywords:    kws,
		MatchAll:    *matchAll,
		UseURO:      *useURO,
		URO: difo.UROOptions{
			Whitelist:   splitCSV(*whitelist),
			Blacklist:   splitCSV(*blacklist),
			HasParams:   *hasParams,
			NoParams:    *noParams,
			HasExt:      *hasExt,
			NoExt:       *noExt,
			AllExts:     *allExts,
			KeepContent: *keepCont,
			KeepSlash:   *keepSlash,
			Vuln:        *vuln,
		},
		Snapshot:     *snapshot,
		Concurrency:  *conc,
		Download:     *download,
		OutDir:       *outDir,
		StatusFilter: *status,
		MaxSize:      int64(*maxSizeMB) * 1024 * 1024,
		LatestOnly:   *latestOnly,
		DownloadConc: *dlConc,
		Live:         *live,
		LiveExternal: *liveExt,
		LiveAssets:   splitCSV(*liveAssets),
		LiveMax:      *liveMax,
		HitFile:      *hitFile,
		DumpFile:     *dumpFile,
		JSON:         *jsonOut,
		Silent:       *silent,
		NoColor:      *noColor,
		Timeout:      time.Duration(*timeoutS) * time.Second,
		UserAgent:    *ua,
		Retries:      *retries,
		RetryBase:    time.Duration(*retryBS) * time.Second,
		RateDelay:    time.Duration(*delayMS) * time.Millisecond,
	}
	return cfg, nil
}

// collectDomains gathers targets from -d, -l <file>, positional args, and stdin
// (when piped), normalizing each to a bare host.
func collectDomains(single, listFile string, args []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = normalizeDomain(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	if single != "" {
		add(single)
	}
	for _, a := range args {
		add(a)
	}
	if listFile != "" {
		if f, err := os.Open(listFile); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				add(sc.Text())
			}
			f.Close()
		}
	}
	// Read piped stdin only if nothing else was given.
	if len(out) == 0 && isPiped(os.Stdin) {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			add(sc.Text())
		}
	}
	return out
}

func normalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 { // strip creds
		s = s[i+1:]
	}
	if i := strings.Index(s, ":"); i >= 0 { // strip port
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	return strings.ToLower(strings.TrimSpace(s))
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isPiped(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func usage() {
	w := flag.CommandLine.Output()
	fmt.Fprintf(w, `difo %s -  inFOrmation DIsclosure 

USAGE:
  difo -d <domain> [options]
  difo <domain> [domain ...] [options]
  cat domains.txt | difo [options]

EXAMPLES:
  # Hunt sensitive files across all subdomains of a target
  difo -d example.com

  # Aggregate URLs from Wayback + AlienVault OTX + Common Crawl
  difo -d example.com -sources all

  # Save every archived URL to a file, then the findings separately
  difo -d example.com -dump all.txt -o hits.txt

  # Resolve the closest archived snapshot for each finding (handles 404s)
  difo -d example.com -snapshot -c 30

  # Download every distinct version (by content hash) of each found file.
  # A .js captured in 2023 and 2024 with different content yields BOTH copies.
  difo -d example.com -download -outdir loot

  # Download only the newest 200-status copy of each .js/.json/.xml
  difo -d example.com -ext js,json,xml -download -latest -status 200

  # Only .sql / .bak / .env, piped to another tool
  difo -d example.com -ext sql,bak,env -silent

  # Dump every decluttered URL (acts like 'waybackurls | uro')
  difo -d example.com -all > urls.txt

OPTIONS:
`, version)
	flag.PrintDefaults()
}
