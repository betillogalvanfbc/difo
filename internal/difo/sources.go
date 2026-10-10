package difo

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Source is a provider of known URLs for a domain. Implementations stream URLs
// to emit; emit returns false to request an early stop (e.g. a global limit was
// reached), which the source must honor.
type Source interface {
	Name() string
	Fetch(ctx context.Context, domain string, includeSubs bool, emit func(rawURL string) bool) error
}

// ---------------------------------------------------------------------------
// Wayback Machine (CDX API)
// ---------------------------------------------------------------------------

// WaybackSource wraps the CDX client as a Source.
type WaybackSource struct {
	client    *CDXClient
	collapse  string
	matchType string
	from, to  string
	ua        string
	limit     int
}

func (s *WaybackSource) Name() string { return "wayback" }

func (s *WaybackSource) Fetch(ctx context.Context, domain string, includeSubs bool, emit func(string) bool) error {
	q := CDXQuery{
		Domain:      domain,
		IncludeSubs: includeSubs,
		Collapse:    s.collapse,
		MatchType:   s.matchType,
		Limit:       s.limit,
		From:        s.from,
		To:          s.to,
		UserAgent:   s.ua,
	}
	return s.client.Stream(ctx, q, emit)
}

// ---------------------------------------------------------------------------
// AlienVault OTX (Open Threat Exchange)
// ---------------------------------------------------------------------------

// OTXSource pulls passively-observed URLs from AlienVault OTX. No API key is
// needed for the public url_list endpoint.
type OTXSource struct {
	http  *http.Client
	retry retryConfig
	ua    string
}

func (s *OTXSource) Name() string { return "otx" }

type otxResponse struct {
	URLList []struct {
		URL string `json:"url"`
	} `json:"url_list"`
	HasNext  bool `json:"has_next"`
	FullSize int  `json:"full_size"`
}

func (s *OTXSource) Fetch(ctx context.Context, domain string, includeSubs bool, emit func(string) bool) error {
	const maxPages = 1000 // safety bound
	for page := 1; page <= maxPages; page++ {
		reqURL := fmt.Sprintf(
			"https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=%d",
			url.PathEscape(domain), page,
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", s.userAgent())

		resp, err := doWithRetry(s.http, req, s.retry)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil // nothing indexed for this domain
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("OTX HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}

		var or otxResponse
		if err := json.Unmarshal(body, &or); err != nil {
			return fmt.Errorf("decoding OTX json: %w", err)
		}
		if len(or.URLList) == 0 {
			return nil
		}
		for _, u := range or.URLList {
			if u.URL == "" {
				continue
			}
			if !emit(u.URL) {
				return nil
			}
		}
		if !or.HasNext {
			return nil
		}
	}
	return nil
}

func (s *OTXSource) userAgent() string {
	if s.ua != "" {
		return s.ua
	}
	return "difo/1.0 (+information-disclosure-hunter)"
}

// ---------------------------------------------------------------------------
// Common Crawl (CDX index per crawl)
// ---------------------------------------------------------------------------

// CommonCrawlSource queries the most recent Common Crawl indexes. Common Crawl
// publishes one CDX index per crawl; this source fetches collinfo.json to find
// them and queries the newest `indexes` of them.
type CommonCrawlSource struct {
	http    *http.Client
	retry   retryConfig
	ua      string
	indexes int // number of most-recent indexes to query
}

func (s *CommonCrawlSource) Name() string { return "commoncrawl" }

type ccCollection struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

func (s *CommonCrawlSource) collections(ctx context.Context) ([]ccCollection, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.userAgent())

	resp, err := doWithRetry(s.http, req, s.retry)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Common Crawl collinfo HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var cols []ccCollection
	if err := json.Unmarshal(body, &cols); err != nil {
		return nil, fmt.Errorf("decoding collinfo: %w", err)
	}
	// collinfo.json is newest-first; sort by id desc defensively.
	sort.Slice(cols, func(i, j int) bool { return cols[i].ID > cols[j].ID })
	return cols, nil
}

func (s *CommonCrawlSource) Fetch(ctx context.Context, domain string, includeSubs bool, emit func(string) bool) error {
	cols, err := s.collections(ctx)
	if err != nil {
		return err
	}
	n := s.indexes
	if n < 1 {
		n = 1
	}
	if n > len(cols) {
		n = len(cols)
	}

	pattern := domain + "/*"
	if includeSubs {
		pattern = "*." + domain + "/*"
	}

	for _, col := range cols[:n] {
		if col.CDXAPI == "" {
			continue
		}
		if stop, err := s.fetchIndex(ctx, col, pattern, emit); err != nil {
			return err
		} else if stop {
			return nil
		}
	}
	return nil
}

// fetchIndex streams one Common Crawl index. It returns stop=true when emit
// asked to halt. A 404 (no captures) is treated as an empty result.
func (s *CommonCrawlSource) fetchIndex(ctx context.Context, col ccCollection, pattern string, emit func(string) bool) (bool, error) {
	reqURL := col.CDXAPI + "?url=" + url.QueryEscape(pattern) + "&output=json&fl=url"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", s.userAgent())

	resp, err := doWithRetry(s.http, req, s.retry)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil // no captures in this index
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("Common Crawl %s HTTP %d", col.ID, resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var row struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.URL == "" {
			continue
		}
		if !emit(row.URL) {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("reading Common Crawl stream: %w", err)
	}
	return false, nil
}

func (s *CommonCrawlSource) userAgent() string {
	if s.ua != "" {
		return s.ua
	}
	return "difo/1.0 (+information-disclosure-hunter)"
}

// ---------------------------------------------------------------------------
// Source construction
// ---------------------------------------------------------------------------

// NormalizeSources maps user-supplied source names (with aliases) to canonical
// names, preserving order and removing duplicates. "all" expands to every
// source.
func NormalizeSources(names []string) []string {
	alias := map[string]string{
		"wayback": "wayback", "wb": "wayback", "web.archive.org": "wayback",
		"otx": "otx", "alienvault": "otx",
		"commoncrawl": "commoncrawl", "cc": "commoncrawl", "common-crawl": "commoncrawl",
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(c string) {
		if _, ok := seen[c]; !ok {
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "all" {
			add("wayback")
			add("otx")
			add("commoncrawl")
			continue
		}
		if c, ok := alias[n]; ok {
			add(c)
		}
	}
	if len(out) == 0 {
		out = []string{"wayback"}
	}
	return out
}

// buildSources constructs the enabled Source implementations from config.
func buildSources(cfg Config, cdx *CDXClient, note func(int, time.Duration, int, int)) []Source {
	retry := defaultRetry(cfg.Retries, cfg.RetryBase, cfg.RateDelay)
	retry.notify = note
	newClient := func() *http.Client { return &http.Client{Timeout: cfg.Timeout} }

	var srcs []Source
	for _, name := range NormalizeSources(cfg.Sources) {
		switch name {
		case "wayback":
			srcs = append(srcs, &WaybackSource{
				client: cdx, collapse: cfg.Collapse, matchType: cfg.MatchType,
				from: cfg.From, to: cfg.To, ua: cfg.UserAgent, limit: cfg.Limit,
			})
		case "otx":
			srcs = append(srcs, &OTXSource{http: newClient(), retry: retry, ua: cfg.UserAgent})
		case "commoncrawl":
			srcs = append(srcs, &CommonCrawlSource{http: newClient(), retry: retry, ua: cfg.UserAgent, indexes: cfg.CCIndexes})
		}
	}
	return srcs
}
