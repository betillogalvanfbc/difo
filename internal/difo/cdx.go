package difo

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const cdxEndpoint = "https://web.archive.org/cdx/search/cdx"

// CDXQuery describes a single Wayback CDX search.
type CDXQuery struct {
	Domain      string // e.g. "example.com"
	IncludeSubs bool   // query *.domain/* instead of domain/*
	Collapse    string // CDX collapse field, e.g. "urlkey"
	MatchType   string // CDX matchType: exact, prefix, host, domain (optional)
	Limit       int    // 0 means no limit
	From        string // YYYYMMDD... (optional)
	To          string // YYYYMMDD... (optional)
	UserAgent   string
}

// buildURL assembles the CDX request URL with properly encoded parameters.
func (q CDXQuery) buildURL() string {
	v := url.Values{}

	urlParam := q.Domain + "/*"
	if q.IncludeSubs {
		urlParam = "*." + q.Domain + "/*"
	}
	v.Set("url", urlParam)
	v.Set("output", "text")
	v.Set("fl", "original")
	if q.Collapse != "" {
		v.Set("collapse", q.Collapse)
	}
	if q.MatchType != "" {
		v.Set("matchType", q.MatchType)
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.From != "" {
		v.Set("from", q.From)
	}
	if q.To != "" {
		v.Set("to", q.To)
	}
	return cdxEndpoint + "?" + v.Encode()
}

// CDXClient fetches URLs from the Wayback Machine CDX API.
type CDXClient struct {
	HTTP  *http.Client
	Retry retryConfig
}

// NewCDXClient returns a client with the given timeout and retry policy.
func NewCDXClient(timeout time.Duration, retries int, base, delay time.Duration) *CDXClient {
	return &CDXClient{
		HTTP:  &http.Client{Timeout: timeout},
		Retry: defaultRetry(retries, base, delay),
	}
}

// Stream performs the CDX query and calls fn for every URL line returned, as
// they arrive. It stops early (without error) if fn returns false.
func (c *CDXClient) Stream(ctx context.Context, q CDXQuery, fn func(rawURL string) bool) error {
	reqURL := q.buildURL()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	ua := q.UserAgent
	if ua == "" {
		ua = "difo/1.0 (+information-disclosure-hunter)"
	}
	req.Header.Set("User-Agent", ua)

	resp, err := doWithRetry(c.HTTP, req, c.Retry)
	if err != nil {
		return fmt.Errorf("requesting CDX: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("CDX returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	sc := bufio.NewScanner(resp.Body)
	// Archived URLs can be very long; grow the scanner buffer accordingly.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !fn(line) {
			return nil
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading CDX stream: %w", err)
	}
	return nil
}

// RequestURL exposes the fully-built CDX URL for logging / debugging.
func (q CDXQuery) RequestURL() string { return q.buildURL() }
