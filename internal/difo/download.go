package difo

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Capture is a single archived snapshot of a URL as reported by the CDX API.
type Capture struct {
	Timestamp  string `json:"timestamp"`
	Original   string `json:"original"`
	StatusCode string `json:"statuscode"`
	Digest     string `json:"digest"` // SHA1 of the content: the key to distinct versions
	MimeType   string `json:"mimetype"`
	Length     string `json:"length"`
}

// RawURL returns the "identity" download URL that yields the original archived
// bytes without Wayback's HTML rewriting or toolbar injection.
func (c Capture) RawURL() string {
	return fmt.Sprintf("https://web.archive.org/web/%sid_/%s", c.Timestamp, c.Original)
}

// Captures lists every archived capture of a single URL, newest filtering left
// to the caller. statusFilter is a comma list (e.g. "200" or "200,301"); "any"
// or "" disables the status filter. Results are collapsed by digest server-side
// so near-duplicates are reduced before transfer.
func (c *CDXClient) Captures(ctx context.Context, rawURL, statusFilter, from, to, ua string) ([]Capture, error) {
	v := url.Values{}
	v.Set("url", rawURL)
	v.Set("output", "json")
	v.Set("fl", "timestamp,original,statuscode,digest,mimetype,length")
	v.Set("collapse", "digest")
	if from != "" {
		v.Set("from", from)
	}
	if to != "" {
		v.Set("to", to)
	}
	if statusFilter != "" && !strings.EqualFold(statusFilter, "any") {
		codes := splitSimple(statusFilter)
		if len(codes) > 0 {
			v.Set("filter", "statuscode:("+strings.Join(codes, "|")+")")
		}
	}

	reqURL := cdxEndpoint + "?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if ua == "" {
		ua = "difo/1.0 (+information-disclosure-hunter)"
	}
	req.Header.Set("User-Agent", ua)

	resp, err := doWithRetry(c.HTTP, req, c.Retry)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CDX HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}

	// CDX json output is an array of rows; the first row is the header.
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("decoding CDX json: %w", err)
	}
	if len(rows) <= 1 {
		return nil, nil
	}

	idx := map[string]int{}
	for i, h := range rows[0] {
		idx[h] = i
	}
	at := func(r []string, name string) string {
		if i, ok := idx[name]; ok && i < len(r) {
			return r[i]
		}
		return ""
	}

	caps := make([]Capture, 0, len(rows)-1)
	for _, r := range rows[1:] {
		caps = append(caps, Capture{
			Timestamp:  at(r, "timestamp"),
			Original:   at(r, "original"),
			StatusCode: at(r, "statuscode"),
			Digest:     at(r, "digest"),
			MimeType:   at(r, "mimetype"),
			Length:     at(r, "length"),
		})
	}
	return caps, nil
}

// UniqueByDigest returns one capture per distinct content digest (so the same
// file archived unchanged across years collapses to a single entry, while a
// genuinely changed file keeps every version). It keeps the first capture seen
// for each digest, so the caller controls which one wins by ordering the input
// (e.g. newest-first to keep the most recent).
func UniqueByDigest(caps []Capture) []Capture {
	seen := map[string]struct{}{}
	var out []Capture
	for _, c := range caps {
		key := c.Digest
		if key == "" {
			key = c.Timestamp + c.Original // fall back when digest is absent
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

// Latest returns the capture with the most recent timestamp.
func Latest(caps []Capture) (Capture, bool) {
	if len(caps) == 0 {
		return Capture{}, false
	}
	best := caps[0]
	for _, c := range caps[1:] {
		if c.Timestamp > best.Timestamp {
			best = c
		}
	}
	return best, true
}

// Downloader fetches archived file bytes to disk.
type Downloader struct {
	HTTP      *http.Client
	UserAgent string
	MaxSize   int64 // max bytes per file; <=0 means effectively unlimited
	Retry     retryConfig
}

// NewDownloader builds a downloader. maxSize is in bytes.
func NewDownloader(timeout time.Duration, maxSize int64, retries int, base, delay time.Duration) *Downloader {
	if maxSize <= 0 {
		maxSize = 1 << 62
	}
	return &Downloader{
		HTTP:      &http.Client{Timeout: timeout},
		UserAgent: "difo/1.0 (+information-disclosure-hunter)",
		MaxSize:   maxSize,
		Retry:     defaultRetry(retries, base, delay),
	}
}

// Fetch downloads one capture's original bytes into outDir and returns the file
// path written, the number of bytes saved, and the SHA1 of the downloaded
// (decoded) content. The content hash lets callers dedupe versions that share
// identical bytes even when the Wayback CDX digest differs (e.g. a capture that
// was stored gzip-compressed vs plain).
func (d *Downloader) Fetch(ctx context.Context, cap Capture, outDir string) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cap.RawURL(), nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", d.UserAgent)

	resp, err := doWithRetry(d.HTTP, req, d.Retry)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("download HTTP %d", resp.StatusCode)
	}

	dest := destPath(outDir, cap)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", 0, "", err
	}
	f, err := os.Create(dest)
	if err != nil {
		return "", 0, "", err
	}
	defer f.Close()

	h := sha1.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, d.MaxSize))
	if err != nil {
		return dest, n, "", err
	}
	return dest, n, hex.EncodeToString(h.Sum(nil)), nil
}

var illegalChars = regexp.MustCompile(`[<>:"\\|?*\x00-\x1f]`)

// sanitizeComponent makes a single path segment safe on Windows and *nix.
func sanitizeComponent(s string) string {
	s = illegalChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, " .")
	if s == "" {
		return "_"
	}
	if len(s) > 150 {
		s = s[:150]
	}
	return s
}

// destPath builds a collision-free local path:
//
//	<outDir>/<host>/<url-path-dirs>/<timestamp>_<digest8>_<filename>
//
// The timestamp+digest prefix keeps every distinct version of the same URL as
// its own file. The whole result is kept under outDir even for hostile paths.
func destPath(outDir string, cap Capture) string {
	host := "unknown-host"
	p := cap.Original
	if u, err := url.Parse(cap.Original); err == nil {
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

	parts := []string{outDir, sanitizeComponent(host)}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if seg != "" {
			parts = append(parts, sanitizeComponent(seg))
		}
	}
	dir := filepath.Join(parts...)

	short := cap.Digest
	if len(short) > 8 {
		short = short[:8]
	}
	if short == "" {
		short = "nodigest"
	}
	fname := sanitizeComponent(cap.Timestamp + "_" + short + "_" + name)

	full := filepath.Join(dir, fname)
	// Defense in depth: ensure the cleaned path never escapes outDir.
	if clean := filepath.Clean(full); !strings.HasPrefix(clean, filepath.Clean(outDir)) {
		return filepath.Join(outDir, fname)
	}
	return full
}

// splitSimple splits a comma list and trims each item.
func splitSimple(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
