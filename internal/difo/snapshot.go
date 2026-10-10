package difo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const availabilityEndpoint = "https://archive.org/wayback/available"

// Snapshot is the closest archived capture of a URL.
type Snapshot struct {
	Available bool
	URL       string // direct web.archive.org snapshot URL
	Timestamp string // capture timestamp (YYYYMMDDhhmmss)
	Status    string // HTTP status recorded for the capture
}

// availabilityResponse mirrors the archive.org availability API JSON.
type availabilityResponse struct {
	ArchivedSnapshots struct {
		Closest struct {
			Available bool   `json:"available"`
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
			Status    string `json:"status"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
}

// SnapshotResolver looks up the closest working snapshot for a URL. This solves
// the "404 on the live file" problem: even when the original file is gone, the
// Wayback Machine usually still has a capture of it.
type SnapshotResolver struct {
	HTTP      *http.Client
	UserAgent string
	Retry     retryConfig
}

// NewSnapshotResolver returns a resolver with the given timeout and retry policy.
func NewSnapshotResolver(timeout time.Duration, retries int, base, delay time.Duration) *SnapshotResolver {
	return &SnapshotResolver{
		HTTP:      &http.Client{Timeout: timeout},
		UserAgent: "difo/1.0 (+information-disclosure-hunter)",
		Retry:     defaultRetry(retries, base, delay),
	}
}

// Closest returns the closest archived snapshot for rawURL.
func (r *SnapshotResolver) Closest(ctx context.Context, rawURL string) (Snapshot, error) {
	reqURL := availabilityEndpoint + "?url=" + url.QueryEscape(rawURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Snapshot{}, err
	}
	req.Header.Set("User-Agent", r.UserAgent)

	resp, err := doWithRetry(r.HTTP, req, r.Retry)
	if err != nil {
		return Snapshot{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Snapshot{}, fmt.Errorf("availability API HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Snapshot{}, err
	}

	var ar availabilityResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return Snapshot{}, fmt.Errorf("decoding availability response: %w", err)
	}

	c := ar.ArchivedSnapshots.Closest
	return Snapshot{
		Available: c.Available,
		URL:       c.URL,
		Timestamp: c.Timestamp,
		Status:    c.Status,
	}, nil
}
