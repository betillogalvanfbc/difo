package difo

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// retryConfig controls how transient HTTP failures (429 / 5xx) are retried.
type retryConfig struct {
	max    int           // max retries after the first attempt (0 = no retry)
	base   time.Duration // base backoff; grows exponentially per attempt
	delay  time.Duration // fixed polite delay applied before every request
	notify func(status int, wait time.Duration, attempt, max int)
}

func defaultRetry(max int, base, delay time.Duration) retryConfig {
	if base <= 0 {
		base = 2 * time.Second
	}
	return retryConfig{max: max, base: base, delay: delay}
}

// retryable reports whether a status code is worth retrying.
func retryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	}
	return false
}

// doWithRetry performs req, retrying on network errors and 429/5xx responses
// with exponential backoff plus jitter. It honors a Retry-After header when the
// server sends one. All DIFO requests are GET with no body, so the same request
// can be safely replayed. The final response (even if still an error status) is
// returned so callers can report it.
func doWithRetry(client *http.Client, req *http.Request, rc retryConfig) (*http.Response, error) {
	ctx := req.Context()
	var lastResp *http.Response
	var lastErr error

	for attempt := 0; ; attempt++ {
		if rc.delay > 0 {
			if !sleepCtx(ctx, rc.delay) {
				return nil, ctx.Err()
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			lastResp = nil
		} else if retryable(resp.StatusCode) {
			lastResp = resp
			lastErr = nil
		} else {
			return resp, nil // success or a non-retryable status
		}

		if attempt >= rc.max {
			if lastResp != nil {
				return lastResp, nil
			}
			return nil, lastErr
		}

		// Compute the wait: prefer Retry-After, else exponential backoff + jitter.
		wait := backoff(rc.base, attempt)
		status := 0
		if lastResp != nil {
			status = lastResp.StatusCode
			if ra := parseRetryAfter(lastResp.Header.Get("Retry-After")); ra > 0 {
				wait = ra
			}
			// Drain and close so the connection can be reused.
			io.Copy(io.Discard, io.LimitReader(lastResp.Body, 4096))
			lastResp.Body.Close()
		}
		if rc.notify != nil {
			rc.notify(status, wait, attempt, rc.max)
		}
		if !sleepCtx(ctx, wait) {
			return nil, ctx.Err()
		}
	}
}

// backoff returns base * 2^attempt plus up to 25% jitter, capped at 60s.
func backoff(base time.Duration, attempt int) time.Duration {
	d := base << attempt
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(d/4) + 1))
	return d + jitter
}

// parseRetryAfter understands both the delay-seconds and HTTP-date forms.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// sleepCtx waits for d or until ctx is cancelled; it returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
