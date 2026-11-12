// Package webhook posts alerts as JSON to an HTTP endpoint.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wolverine/internal/event"
)

const (
	defaultTimeout    = 10 * time.Second
	defaultRetryDelay = time.Second
	maxErrorBody      = 512
)

// Webhook POSTs the alert, encoded as JSON (same format as the alerts written
// on stdout), to URL. Network errors, 429 and 5xx responses are retried up to
// Retries times with an exponential backoff; other non-2xx responses fail
// immediately.
//
// When Body is set, it renders the request body instead (e.g. a Slack
// message).
//
// The URL may embed a secret (Slack, Teams...): only its scheme and host
// appear in errors.
type Webhook struct {
	ID        string
	URL       string
	Headers   map[string]string
	Timeout   time.Duration
	Retries   int
	MaxEvents int
	Body      *Body

	// Client defaults to http.DefaultClient; RetryDelay to one second.
	Client     *http.Client
	RetryDelay time.Duration
}

func (w *Webhook) Name() string { return w.ID }

func (w *Webhook) Execute(ctx context.Context, alert *event.Alert) error {
	var body []byte
	var err error
	if w.Body != nil {
		body, err = w.Body.Render(alert, w.MaxEvents)
	} else {
		body, err = json.Marshal(w.payload(alert))
	}
	if err != nil {
		return err
	}

	delay := w.RetryDelay
	if delay <= 0 {
		delay = defaultRetryDelay
	}
	var lastErr error
	for attempt := 0; attempt <= w.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w (last error: %v)", ctx.Err(), lastErr)
			case <-time.After(delay):
			}
			delay *= 2
		}
		retry, err := w.post(ctx, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return lastErr
}

// post sends one request and reports whether a failure is worth retrying.
func (w *Webhook) post(ctx context.Context, body []byte) (retry bool, err error) {
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "wolverine")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // its message contains the full URL
		}
		return true, fmt.Errorf("POST %s: %w", w.redactedURL(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		return false, nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	retry = resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return retry, fmt.Errorf("POST %s: %s: %s", w.redactedURL(), resp.Status, strings.TrimSpace(string(msg)))
}

// redactedURL returns the URL without its path, query and credentials,
// which may hold a secret.
func (w *Webhook) redactedURL() string {
	u, err := url.Parse(w.URL)
	if err != nil {
		return "webhook"
	}
	return u.Scheme + "://" + u.Host + "/..."
}

// payload returns the alert to send, with at most MaxEvents events. The
// original alert is shared with other actions and is not modified.
func (w *Webhook) payload(a *event.Alert) *event.Alert {
	if w.MaxEvents <= 0 || len(a.Events) <= w.MaxEvents {
		return a
	}
	p := *a
	p.Events = a.Events[:w.MaxEvents]
	p.Metadata = maps.Clone(a.Metadata)
	if p.Metadata == nil {
		p.Metadata = map[string]any{}
	}
	p.Metadata["events_total"] = len(a.Events)
	return &p
}
