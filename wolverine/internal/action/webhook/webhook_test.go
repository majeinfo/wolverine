package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wolverine/internal/action/allowlist"
	"wolverine/internal/event"
)

func testAlert(ip string, nEvents int) *event.Alert {
	a := &event.Alert{
		ID:       "a1",
		RuleID:   "ssh-failed-logins-per-ip",
		Severity: "high",
		Message:  "Repeated failed SSH logins",
		Metadata: map[string]any{"value": ip},
	}
	for range nEvents {
		a.Events = append(a.Events, &event.Event{SourceIP: ip, Raw: "Failed password"})
	}
	return a
}

// server answers with the given status codes in turn (the last one repeats)
// and records the requests.
func server(t *testing.T, codes ...int) (*httptest.Server, *atomic.Int32, chan *http.Request, chan []byte) {
	var calls atomic.Int32
	reqs := make(chan *http.Request, 10)
	bodies := make(chan []byte, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		var body json.RawMessage
		json.NewDecoder(r.Body).Decode(&body)
		reqs <- r
		bodies <- body
		code := codes[min(n, len(codes))-1]
		rw.WriteHeader(code)
		rw.Write([]byte("response body"))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, reqs, bodies
}

func TestExecute(t *testing.T) {
	srv, calls, reqs, bodies := server(t, 204)
	w := &Webhook{ID: "hook", URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer s3cret"}, MaxEvents: 2}

	orig := testAlert("203.0.113.7", 3)
	if err := w.Execute(context.Background(), orig); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("got %d calls, want 1", calls.Load())
	}
	r := <-reqs
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("Authorization") != "Bearer s3cret" || r.Header.Get("User-Agent") != "wolverine" {
		t.Errorf("unexpected request: %s %v", r.Method, r.Header)
	}

	var got event.Alert
	if err := json.Unmarshal(<-bodies, &got); err != nil {
		t.Fatal(err)
	}
	if got.RuleID != "ssh-failed-logins-per-ip" || len(got.Events) != 2 || got.Metadata["events_total"] != 3.0 {
		t.Errorf("unexpected payload: %+v", got)
	}
	if len(orig.Events) != 3 || orig.Metadata["events_total"] != nil {
		t.Error("the original alert was modified")
	}
}

func TestRetry(t *testing.T) {
	srv, calls, _, _ := server(t, 503, 429, 200)
	w := &Webhook{URL: srv.URL, Retries: 2, RetryDelay: time.Millisecond}
	if err := w.Execute(context.Background(), testAlert("203.0.113.7", 1)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Errorf("got %d calls, want 3", calls.Load())
	}
}

func TestRetriesExhausted(t *testing.T) {
	srv, calls, _, _ := server(t, 500)
	w := &Webhook{URL: srv.URL, Retries: 1, RetryDelay: time.Millisecond}
	err := w.Execute(context.Background(), testAlert("203.0.113.7", 1))
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "response body") {
		t.Fatalf("got %v, want a 500 error with the response body", err)
	}
	if calls.Load() != 2 {
		t.Errorf("got %d calls, want 2", calls.Load())
	}
}

func TestNoRetryOnClientError(t *testing.T) {
	srv, calls, _, _ := server(t, 401)
	w := &Webhook{URL: srv.URL, Retries: 3, RetryDelay: time.Millisecond}
	if err := w.Execute(context.Background(), testAlert("203.0.113.7", 1)); err == nil {
		t.Fatal("expected an error")
	}
	if calls.Load() != 1 {
		t.Errorf("got %d calls, want 1 (4xx is not retried)", calls.Load())
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first: unblocks the handler so Close returns
	w := &Webhook{URL: srv.URL, Timeout: 50 * time.Millisecond}
	start := time.Now()
	if err := w.Execute(context.Background(), testAlert("203.0.113.7", 1)); err == nil {
		t.Fatal("expected a timeout error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("timeout not honoured: %s", d)
	}
}

func TestAllowlist(t *testing.T) {
	srv, calls, _, _ := server(t, 200)
	w := &Webhook{URL: srv.URL, Allowlist: allowlist.List{netip.MustParsePrefix("10.0.0.0/8")}}
	if err := w.Execute(context.Background(), testAlert("10.1.2.3", 1)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("allowlisted IP: the webhook must not be called")
	}
	if err := w.Execute(context.Background(), testAlert("203.0.113.7", 1)); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("other IPs must be sent")
	}
}
