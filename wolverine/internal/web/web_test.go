package web

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"wolverine/internal/action"
	"wolverine/internal/config"
	"wolverine/internal/engine"
	"wolverine/internal/event"
	"wolverine/internal/stats"
)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

type fakeBackend struct {
	st      *stats.Store
	alerts  []engine.AlertRecord
	pending []action.Pending
	mu      sync.Mutex
	subs    []chan engine.Notice
}

func (f *fakeBackend) Info() engine.Info {
	return engine.Info{Sources: []engine.SourceInfo{{ID: "ssh", Type: "logfile"}}, Rules: []engine.RuleInfo{{ID: "brute"}}}
}
func (f *fakeBackend) Stats() *stats.Store                { return f.st }
func (f *fakeBackend) AlertRecords() []engine.AlertRecord { return f.alerts }
func (f *fakeBackend) PendingUndos() []action.Pending     { return f.pending }
func (f *fakeBackend) Watch() (<-chan engine.Notice, func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan engine.Notice, 10)
	f.subs = append(f.subs, ch)
	return ch, func() {}
}

func (f *fakeBackend) publish(a engine.Notice) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.subs {
		ch <- a
	}
}

func (f *fakeBackend) watchers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

// newTest returns a server whose clock is 10:30, with counters at 10:00:10
// (3 lines), 10:20 (1 line, a match and an alert) and alerts at 10:00 and
// 10:20.
func newTest(t *testing.T, token string) (*fakeBackend, *httptest.Server) {
	t.Helper()
	clock := t0.Add(10 * time.Second)
	st := stats.New([]string{"ssh"}, []string{"brute"})
	st.Now = func() time.Time { return clock }
	st.Line("ssh", 10, true, false)
	st.Line("ssh", 10, true, false)
	st.Line("ssh", 10, false, true)
	clock = t0.Add(20 * time.Minute)
	st.Line("ssh", 10, true, false)
	st.Matched([]string{"brute"}, []string{"brute"})
	b := &fakeBackend{st: st, alerts: []engine.AlertRecord{
		{Alert: &event.Alert{ID: "a1", RuleID: "brute", Severity: "high", Timestamp: t0, Events: []*event.Event{{Raw: "one"}, {Raw: "two"}}},
			Raised: t0,
			Actions: []event.ActionRun{
				{Time: t0, Action: "block-ip", Status: event.ActionOK},
				{Time: t0, Action: "unblock-ip", UndoOf: "block-ip", Status: event.ActionPlanned, Due: t0.Add(time.Hour)},
			}},
		{Alert: &event.Alert{ID: "a2", RuleID: "other", Severity: "low", Timestamp: t0.Add(20 * time.Minute), Events: []*event.Event{{Raw: "three"}}},
			Raised: t0.Add(20 * time.Minute)},
	}}
	t.Setenv("TEST_TOKEN", token)
	cfg := config.HTTP{}
	if token != "" {
		cfg.TokenEnv = "TEST_TOKEN"
	}
	s, err := New(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return t0.Add(30 * time.Minute) }
	s.heartbeat = 50 * time.Millisecond
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return b, srv
}

func get(t *testing.T, url, token string, v any) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("%s: %v", url, err)
		}
	}
	return resp
}

func TestParseTime(t *testing.T) {
	now := t0
	for in, want := range map[string]time.Time{
		"now":                  now,
		"-15m":                 now.Add(-15 * time.Minute),
		"now-1h":               now.Add(-time.Hour),
		"2026-11-13T09:00:00Z": t0.Add(-time.Hour),
		"1794567600":           time.Unix(1794567600, 0),
	} {
		got, err := parseTime(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %s %v, want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"yesterday", "15m", "now+1h", "-abc"} {
		if _, err := parseTime(in, now); err == nil {
			t.Errorf("%s: no error", in)
		}
	}
}

func TestAuth(t *testing.T) {
	_, srv := newTest(t, "s3cret")
	for token, want := range map[string]int{"": 401, "wrong": 401, "s3cret": 200} {
		if resp := get(t, srv.URL+"/api/v1/info", token, nil); resp.StatusCode != want {
			t.Errorf("token %q: %d, want %d", token, resp.StatusCode, want)
		}
	}
	if resp := get(t, srv.URL+"/api/v1/alerts/watch", "", nil); resp.StatusCode != 401 {
		t.Errorf("watch without token: %d", resp.StatusCode)
	}
	// The dashboard itself holds no data: no token needed.
	resp := get(t, srv.URL+"/", "", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("dashboard: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("security headers: %v", resp.Header)
	}
	for _, f := range []string{"/app.js", "/style.css", "/healthz"} {
		if resp := get(t, srv.URL+f, "", nil); resp.StatusCode != 200 {
			t.Errorf("%s: %d", f, resp.StatusCode)
		}
	}
	var e map[string]string
	if resp := get(t, srv.URL+"/api/v1/nope", "s3cret", &e); resp.StatusCode != 404 || e["error"] == "" {
		t.Errorf("unknown endpoint: %d %v", resp.StatusCode, e)
	}

	t.Setenv("UNSET_TOKEN", "")
	if _, err := New(nil, config.HTTP{TokenEnv: "UNSET_TOKEN"}); err == nil || !strings.Contains(err.Error(), "UNSET_TOKEN") {
		t.Errorf("missing token variable: %v", err)
	}
}

func TestStats(t *testing.T) {
	_, srv := newTest(t, "")
	var r statsResponse
	get(t, srv.URL+"/api/v1/stats", "", &r)
	if !r.SinceStart || r.Totals.Lines != 4 || r.Totals.Bytes != 40 || r.Sources["ssh"].Bytes != 40 || r.Totals.Unparsed != 1 || r.Totals.Alerts != 1 || r.Sources["ssh"].Events != 3 || r.Rules["brute"].Matches != 1 {
		t.Errorf("since start: %+v", r)
	}
	// The last 15 minutes (from 10:15): the 10:20 bucket only.
	r = statsResponse{}
	get(t, srv.URL+"/api/v1/stats?from=-15m", "", &r)
	if r.SinceStart || r.Totals.Lines != 1 || r.Totals.Alerts != 1 || !r.From.Equal(t0.Add(15*time.Minute)) || !r.To.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("last 15m: %+v", r)
	}
	r = statsResponse{}
	get(t, srv.URL+"/api/v1/stats?from=2026-11-13T10:00:00Z&to=2026-11-13T10:01:00Z", "", &r)
	if r.Totals.Lines != 3 || !r.AvailableSince.Equal(t0) {
		t.Errorf("10:00-10:01: %+v", r)
	}
	var e map[string]string
	for _, q := range []string{"from=bad", "to=bad", "from=-1m&to=-2m"} {
		if resp := get(t, srv.URL+"/api/v1/stats?"+q, "", &e); resp.StatusCode != 400 || e["error"] == "" {
			t.Errorf("%s: %d %v", q, resp.StatusCode, e)
		}
	}
}

func TestSeries(t *testing.T) {
	_, srv := newTest(t, "")
	var r seriesResponse
	// Default: the last hour (9:30-10:30), by 1m (60 minutes / 120).
	get(t, srv.URL+"/api/v1/stats/series", "", &r)
	if r.Step != "1m0s" || len(r.Buckets) != 60 || !r.From.Equal(t0.Add(-30*time.Minute)) {
		t.Fatalf("default: step %s, %d buckets from %s", r.Step, len(r.Buckets), r.From)
	}
	if r.Buckets[30].Totals.Lines != 3 || r.Buckets[50].Rules["brute"].Alerts != 1 {
		t.Errorf("buckets 10:00 / 10:20: %+v / %+v", r.Buckets[30].Totals, r.Buckets[50].Totals)
	}
	r = seriesResponse{}
	get(t, srv.URL+"/api/v1/stats/series?from=-30m&step=10m", "", &r)
	if r.StepSeconds != 600 || len(r.Buckets) != 3 || r.Buckets[0].Totals.Lines != 3 || r.Buckets[2].Totals.Lines != 1 {
		t.Errorf("by 10m: %+v", r)
	}
	var e map[string]string
	// The step is a multiple of a minute; at most maxBuckets buckets.
	for _, q := range []string{"step=30s", "step=90s", "step=x", "from=-72h&step=1m"} {
		if resp := get(t, srv.URL+"/api/v1/stats/series?"+q, "", &e); resp.StatusCode != 400 {
			t.Errorf("%s: %d %v", q, resp.StatusCode, e)
		}
	}
}

func TestAlerts(t *testing.T) {
	_, srv := newTest(t, "")
	ids := func(q string) string {
		t.Helper()
		var r alertsResponse
		if resp := get(t, srv.URL+"/api/v1/alerts?"+q, "", &r); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", q, resp.StatusCode)
		}
		var s []string
		for _, a := range r.Alerts {
			s = append(s, a.ID)
		}
		return strings.Join(s, ",")
	}
	for q, want := range map[string]string{
		"":                        "a2,a1", // newest first
		"from=-15m":               "a2",
		"rule=brute":              "a1",
		"rule=brute,other":        "a2,a1",
		"severity=low":            "a2",
		"limit=1":                 "a2",
		"to=2026-11-13T10:20:00Z": "a1",
	} {
		if got := ids(q); got != want {
			t.Errorf("%q: %s, want %s", q, got, want)
		}
	}
	var r alertsResponse
	get(t, srv.URL+"/api/v1/alerts?limit=1", "", &r)
	if r.Total != 2 {
		t.Errorf("total %d, want 2", r.Total)
	}
	for mode, want := range map[string]string{"": "two", "last": "two", "all": "one,two", "none": ""} {
		var r alertsResponse
		get(t, srv.URL+"/api/v1/alerts?rule=brute&events="+mode, "", &r)
		var raws []string
		for _, ev := range r.Alerts[0].Events {
			raws = append(raws, ev.Raw)
		}
		if got := strings.Join(raws, ","); got != want {
			t.Errorf("events=%s: %q, want %q", mode, got, want)
		}
	}
	for _, q := range []string{"limit=0", "limit=x", "events=some"} {
		if resp := get(t, srv.URL+"/api/v1/alerts?"+q, "", nil); resp.StatusCode != 400 {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}

	// The action log, always an array.
	var raw struct{ Alerts []map[string]any }
	get(t, srv.URL+"/api/v1/alerts", "", &raw)
	if got := raw.Alerts; len(got) != 2 || got[0]["Actions"] == nil || len(got[0]["Actions"].([]any)) != 0 {
		t.Fatalf("a2 actions: %v", got)
	}
	if acts := raw.Alerts[1]["Actions"].([]any); len(acts) != 2 ||
		acts[1].(map[string]any)["UndoOf"] != "block-ip" || acts[1].(map[string]any)["Due"] != "2026-11-13T11:00:00Z" {
		t.Errorf("a1 actions: %v", acts)
	}
	if _, ok := raw.Alerts[1]["Actions"].([]any)[0].(map[string]any)["Due"]; ok {
		t.Error("Due given for an action that is not planned")
	}

	// One alert, with all its events by default.
	var one alertView
	if resp := get(t, srv.URL+"/api/v1/alerts/a1", "", &one); resp.StatusCode != 200 || one.ID != "a1" || len(one.Events) != 2 || len(one.Actions) != 2 {
		t.Errorf("alert a1: %d %+v", resp.StatusCode, one)
	}
	one = alertView{}
	if resp := get(t, srv.URL+"/api/v1/alerts/a1?events=none", "", &one); resp.StatusCode != 200 || len(one.Events) != 0 {
		t.Errorf("alert a1, events=none: %d %+v", resp.StatusCode, one)
	}
	if resp := get(t, srv.URL+"/api/v1/alerts/nope", "", nil); resp.StatusCode != 404 {
		t.Errorf("unknown alert: %d", resp.StatusCode)
	}
}

// The range is on when the alerts were raised, not on the time of their
// events; the alerts with an undo still pending can be asked for, whatever
// their age, even when no longer kept.
func TestAlertsRaisedAndPendingUndo(t *testing.T) {
	b, srv := newTest(t, "")
	old := &event.Alert{ID: "old", RuleID: "brute", Timestamp: t0.Add(-3 * time.Hour)} // a log read late
	gone := &event.Alert{ID: "gone", RuleID: "brute", Timestamp: t0.Add(-48 * time.Hour)}
	b.alerts = append(b.alerts, engine.AlertRecord{Alert: old, Raised: t0.Add(25 * time.Minute)})
	b.pending = []action.Pending{
		{Action: "block-ip", Actions: []string{"unblock-ip"}, Due: t0.Add(2 * time.Hour), Alert: b.alerts[0].Alert},
		{Action: "block-ip", Actions: []string{"unblock-ip"}, Due: t0.Add(time.Hour), Attempts: 1, Alert: gone},
	}
	ids := func(q string) string {
		t.Helper()
		var r alertsResponse
		if resp := get(t, srv.URL+"/api/v1/alerts?"+q, "", &r); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", q, resp.StatusCode)
		}
		var s []string
		for _, a := range r.Alerts {
			id := a.ID
			if a.Undo != nil {
				id += "(undo " + a.Undo.Due.Format("15:04") + ")"
			}
			s = append(s, id)
		}
		return strings.Join(s, ",")
	}
	for q, want := range map[string]string{
		"from=-10m":                              "old,a2", // raised at 10:25: newest first
		"":                                       "old,a2,a1(undo 12:00),gone(undo 11:00)",
		"undo=pending":                           "a1(undo 12:00),gone(undo 11:00)",
		"undo=pending&from=2026-11-13T09:00:00Z": "a1(undo 12:00)",
	} {
		if got := ids(q); got != want {
			t.Errorf("%q: %s, want %s", q, got, want)
		}
	}
	var one alertView
	if resp := get(t, srv.URL+"/api/v1/alerts/gone", "", &one); resp.StatusCode != 200 || one.Undo == nil || one.Undo.Attempts != 1 || !one.Raised.IsZero() {
		t.Errorf("alert gone: %d %+v", resp.StatusCode, one)
	}
	if resp := get(t, srv.URL+"/api/v1/alerts?undo=done", "", nil); resp.StatusCode != 400 {
		t.Errorf("undo=done: %d", resp.StatusCode)
	}

	// Sorted by the time of their first event: a2 (10:20), a1 (10:00),
	// old (07:00, from Start), gone (two days ago, from Timestamp).
	old.Start, old.End = t0.Add(-3*time.Hour), t0.Add(-2*time.Hour)
	if got, want := ids("sort=event"), "a2,a1(undo 12:00),old,gone(undo 11:00)"; got != want {
		t.Errorf("sort=event: %s, want %s", got, want)
	}
	if got, want := ids("sort=event&limit=1&from=-10m"), "a2"; got != want {
		t.Errorf("sort=event, limit=1: %s, want %s", got, want)
	}
	if got, want := ids("sort=raised"), "old,a2,a1(undo 12:00),gone(undo 11:00)"; got != want {
		t.Errorf("sort=raised: %s, want %s", got, want)
	}
	if resp := get(t, srv.URL+"/api/v1/alerts?sort=time", "", nil); resp.StatusCode != 400 {
		t.Errorf("sort=time: %d", resp.StatusCode)
	}
}

func TestWatch(t *testing.T) {
	b, srv := newTest(t, "")
	resp, err := http.Get(srv.URL + "/api/v1/alerts/watch?rule=brute&events=none")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	r := bufio.NewReader(resp.Body)
	readBlock := func() string {
		t.Helper()
		var lines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				if err == io.EOF && len(lines) == 0 {
					return "EOF"
				}
				t.Fatal(err)
			}
			if line == "\n" {
				return strings.Join(lines, "")
			}
			lines = append(lines, line)
		}
	}
	if got := readBlock(); !strings.Contains(got, ": connected") {
		t.Fatalf("first block: %q", got)
	}
	for b.watchers() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	// Filtered out (rule), then sent without its events.
	x1 := &event.Alert{ID: "x1", RuleID: "other"}
	x2 := &event.Alert{ID: "x2", RuleID: "brute", Events: []*event.Event{{Raw: "secret line"}}}
	b.publish(engine.Notice{Alert: x1})
	b.publish(engine.Notice{Alert: x2, Raised: t0})
	b.publish(engine.Notice{Alert: x1, Action: &event.ActionRun{Action: "mail", Status: event.ActionOK}})
	b.publish(engine.Notice{Alert: x2, Action: &event.ActionRun{Action: "block-ip", Status: event.ActionFailed, Error: "boom"}})
	next := func() string {
		got := readBlock()
		for strings.HasPrefix(got, ": heartbeat") {
			got = readBlock()
		}
		return got
	}
	if got := next(); !strings.HasPrefix(got, "event: alert\nid: x2\ndata: {") || strings.Contains(got, "secret line") ||
		!strings.Contains(got, `"Raised":"2026-11-13T10:00:00Z","Actions":[]`) {
		t.Errorf("alert block: %q", got)
	}
	if got := next(); got != `event: action
data: {"AlertID":"x2","RuleID":"brute","Time":"0001-01-01T00:00:00Z","Action":"block-ip","Status":"failed","Error":"boom"}
` {
		t.Errorf("action block: %q", got)
	}
	// Heartbeats keep an idle stream alive.
	if got := readBlock(); got != ": heartbeat\n" {
		t.Errorf("heartbeat: %q", got)
	}
	// The stream ends when the engine stops.
	b.mu.Lock()
	close(b.subs[0])
	b.mu.Unlock()
	for got := readBlock(); got != "EOF"; got = readBlock() {
		if !strings.HasPrefix(got, ": heartbeat") {
			t.Fatalf("after close: %q", got)
		}
	}
}
