package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"wolverine/internal/action"
	"wolverine/internal/engine"
	"wolverine/internal/event"
	"wolverine/internal/stats"
)

const (
	// maxBuckets is the number of buckets a series may have.
	maxBuckets = 2000
	// autoBuckets is about the number of buckets of a series when no step
	// is given.
	autoBuckets = 120
	// defaultAlerts and maxAlerts are the default and maximum limit of
	// /alerts.
	defaultAlerts = 100
	maxAlerts     = 10000
)

// apiError is an error of the client: bad parameter...
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &apiError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

// parseTime parses a time parameter: RFC 3339 ("2026-11-13T10:00:00Z"), Unix
// seconds, "now", or a duration relative to now ("-15m", "now-1h").
func parseTime(s string, now time.Time) (time.Time, error) {
	if s == "now" {
		return now, nil
	}
	if rel, ok := strings.CutPrefix(s, "now"); ok || strings.HasPrefix(s, "-") {
		if ok && rel == "" {
			return now, nil
		}
		d, err := time.ParseDuration(rel)
		if err != nil || d > 0 {
			return time.Time{}, fmt.Errorf("%q: a relative time is a negative duration, e.g. -15m or now-1h", s)
		}
		return now.Add(d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Time{}, fmt.Errorf("%q: not a time (RFC 3339, Unix seconds, now, or e.g. -15m)", s)
}

// interval reads the from and to parameters. A missing to is now; a missing
// from is def (relative to now), or the zero time if def is 0.
func (s *Server) interval(q url.Values, def time.Duration) (from, to time.Time, err error) {
	now := s.now()
	to = now
	if v := q.Get("to"); v != "" {
		if to, err = parseTime(v, now); err != nil {
			return from, to, badRequest("to: %v", err)
		}
	}
	if v := q.Get("from"); v != "" {
		if from, err = parseTime(v, now); err != nil {
			return from, to, badRequest("from: %v", err)
		}
	} else if def != 0 {
		from = now.Add(-def)
	}
	if !from.IsZero() && !from.Before(to) {
		return from, to, badRequest("from must be before to")
	}
	return from, to, nil
}

func (s *Server) info(*http.Request) (any, error) {
	return s.backend.Info(), nil
}

// statsResponse is the result of /stats.
type statsResponse struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Since start: the counters since wolverine started, else those of
	// [from, to), at a minute's resolution.
	SinceStart bool `json:"since_start"`
	// AvailableSince is the start of the oldest bucket kept: the counters
	// of an interval that starts before are partial.
	AvailableSince time.Time `json:"available_since"`
	*stats.Counts
}

// stats gives the totals since the start, or those of [from, to).
func (s *Server) stats(r *http.Request) (any, error) {
	q := r.URL.Query()
	st := s.backend.Stats()
	resp := statsResponse{AvailableSince: available(st)}
	if q.Get("from") == "" && q.Get("to") == "" {
		resp.From, resp.To, resp.SinceStart = st.Started(), s.now(), true
		resp.Counts = st.Total()
		return resp, nil
	}
	from, to, err := s.interval(q, 0)
	if err != nil {
		return nil, err
	}
	if from.IsZero() {
		from = st.Started()
	}
	resp.From, resp.To = from.Truncate(stats.Resolution), to
	resp.Counts = st.Interval(from, to)
	return resp, nil
}

func available(st *stats.Store) time.Time {
	if t := st.Oldest(); !t.IsZero() {
		return t
	}
	return st.Started().Truncate(stats.Resolution)
}

// seriesResponse is the result of /stats/series.
type seriesResponse struct {
	From           time.Time      `json:"from"`
	To             time.Time      `json:"to"`
	Step           string         `json:"step"`
	StepSeconds    int64          `json:"step_seconds"`
	AvailableSince time.Time      `json:"available_since"`
	Buckets        []stats.Bucket `json:"buckets"`
}

// series gives the counters of [from, to) by step. Default: the last hour,
// with a step that gives about autoBuckets buckets.
func (s *Server) series(r *http.Request) (any, error) {
	q := r.URL.Query()
	from, to, err := s.interval(q, time.Hour)
	if err != nil {
		return nil, err
	}
	st := s.backend.Stats()
	if from.IsZero() {
		from = st.Started()
	}
	var step time.Duration
	if v := q.Get("step"); v != "" {
		if step, err = time.ParseDuration(v); err != nil || step < stats.Resolution || step%stats.Resolution != 0 {
			return nil, badRequest("step: %q: a multiple of %s, e.g. 5m", v, stats.Resolution)
		}
	} else {
		step = max(to.Sub(from)/autoBuckets, stats.Resolution).Truncate(stats.Resolution)
	}
	if n := to.Sub(from.Truncate(step)) / step; n > maxBuckets {
		return nil, badRequest("%d buckets: at most %d, use a larger step", n, maxBuckets)
	}
	buckets := st.Series(from, to, step)
	return seriesResponse{
		From: from.Truncate(step), To: to, Step: step.String(), StepSeconds: int64(step / time.Second),
		AvailableSince: available(st), Buckets: buckets,
	}, nil
}

// alertFilter selects alerts and what to include of their events.
type alertFilter struct {
	rules    []string
	severity []string
	events   string // none, last, all
	// pendingUndo keeps only the alerts with an undo not run yet.
	pendingUndo bool
}

func parseAlertFilter(q url.Values) (alertFilter, error) {
	f := alertFilter{events: "last"}
	for _, v := range q["rule"] {
		f.rules = append(f.rules, strings.Split(v, ",")...)
	}
	for _, v := range q["severity"] {
		f.severity = append(f.severity, strings.Split(v, ",")...)
	}
	if v := q.Get("events"); v != "" {
		if v != "none" && v != "last" && v != "all" {
			return f, badRequest("events: %q: none, last or all", v)
		}
		f.events = v
	}
	switch v := q.Get("undo"); v {
	case "":
	case "pending":
		f.pendingUndo = true
	default:
		return f, badRequest("undo: %q: pending is the only value", v)
	}
	return f, nil
}

func (f alertFilter) match(a *event.Alert) bool {
	return (len(f.rules) == 0 || slices.Contains(f.rules, a.RuleID)) &&
		(len(f.severity) == 0 || slices.Contains(f.severity, a.Severity))
}

// apply returns the alert with the events asked for: a copy if some are
// left out.
func (f alertFilter) apply(a *event.Alert) *event.Alert {
	if f.events == "all" || len(a.Events) == 0 {
		return a
	}
	c := *a
	c.Events = nil
	if f.events == "last" {
		c.Events = a.Events[len(a.Events)-1:]
	}
	return &c
}

// alertView is an alert with when it was raised, its action log (what its
// actions did, and the undo actions planned or run, in that order), and
// its undo not run yet, if any.
type alertView struct {
	*event.Alert
	// Raised is when wolverine raised the alert; Timestamp is the time of
	// its event, from the log. Zero for an alert no longer kept (see
	// max_lifetime) whose undo is still pending.
	Raised  time.Time `json:",omitzero"`
	Actions []event.ActionRun
	Undo    *undoView `json:",omitempty"`
}

// undoView is an undo not run yet.
type undoView struct {
	// Action is the action undone; Actions are the undo actions left to
	// run, at Due.
	Action   string
	Actions  []string
	Due      time.Time
	Attempts int `json:",omitempty"`
}

func (f alertFilter) view(r engine.AlertRecord, p *action.Pending) alertView {
	v := alertView{Alert: f.apply(r.Alert), Raised: r.Raised, Actions: r.Actions}
	if v.Actions == nil {
		v.Actions = []event.ActionRun{}
	}
	if p != nil {
		v.Undo = &undoView{Action: p.Action, Actions: p.Actions, Due: p.Due, Attempts: p.Attempts}
	}
	return v
}

// raised returns when an alert was raised, or, if no longer kept, the
// time of its event.
func raised(r engine.AlertRecord) time.Time {
	if r.Raised.IsZero() {
		return r.Alert.Timestamp
	}
	return r.Raised
}

// alertRecords returns the alerts kept, newest first, and their pending
// undos by alert id. The alerts whose undo is pending but that are no
// longer kept (an undo after more than max_lifetime) are included, without
// their action log.
func (s *Server) alertRecords() ([]engine.AlertRecord, map[string]*action.Pending) {
	records := s.backend.AlertRecords()
	pending := map[string]*action.Pending{}
	for _, p := range s.backend.PendingUndos() {
		if p.Alert != nil {
			pending[p.Alert.ID] = &p
		}
	}
	kept := make(map[string]bool, len(records))
	for _, r := range records {
		kept[r.Alert.ID] = true
	}
	for id, p := range pending {
		if !kept[id] {
			records = append(records, engine.AlertRecord{Alert: p.Alert})
		}
	}
	slices.SortStableFunc(records, func(a, b engine.AlertRecord) int { return raised(b).Compare(raised(a)) })
	return records, pending
}

// actionNotice is a run added to the action log of an alert, as sent by
// /alerts/watch.
type actionNotice struct {
	AlertID string
	RuleID  string
	event.ActionRun
}

// alertsResponse is the result of /alerts.
type alertsResponse struct {
	// Total is the number of alerts that match, Alerts the first limit of
	// them, newest first.
	Total  int         `json:"total"`
	Alerts []alertView `json:"alerts"`
}

// alerts gives the alerts memorized (within the maximum lifetime) raised in
// [from, to), newest first.
func (s *Server) alerts(r *http.Request) (any, error) {
	q := r.URL.Query()
	from, to, err := s.interval(q, 0)
	if err != nil {
		return nil, err
	}
	f, err := parseAlertFilter(q)
	if err != nil {
		return nil, err
	}
	limit := defaultAlerts
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 || limit > maxAlerts {
			return nil, badRequest("limit: %q: between 1 and %d", v, maxAlerts)
		}
	}
	records, pending := s.alertRecords()
	resp := alertsResponse{Alerts: []alertView{}}
	for _, r := range records {
		t, p := raised(r), pending[r.Alert.ID]
		if t.Before(from) || !t.Before(to) || !f.match(r.Alert) || (f.pendingUndo && p == nil) {
			continue
		}
		resp.Total++
		if len(resp.Alerts) < limit {
			resp.Alerts = append(resp.Alerts, f.view(r, p))
		}
	}
	return resp, nil
}

// alert gives an alert memorized, by id, with its action log and all its
// events (unless events=last or none).
func (s *Server) alert(r *http.Request) (any, error) {
	q := r.URL.Query()
	if q.Get("events") == "" {
		q.Set("events", "all")
	}
	f, err := parseAlertFilter(q)
	if err != nil {
		return nil, err
	}
	id := r.PathValue("id")
	records, pending := s.alertRecords()
	for _, rec := range records {
		if rec.Alert.ID == id {
			return f.view(rec, pending[id]), nil
		}
	}
	return nil, &apiError{http.StatusNotFound, fmt.Sprintf("alert %q: not found (or expired, see max_lifetime)", id)}
}

// watch streams the alerts raised from now on, and what their actions do,
// as server-sent events:
//
//	event: alert
//	id: <alert id>
//	data: {"ID":..., "Actions":[]}
//
//	event: action
//	data: {"AlertID":..., "RuleID":..., "Action":..., "Status":...}
//
// A comment is sent every heartbeat. The stream ends when wolverine stops
// or if the client reads too slowly: it should reconnect, and may fetch
// /alerts for what it missed.
func (s *Server) watch(w http.ResponseWriter, r *http.Request) {
	f, err := parseAlertFilter(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if s.watchers.Add(1) > maxWatchers {
		s.watchers.Add(-1)
		writeError(w, http.StatusServiceUnavailable, "too many watchers (%d)", maxWatchers)
		return
	}
	defer s.watchers.Add(-1)

	notices, cancel := s.backend.Watch()
	defer cancel()
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // nginx: do not buffer
	w.WriteHeader(http.StatusOK)

	send := func(format string, args ...any) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("retry: 3000\n: connected\n\n") {
		return
	}
	tick := time.NewTicker(s.heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if !send(": heartbeat\n\n") {
				return
			}
		case n, ok := <-notices:
			if !ok {
				return // wolverine stops, or the client lagged
			}
			a := n.Alert
			if a == nil || !f.match(a) {
				continue
			}
			if n.Action != nil {
				b, err := json.Marshal(actionNotice{a.ID, a.RuleID, *n.Action})
				if err != nil || !send("event: action\ndata: %s\n\n", b) {
					return
				}
				continue
			}
			b, err := json.Marshal(f.view(engine.AlertRecord{Alert: a, Raised: n.Raised}, nil))
			if err != nil {
				continue
			}
			if !send("event: alert\nid: %s\ndata: %s\n\n", a.ID, b) {
				return
			}
		}
	}
}
