package action

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/event"
)

// fake is an action that records its calls and fails while fail is set.
type fake struct {
	id   string
	mu   sync.Mutex
	got  []string // alert id, undo_of
	fail bool
}

func (f *fake) Name() string { return f.id }
func (f *fake) Execute(_ context.Context, a *event.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("unreachable")
	}
	undo, _ := a.Metadata["undo_of"].(string)
	f.got = append(f.got, a.ID+" "+undo)
	return nil
}

func (f *fake) calls() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.got, ",")
}

// runLog records the action runs reported, one line each: "alert
// action<undoOf status due".
type runLog struct {
	mu   sync.Mutex
	runs []string
	last event.ActionRun
}

func (l *runLog) report(alertID string, r event.ActionRun) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line := alertID + " " + r.Action
	if r.UndoOf != "" {
		line += "<" + r.UndoOf
	}
	line += " " + r.Status
	if !r.Due.IsZero() {
		line += " " + r.Due.Format("15:04")
	}
	if r.Time.IsZero() {
		line += " (no time)"
	}
	l.runs = append(l.runs, line)
	l.last = r
}

// take returns the lines recorded since the previous call.
func (l *runLog) take() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := strings.Join(l.runs, ", ")
	l.runs = nil
	return s
}

func TestBuildUndos(t *testing.T) {
	block, unblock, mail := &fake{id: "block"}, &fake{id: "unblock"}, &fake{id: "mail"}
	actions := map[string]Action{"block": block, "unblock": unblock, "mail": mail, "off": nil}
	cfg := func(undo *config.Undo) []config.Action {
		return []config.Action{{ID: "block", Undo: undo}, {ID: "unblock"}, {ID: "mail"}, {ID: "off", Disabled: true}}
	}
	undos, err := BuildUndos(cfg(&config.Undo{After: time.Hour, Actions: []string{"unblock", "mail"}}), actions)
	if err != nil || len(undos) != 1 || undos["block"].After != time.Hour || strings.Join(undos["block"].Actions, ",") != "unblock,mail" {
		t.Fatalf("got %+v, %v", undos, err)
	}

	for _, tt := range []struct {
		undo config.Undo
		want string
	}{
		{config.Undo{Actions: []string{"unblock"}}, "undo.after must be a positive duration"},
		{config.Undo{After: time.Hour}, "at least one action"},
		{config.Undo{After: time.Hour, Actions: []string{"nope"}}, `unknown action "nope"`},
		{config.Undo{After: time.Hour, Actions: []string{"block"}}, "cannot undo itself"},
		{config.Undo{After: time.Hour, Actions: []string{"off"}}, `action "off" is disabled`},
	} {
		if _, err := BuildUndos(cfg(&tt.undo), actions); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%+v: got %v, want %q", tt.undo, err, tt.want)
		}
	}
	// No chains.
	cfgs := cfg(&config.Undo{After: time.Hour, Actions: []string{"unblock"}})
	cfgs[1].Undo = &config.Undo{After: time.Hour, Actions: []string{"mail"}}
	if _, err := BuildUndos(cfgs, actions); err == nil || !strings.Contains(err.Error(), `"unblock" has an undo itself`) {
		t.Errorf("chain: got %v", err)
	}
	// A disabled action is not undone, and may use a disabled undo action.
	cfgs = cfg(&config.Undo{After: time.Hour, Actions: []string{"off"}})
	cfgs[0].Disabled = true
	if undos, err := BuildUndos(cfgs, actions); err != nil || len(undos) != 0 {
		t.Errorf("disabled: got %v, %v", undos, err)
	}
}

func TestScheduler(t *testing.T) {
	unblock, mail := &fake{id: "unblock"}, &fake{id: "mail"}
	clock := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s := NewScheduler(
		map[string]*Undo{"block": {After: time.Hour, Actions: []string{"unblock", "mail"}}},
		map[string]Action{"unblock": unblock, "mail": mail},
	)
	s.Now = func() time.Time { return clock }
	var log runLog
	s.Report = log.report
	alert := func(id, ip string) *event.Alert {
		return &event.Alert{ID: id, RuleID: "ssh", Metadata: map[string]any{"value": ip}}
	}

	s.Schedule("mail", alert("a0", "192.0.2.1")) // no undo
	s.Schedule("block", alert("a1", "192.0.2.1"))
	s.Schedule("block", alert("a2", "192.0.2.2"))
	clock = clock.Add(30 * time.Minute)
	// The same IP blocked again: its undo is postponed.
	s.Schedule("block", alert("a3", "192.0.2.1"))
	if p, changed := s.Pending(); len(p) != 2 || !changed || p[0].Alert.ID != "a2" || p[1].Alert.ID != "a3" {
		t.Fatalf("pending: %+v", p)
	}
	if got, want := log.take(), "a1 unblock<block planned 11:00, a1 mail<block planned 11:00, "+
		"a2 unblock<block planned 11:00, a2 mail<block planned 11:00, "+
		"a1 unblock<block postponed 11:30, a1 mail<block postponed 11:30, "+
		"a3 unblock<block planned 11:30, a3 mail<block planned 11:30"; got != want {
		t.Errorf("reported:\n%s\nwant:\n%s", got, want)
	}

	clock = clock.Add(31 * time.Minute)
	s.runDue()
	if got := unblock.calls() + " / " + mail.calls(); got != "a2 block / a2 block" {
		t.Fatalf("after an hour: %s", got)
	}
	// The alert given to the actions is not modified.
	if p, _ := s.Pending(); len(p) != 1 || p[0].Alert.Metadata["undo_of"] != nil {
		t.Fatalf("pending: %+v", p)
	}

	// A failed undo action is tried again later, alone.
	unblock.fail = true
	clock = clock.Add(30 * time.Minute)
	s.runDue()
	p, _ := s.Pending()
	if len(p) != 1 || p[0].Attempts != 1 || strings.Join(p[0].Actions, ",") != "unblock" || !p[0].Due.Equal(clock.Add(undoRetryDelay)) {
		t.Fatalf("after a failure: %+v", p)
	}
	// The failure is reported with the time of the retry.
	if got, want := log.take(), "a2 unblock<block ok, a2 mail<block ok, a3 mail<block ok, a3 unblock<block failed 11:32"; got != want {
		t.Errorf("reported: %s, want %s", got, want)
	}
	if log.last.Error != "unreachable" || !strings.Contains(log.last.Detail, "attempt 1 of 5") {
		t.Errorf("failure: %+v", log.last)
	}
	unblock.fail = false
	clock = clock.Add(undoRetryDelay)
	s.runDue()
	if got := unblock.calls() + " / " + mail.calls(); got != "a2 block,a3 block / a2 block,a3 block" {
		t.Fatalf("after the retry: %s", got)
	}
	if p, _ := s.Pending(); len(p) != 0 {
		t.Fatalf("pending: %+v", p)
	}

	// Given up after maxUndoAttempts.
	unblock.fail = true
	s.Schedule("block", alert("a4", "192.0.2.4"))
	for range maxUndoAttempts {
		clock = clock.Add(time.Hour)
		s.runDue()
	}
	if p, _ := s.Pending(); len(p) != 0 {
		t.Fatalf("not given up: %+v", p)
	}
	if !strings.HasSuffix(log.take(), "a4 unblock<block failed") || !strings.Contains(log.last.Detail, "given up") {
		t.Errorf("given up: %+v", log.last)
	}
}

func TestSchedulerRestore(t *testing.T) {
	unblock := &fake{id: "unblock"}
	s := NewScheduler(
		map[string]*Undo{"block": {After: time.Hour, Actions: []string{"unblock"}}},
		map[string]Action{"unblock": unblock, "off": nil},
	)
	var log runLog
	s.Report = log.report
	due := time.Now().Add(-time.Minute) // overdue
	s.Restore([]Pending{
		{Key: "k1", Action: "block", Actions: []string{"unblock"}, Due: due, Alert: &event.Alert{ID: "a1"}},
		// The action no longer has an undo, or its undo action is gone.
		{Key: "k2", Action: "mail", Actions: []string{"unblock"}, Due: due, Alert: &event.Alert{ID: "a2"}},
		{Key: "k3", Action: "block", Actions: []string{"off", "gone"}, Due: due, Alert: &event.Alert{ID: "a3"}},
	})
	if p, changed := s.Pending(); len(p) != 1 || p[0].Key != "k1" || !changed {
		t.Fatalf("restored: %+v", p)
	}
	if got, want := log.take(), "a2 unblock<mail skipped, a3 off<block skipped, a3 gone<block skipped"; got != want {
		t.Errorf("reported: %s, want %s", got, want)
	}

	// Overdue undos run as soon as the scheduler starts.
	s.Start()
	deadline := time.Now().Add(5 * time.Second)
	for unblock.calls() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()
	if got := unblock.calls(); got != "a1 block" {
		t.Errorf("calls: %q", got)
	}
	if got := log.take(); got != "a1 unblock<block ok" {
		t.Errorf("reported after the start: %s", got)
	}
}

func TestSchedulerStartStop(t *testing.T) {
	unblock := &fake{id: "unblock"}
	s := NewScheduler(
		map[string]*Undo{"block": {After: 50 * time.Millisecond, Actions: []string{"unblock"}}},
		map[string]Action{"unblock": unblock},
	)
	var log runLog
	s.Report = log.report
	s.Start()
	// Through the dispatcher: only the actions that succeed are undone.
	failing := &fake{id: "block2", fail: true}
	block := &fake{id: "block"}
	d := NewDispatcher(context.Background(), map[string][]Action{"r": {block, failing}}, 10, s, log.report)
	d.Dispatch(&event.Alert{ID: "a1", RuleID: "r", Metadata: map[string]any{"value": "x"}})
	d.Close()
	deadline := time.Now().Add(5 * time.Second)
	for unblock.calls() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()
	if got := unblock.calls(); got != "a1 block" {
		t.Errorf("calls: %q", got)
	}
	// The planned undo is reported before the failure of the next action.
	got := log.take()
	if !strings.HasPrefix(got, "a1 block ok, a1 unblock<block planned ") || !strings.HasSuffix(got, ", a1 block2 failed, a1 unblock<block ok") {
		t.Errorf("reported: %s", got)
	}
}

func TestDispatcherDropped(t *testing.T) {
	var log runLog
	slow := &blocking{started: make(chan struct{}), release: make(chan struct{})}
	d := NewDispatcher(context.Background(), map[string][]Action{"r": {slow, &fake{id: "mail"}}}, 1, nil, log.report)
	d.Dispatch(&event.Alert{ID: "a1", RuleID: "r"}) // running
	<-slow.started
	d.Dispatch(&event.Alert{ID: "a2", RuleID: "r"}) // queued
	d.Dispatch(&event.Alert{ID: "a3", RuleID: "r"}) // dropped
	close(slow.release)
	d.Close()
	if got := log.take(); !strings.Contains(got, "a3 slow dropped, a3 mail dropped") || strings.Count(got, " ok") != 4 {
		t.Errorf("reported: %s", got)
	}
}

// blocking is an action whose first run waits for release.
type blocking struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blocking) Name() string { return "slow" }
func (b *blocking) Execute(context.Context, *event.Alert) error {
	b.once.Do(func() {
		close(b.started)
		<-b.release
	})
	return nil
}
