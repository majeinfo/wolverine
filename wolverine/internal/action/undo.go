package action

import (
	"context"
	"fmt"
	"log"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/event"
	"wolverine/internal/verbose"
)

const (
	// undoRetryDelay is how long a failed undo action waits before it is
	// tried again.
	undoRetryDelay = time.Minute
	// maxUndoAttempts is how many times an undo action is tried.
	maxUndoAttempts = 5
)

// Undo is how an action is undone: the actions run After it succeeded.
type Undo struct {
	After   time.Duration
	Actions []string // action ids
}

// BuildUndos returns the undo of each enabled action that has one, by
// action id. actions is the result of Build.
func BuildUndos(cfgs []config.Action, actions map[string]Action) (map[string]*Undo, error) {
	undos := map[string]*Undo{}
	for _, c := range cfgs {
		if c.Undo == nil {
			continue
		}
		if c.Undo.After <= 0 {
			return nil, fmt.Errorf("action %q: undo.after must be a positive duration (e.g. 1h)", c.ID)
		}
		if len(c.Undo.Actions) == 0 {
			return nil, fmt.Errorf("action %q: undo.actions: at least one action is required", c.ID)
		}
		for _, id := range c.Undo.Actions {
			a, ok := actions[id]
			switch {
			case !ok:
				return nil, fmt.Errorf("action %q: undo.actions: unknown action %q", c.ID, id)
			case id == c.ID:
				return nil, fmt.Errorf("action %q: undo.actions: an action cannot undo itself", c.ID)
			case a == nil && !c.Disabled:
				// The action would never be undone.
				return nil, fmt.Errorf("action %q: undo.actions: action %q is disabled", c.ID, id)
			}
			if u := undoOf(cfgs, id); u != nil {
				return nil, fmt.Errorf("action %q: undo.actions: action %q has an undo itself", c.ID, id)
			}
		}
		if !c.Disabled {
			undos[c.ID] = &Undo{After: c.Undo.After, Actions: slices.Clone(c.Undo.Actions)}
		}
	}
	return undos, nil
}

func undoOf(cfgs []config.Action, id string) *config.Undo {
	for _, c := range cfgs {
		if c.ID == id {
			return c.Undo
		}
	}
	return nil
}

// Pending is an undo waiting for its time.
type Pending struct {
	// Key identifies what is undone: the action, the rule and its group_by
	// value (e.g. the IP address blocked). A new alert with the same key
	// postpones the undo instead of adding one.
	Key string
	// Action is the id of the action undone.
	Action string
	// Actions are the ids of the undo actions left to run.
	Actions []string
	Due     time.Time
	// Attempts counts the failed attempts.
	Attempts int
	Alert    *event.Alert
}

// Scheduler runs the undo actions when they are due. Start runs it in the
// background, Stop stops it: the undos not run yet stay pending (see
// Pending and Restore, to keep them across restarts).
type Scheduler struct {
	undos   map[string]*Undo
	actions map[string]Action
	// Now gives the current time (nil: time.Now).
	Now func() time.Time
	// Report, if not nil, is told what happens to the undo actions: set
	// it before Restore and Start.
	Report event.Reporter

	mu      sync.Mutex
	pending map[string]*Pending
	changed bool

	wake chan struct{}
	stop chan struct{}
	done chan struct{}
}

// NewScheduler creates a scheduler for the undos of BuildUndos. actions is
// the result of Build.
func NewScheduler(undos map[string]*Undo, actions map[string]Action) *Scheduler {
	return &Scheduler{
		undos:   undos,
		actions: actions,
		pending: map[string]*Pending{},
		wake:    make(chan struct{}, 1),
	}
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Undoes reports whether the action has an undo.
func (s *Scheduler) Undoes(actionID string) bool {
	return s != nil && s.undos[actionID] != nil
}

// Schedule plans the undo of an action that succeeded for an alert, if the
// action has one. If the same thing (see Pending.Key) is already to be
// undone, its undo is postponed.
func (s *Scheduler) Schedule(actionID string, a *event.Alert) {
	if !s.Undoes(actionID) {
		return
	}
	u := s.undos[actionID]
	p := &Pending{
		Key:     fmt.Sprintf("%s\x00%s\x00%v", actionID, a.RuleID, a.Metadata["value"]),
		Action:  actionID,
		Actions: slices.Clone(u.Actions),
		Due:     s.now().Add(u.After),
		Alert:   a,
	}
	s.mu.Lock()
	old, postponed := s.pending[p.Key]
	s.pending[p.Key] = p
	s.changed = true
	s.mu.Unlock()
	what := "planned"
	if postponed {
		what = "postponed"
		for _, id := range old.Actions {
			s.report(old.Alert, event.ActionRun{Action: id, UndoOf: actionID, Status: event.ActionPostponed, Due: p.Due,
				Detail: fmt.Sprintf("%s done again for alert %s: undone after it instead", actionID, a.ID)})
		}
	}
	for _, id := range p.Actions {
		s.report(a, event.ActionRun{Action: id, UndoOf: actionID, Status: event.ActionPlanned, Due: p.Due})
	}
	verbose.Infof("action %s: undo (%s) %s at %s for alert %s (%s)", actionID, strings.Join(u.Actions, ", "), what, p.Due.Format(time.DateTime), a.ID, a.RuleID)
	s.signal()
}

// report tells s.Report what happened to an undo action of alert a.
func (s *Scheduler) report(a *event.Alert, run event.ActionRun) {
	if s.Report == nil || a == nil {
		return
	}
	if run.Time.IsZero() {
		run.Time = s.now()
	}
	s.Report(a.ID, run)
}

func (s *Scheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Restore adds undos saved by a previous run. Those of actions that no
// longer have an undo, and the undo actions that are gone, are dropped. The
// undos already due run as soon as the scheduler starts.
func (s *Scheduler) Restore(pending []Pending) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range pending {
		if p.Alert == nil || !s.Undoes(p.Action) {
			log.Printf("action %s: no undo anymore, pending undo for alert %s dropped", p.Action, alertID(p.Alert))
			s.changed = true
			for _, id := range p.Actions {
				s.report(p.Alert, event.ActionRun{Action: id, UndoOf: p.Action, Status: event.ActionSkipped,
					Detail: fmt.Sprintf("action %s has no undo anymore", p.Action)})
			}
			continue
		}
		var ids []string
		for _, id := range p.Actions {
			if s.actions[id] == nil {
				log.Printf("action %s: undo action %s is gone or disabled, not run for alert %s", p.Action, id, p.Alert.ID)
				s.changed = true
				s.report(p.Alert, event.ActionRun{Action: id, UndoOf: p.Action, Status: event.ActionSkipped,
					Detail: "the undo action is gone or disabled"})
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			continue
		}
		p.Actions = ids
		s.pending[p.Key] = &p
	}
	if len(s.pending) > 0 {
		verbose.Infof("%d pending undos restored", len(s.pending))
	}
}

func alertID(a *event.Alert) string {
	if a == nil {
		return "?"
	}
	return a.ID
}

// Pending returns the undos not run yet, by due time, and whether they
// changed since the previous call (or since Restore).
func (s *Scheduler) Pending() ([]Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.changed
	s.changed = false
	return s.list(), changed
}

// List returns the undos not run yet, by due time, without changing what
// Pending reports.
func (s *Scheduler) List() []Pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list()
}

func (s *Scheduler) list() []Pending {
	var list []Pending
	for _, p := range s.pending {
		c := *p
		c.Actions = slices.Clone(p.Actions)
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].Due.Equal(list[j].Due) {
			return list[i].Due.Before(list[j].Due)
		}
		return list[i].Key < list[j].Key
	})
	return list
}

// Start runs the undos when they are due, until Stop.
func (s *Scheduler) Start() {
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	go s.run()
}

// Stop stops the scheduler, once the undos due have run: a run that reads
// its sources once still undoes the actions due.
func (s *Scheduler) Stop() {
	close(s.stop)
	<-s.done
}

func (s *Scheduler) run() {
	defer close(s.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		s.runDue()
		timer.Reset(s.next())
		select {
		case <-s.stop:
			s.runDue()
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}

// next returns how long to wait for the next undo.
func (s *Scheduler) next() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	wait := time.Hour
	now := s.now()
	for _, p := range s.pending {
		wait = min(wait, max(p.Due.Sub(now), 0))
	}
	return wait
}

// runDue runs the undos that are due.
func (s *Scheduler) runDue() {
	s.mu.Lock()
	now := s.now()
	var due []*Pending
	for _, p := range s.pending {
		if !p.Due.After(now) {
			due = append(due, p)
		}
	}
	s.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].Due.Before(due[j].Due) })

	for _, p := range due {
		failed, errs := s.undo(p)

		s.mu.Lock()
		var retry time.Time
		var detail string
		// Unless a new alert postponed it meanwhile.
		if s.pending[p.Key] == p {
			s.changed = true
			p.Attempts++
			switch {
			case len(failed) == 0:
				delete(s.pending, p.Key)
			case p.Attempts >= maxUndoAttempts:
				log.Printf("action %s: undo (%s) for alert %s failed %d times, given up", p.Action, strings.Join(failed, ", "), p.Alert.ID, p.Attempts)
				delete(s.pending, p.Key)
				detail = fmt.Sprintf("attempt %d of %d: given up", p.Attempts, maxUndoAttempts)
			default:
				p.Actions = failed
				p.Due = s.now().Add(undoRetryDelay)
				retry = p.Due
				detail = fmt.Sprintf("attempt %d of %d: tried again at the due time", p.Attempts, maxUndoAttempts)
				log.Printf("action %s: undo (%s) for alert %s will be tried again at %s", p.Action, strings.Join(failed, ", "), p.Alert.ID, p.Due.Format(time.DateTime))
			}
		} else {
			detail = "not tried again: postponed by a later alert"
		}
		s.mu.Unlock()
		for _, run := range errs {
			run.Due, run.Detail = retry, detail
			s.report(p.Alert, run)
		}
	}
}

// undo runs the undo actions of p and returns the ids of those that failed,
// with their runs to report. It reports those that did not fail.
func (s *Scheduler) undo(p *Pending) ([]string, []event.ActionRun) {
	// The undo actions get a copy of the alert that tells what they undo.
	a := *p.Alert
	a.Metadata = maps.Clone(a.Metadata)
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}
	a.Metadata["undo_of"] = p.Action

	var failed []string
	var runs []event.ActionRun
	for _, id := range p.Actions {
		act := s.actions[id]
		if act == nil {
			log.Printf("action %s: undo action %s is gone or disabled, not run for alert %s", p.Action, id, a.ID)
			s.report(p.Alert, event.ActionRun{Action: id, UndoOf: p.Action, Status: event.ActionSkipped, Detail: "the undo action is gone or disabled"})
			continue
		}
		verbose.Debugf("action %s: undoing %s for alert %s (%s)", id, p.Action, a.ID, a.RuleID)
		start := s.now()
		// Not cancelled by a shutdown: the action's own timeout applies.
		err := act.Execute(context.Background(), &a)
		run := event.ActionRun{Time: s.now(), Action: id, UndoOf: p.Action, Status: event.ActionOK, Duration: s.now().Sub(start).Round(time.Millisecond)}
		if err != nil {
			log.Printf("action %s (undo of %s) for alert %s (%s): %v", id, p.Action, a.ID, a.RuleID, err)
			run.Status, run.Error = event.ActionFailed, err.Error()
			failed = append(failed, id)
			runs = append(runs, run)
			continue
		}
		verbose.Infof("action %s: undid %s for alert %s (%s)", id, p.Action, a.ID, a.RuleID)
		s.report(p.Alert, run)
	}
	return failed, runs
}
