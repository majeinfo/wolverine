package engine

import (
	"slices"
	"sync"
	"time"

	"wolverine/internal/event"
	"wolverine/internal/state"
)

// history memorizes the alerts raised (with the rule that raised them and
// their events), and what their actions did, until they expire, at the
// maximum lifetime.
type history struct {
	mu     sync.Mutex
	alerts []*remembered // in the order they were raised
	byID   map[string]*remembered
	// changed tells whether alerts changed since the last call to
	// saved.
	changed bool
}

type remembered struct {
	alert   *event.Alert
	at      time.Time // wall clock
	actions []event.ActionRun
}

// AlertRecord is an alert memorized and its action log.
type AlertRecord struct {
	Alert *event.Alert
	// Raised is when wolverine raised it (wall clock), whereas the alert's
	// Timestamp is the time of its event, read from the log.
	Raised time.Time
	// Actions are what happened to its actions, in that order.
	Actions []event.ActionRun
}

func (h *history) add(a *event.Alert, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.insert(&remembered{alert: a, at: at})
	h.changed = true
}

func (h *history) insert(r *remembered) {
	if h.byID == nil {
		h.byID = map[string]*remembered{}
	}
	h.alerts = append(h.alerts, r)
	h.byID[r.alert.ID] = r
}

// record adds a run to the action log of an alert, and returns the alert,
// or nil if it is not memorized (anymore).
func (h *history) record(alertID string, run event.ActionRun) *event.Alert {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.byID[alertID]
	if r == nil {
		return nil
	}
	r.actions = append(r.actions, run)
	h.changed = true
	return r.alert
}

// restore adds the alerts saved in the state file that were memorized at
// or after cutoff, and returns how many.
func (h *history) restore(saved []state.Alert, cutoff time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range saved {
		if s.Alert != nil && !s.MemorizedAt.Before(cutoff) {
			h.insert(&remembered{alert: s.Alert, at: s.MemorizedAt, actions: s.Actions})
			n++
		}
	}
	slices.SortStableFunc(h.alerts, func(a, b *remembered) int { return a.at.Compare(b.at) })
	h.changed = n != len(saved)
	return n
}

// saved returns the alerts to save in the state file, and whether they
// changed since the previous call.
func (h *history) saved() ([]state.Alert, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.changed {
		return nil, false
	}
	h.changed = false
	alerts := make([]state.Alert, len(h.alerts))
	for i, r := range h.alerts {
		alerts[i] = state.Alert{MemorizedAt: r.at, Alert: r.alert, Actions: slices.Clone(r.actions)}
	}
	return alerts, true
}

// expire forgets the alerts memorized before cutoff and returns how many.
func (h *history) expire(cutoff time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	i := 0
	for i < len(h.alerts) && h.alerts[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		for _, r := range h.alerts[:i] {
			delete(h.byID, r.alert.ID)
		}
		h.alerts = slices.Clone(h.alerts[i:]) // release the old array
		h.changed = true
	}
	return i
}

// trim keeps only the last event of the alerts memorized before cutoff, and
// returns how many events were forgotten. The alerts are replaced by copies:
// they may be in use.
func (h *history) trim(cutoff time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.alerts {
		if !r.at.Before(cutoff) {
			break // in the order they were raised
		}
		if t := r.alert.Trimmed(); t != r.alert {
			n += len(r.alert.Events) - len(t.Events)
			r.alert = t
		}
	}
	if n > 0 {
		h.changed = true
	}
	return n
}

// list returns the alerts memorized, oldest first.
func (h *history) list() []*event.Alert {
	h.mu.Lock()
	defer h.mu.Unlock()
	alerts := make([]*event.Alert, len(h.alerts))
	for i, r := range h.alerts {
		alerts[i] = r.alert
	}
	return alerts
}

// records returns the alerts memorized with their action logs, oldest
// first.
func (h *history) records() []AlertRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	records := make([]AlertRecord, len(h.alerts))
	for i, r := range h.alerts {
		records[i] = AlertRecord{Alert: r.alert, Raised: r.at, Actions: slices.Clone(r.actions)}
	}
	return records
}
