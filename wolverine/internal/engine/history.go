package engine

import (
	"slices"
	"sync"
	"time"

	"wolverine/internal/event"
	"wolverine/internal/state"
)

// history memorizes the alerts raised (with the rule that raised them and
// their events) until they expire, at the maximum lifetime.
type history struct {
	mu     sync.Mutex
	alerts []remembered // in the order they were raised
	// changed tells whether alerts changed since the last call to
	// saved.
	changed bool
}

type remembered struct {
	alert *event.Alert
	at    time.Time // wall clock
}

func (h *history) add(a *event.Alert, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alerts = append(h.alerts, remembered{a, at})
	h.changed = true
}

// restore adds the alerts saved in the state file that were memorized at
// or after cutoff, and returns how many.
func (h *history) restore(saved []state.Alert, cutoff time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range saved {
		if !s.MemorizedAt.Before(cutoff) {
			h.alerts = append(h.alerts, remembered{s.Alert, s.MemorizedAt})
			n++
		}
	}
	slices.SortStableFunc(h.alerts, func(a, b remembered) int { return a.at.Compare(b.at) })
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
		alerts[i] = state.Alert{MemorizedAt: r.at, Alert: r.alert}
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
		h.alerts = slices.Clone(h.alerts[i:]) // release the old array
		h.changed = true
	}
	return i
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
