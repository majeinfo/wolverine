package engine

import (
	"slices"
	"sync"
	"time"

	"wolverine/internal/event"
)

// history memorizes the alerts raised (with the rule that raised them and
// their events) until they expire, at the maximum lifetime.
type history struct {
	mu     sync.Mutex
	alerts []remembered // in the order they were raised
}

type remembered struct {
	alert *event.Alert
	at    time.Time // wall clock
}

func (h *history) add(a *event.Alert, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alerts = append(h.alerts, remembered{a, at})
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
