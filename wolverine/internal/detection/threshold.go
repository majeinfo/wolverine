package detection

import (
	"fmt"
	"sync"
	"time"

	"wolverine/internal/event"
	"wolverine/internal/verbose"
)

// ThresholdRule raises an alert when at least Count matching events sharing
// the same GroupBy value occur within Window. Event timestamps are used, not
// the wall clock, so replaying an old log file gives the same alerts.
//
// Once the rule fires for a group, that group's counter is reset: a new alert
// needs Count new events. If Suppress is set, no new alert is raised for that
// group until Suppress has elapsed since the previous one.
type ThresholdRule struct {
	RuleID      string
	Description string
	Severity    string
	Match       Match
	GroupBy     string
	Count       int
	Window      time.Duration
	Suppress    time.Duration

	mu        sync.Mutex
	groups    map[string][]*event.Event
	fired     map[string]time.Time
	lastSweep time.Time
}

func (r *ThresholdRule) ID() string { return r.RuleID }

func (r *ThresholdRule) Evaluate(ev *event.Event) []*event.Alert {
	if !r.Match.Matches(ev) {
		return nil
	}
	key := FieldValue(ev, r.GroupBy)
	if key == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.groups == nil {
		r.groups = map[string][]*event.Event{}
		r.fired = map[string]time.Time{}
	}
	r.sweep(ev.Timestamp)

	evs := append(evict(r.groups[key], ev.Timestamp.Add(-r.Window)), ev)
	verbose.Debugf("rule %s: %s=%s: %d/%d events within %s", r.RuleID, r.GroupBy, key, len(evs), r.Count, r.Window)
	if len(evs) < r.Count {
		r.groups[key] = evs
		return nil
	}
	delete(r.groups, key)

	if r.Suppress > 0 {
		if last, ok := r.fired[key]; ok && ev.Timestamp.Sub(last) < r.Suppress {
			verbose.Debugf("rule %s: %s=%s: alert suppressed until %s", r.RuleID, r.GroupBy, key, last.Add(r.Suppress).Format(time.DateTime))
			return nil
		}
		r.fired[key] = ev.Timestamp
	}

	return []*event.Alert{{
		ID:        newID(),
		RuleID:    r.RuleID,
		Timestamp: ev.Timestamp,
		Severity:  r.Severity,
		Message: fmt.Sprintf("%s: %d events for %s=%s within %s",
			r.Description, len(evs), r.GroupBy, key, evs[len(evs)-1].Timestamp.Sub(evs[0].Timestamp)),
		Events: evs,
		Metadata: map[string]any{
			"group_by": r.GroupBy,
			"value":    key,
			"count":    len(evs),
			"window":   r.Window.String(),
		},
	}}
}

// evict drops the events older than cutoff.
func evict(evs []*event.Event, cutoff time.Time) []*event.Event {
	i := 0
	for i < len(evs) && evs[i].Timestamp.Before(cutoff) {
		i++
	}
	return evs[i:]
}

// sweep forgets the groups that have no event left in the window and the
// expired suppressions, at most once per window, so memory does not grow with
// every IP ever seen.
func (r *ThresholdRule) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < r.Window {
		return
	}
	r.lastSweep = now
	cutoff := now.Add(-r.Window)
	for k, evs := range r.groups {
		if evs = evict(evs, cutoff); len(evs) == 0 {
			delete(r.groups, k)
		} else {
			r.groups[k] = evs
		}
	}
	for k, last := range r.fired {
		if now.Sub(last) >= r.Suppress {
			delete(r.fired, k)
		}
	}
}
