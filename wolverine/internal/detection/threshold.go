package detection

import (
	"fmt"
	"slices"
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
//
// The events counted and the suppressions are also forgotten by Expire, once
// they have been memorized for the maximum lifetime (wall clock).
type ThresholdRule struct {
	RuleID      string
	Description string
	Severity    string
	Match       Match
	GroupBy     string
	Count       int
	Window      time.Duration
	Suppress    time.Duration
	// Now returns the wall-clock time at which data is memorized, compared
	// with the cutoff of Expire (nil: time.Now).
	Now func() time.Time

	mu        sync.Mutex
	groups    map[string][]memorized
	fired     map[string]suppression
	lastSweep time.Time
}

// memorized is an event counted by a rule, with the wall-clock time it was
// memorized.
type memorized struct {
	ev *event.Event
	at time.Time
}

// suppression is the last alert of a group: its event time, and the
// wall-clock time it was memorized.
type suppression struct {
	last, at time.Time
}

func (r *ThresholdRule) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
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
		r.groups = map[string][]memorized{}
		r.fired = map[string]suppression{}
	}
	r.sweep(ev.Timestamp)

	now := r.now()
	mems := append(evict(r.groups[key], ev.Timestamp.Add(-r.Window)), memorized{ev, now})
	verbose.Debugf("rule %s: %s=%s: %d/%d events within %s", r.RuleID, r.GroupBy, key, len(mems), r.Count, r.Window)
	if len(mems) < r.Count {
		r.groups[key] = mems
		return nil
	}
	delete(r.groups, key)

	if r.Suppress > 0 {
		if s, ok := r.fired[key]; ok && ev.Timestamp.Sub(s.last) < r.Suppress {
			verbose.Debugf("rule %s: %s=%s: alert suppressed until %s", r.RuleID, r.GroupBy, key, s.last.Add(r.Suppress).Format(time.DateTime))
			return nil
		}
		r.fired[key] = suppression{last: ev.Timestamp, at: now}
	}

	evs := make([]*event.Event, len(mems))
	for i, m := range mems {
		evs[i] = m.ev
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

// evict drops the events older than cutoff (event time).
func evict(mems []memorized, cutoff time.Time) []memorized {
	i := 0
	for i < len(mems) && mems[i].ev.Timestamp.Before(cutoff) {
		i++
	}
	return mems[i:]
}

// Expire forgets the events and suppressions memorized before cutoff (wall
// clock), whatever their event time, and returns how many were forgotten.
func (r *ThresholdRule) Expire(cutoff time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for k, mems := range r.groups {
		// Events are memorized in order: the expired ones come first.
		i := 0
		for i < len(mems) && mems[i].at.Before(cutoff) {
			i++
		}
		n += i
		if i == len(mems) {
			delete(r.groups, k)
		} else if i > 0 {
			r.groups[k] = slices.Clone(mems[i:]) // release the old array
		}
	}
	for k, s := range r.fired {
		if s.at.Before(cutoff) {
			delete(r.fired, k)
			n++
		}
	}
	if n > 0 {
		verbose.Debugf("rule %s: %d events and suppressions expired", r.RuleID, n)
	}
	return n
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
	for k, mems := range r.groups {
		if mems = evict(mems, cutoff); len(mems) == 0 {
			delete(r.groups, k)
		} else {
			r.groups[k] = mems
		}
	}
	for k, s := range r.fired {
		if now.Sub(s.last) >= r.Suppress {
			delete(r.fired, k)
		}
	}
}
