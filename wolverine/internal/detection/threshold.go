package detection

import (
	"encoding/json"
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
	// Signature identifies what the rule counts (type, match, exclusions,
	// group_by): data saved under another signature is not restored.
	Signature string
	// Now returns the wall-clock time at which data is memorized, compared
	// with the cutoff of Expire (nil: time.Now).
	Now func() time.Time

	mu        sync.Mutex
	groups    map[string][]memorized
	fired     map[string]suppression
	lastSweep time.Time
	// changed tells whether groups or fired changed since the last Save.
	changed bool
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

func (r *ThresholdRule) init() {
	if r.groups == nil {
		r.groups = map[string][]memorized{}
		r.fired = map[string]suppression{}
	}
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

	r.init()
	r.sweep(ev.Timestamp)
	r.changed = true

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
		r.changed = true
		verbose.Debugf("rule %s: %d events and suppressions expired", r.RuleID, n)
	}
	return n
}

// thresholdData is the data of a ThresholdRule, as saved.
type thresholdData struct {
	Signature    string                      `json:"signature"`
	Groups       map[string][]savedEvent     `json:"groups,omitempty"`
	Suppressions map[string]savedSuppression `json:"suppressions,omitempty"`
}

type savedEvent struct {
	MemorizedAt time.Time    `json:"memorized_at"`
	Event       *event.Event `json:"event"`
}

type savedSuppression struct {
	// Last is the event time of the last alert of the group.
	Last        time.Time `json:"last"`
	MemorizedAt time.Time `json:"memorized_at"`
}

func (r *ThresholdRule) Save() (json.RawMessage, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.changed {
		return nil, false, nil
	}
	d := thresholdData{Signature: r.Signature}
	if len(r.groups) > 0 {
		d.Groups = map[string][]savedEvent{}
		for k, mems := range r.groups {
			for _, m := range mems {
				d.Groups[k] = append(d.Groups[k], savedEvent{m.at, m.ev})
			}
		}
	}
	if len(r.fired) > 0 {
		d.Suppressions = map[string]savedSuppression{}
		for k, s := range r.fired {
			d.Suppressions[k] = savedSuppression{s.last, s.at}
		}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, false, err
	}
	r.changed = false
	return b, true, nil
}

func (r *ThresholdRule) Restore(data json.RawMessage, cutoff time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var d thresholdData
	if err := json.Unmarshal(data, &d); err != nil {
		r.changed = true // the file must drop the invalid data
		return 0, err
	}
	if d.Signature != r.Signature {
		r.changed = true // the file must drop the old data
		return 0, ErrRuleChanged
	}
	r.init()
	n, total := 0, 0
	for k, saved := range d.Groups {
		total += len(saved)
		var mems []memorized
		for _, s := range saved {
			if s.Event != nil && !s.MemorizedAt.Before(cutoff) {
				mems = append(mems, memorized{s.Event, s.MemorizedAt})
			}
		}
		if len(mems) > 0 {
			r.groups[k] = mems
			n += len(mems)
		}
	}
	for k, s := range d.Suppressions {
		total++
		if !s.MemorizedAt.Before(cutoff) {
			r.fired[k] = suppression{last: s.Last, at: s.MemorizedAt}
			n++
		}
	}
	r.changed = n != total
	return n, nil
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
