package detection

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"wolverine/internal/event"
)

// SimpleRule raises an alert for every event that matches: no counting,
// no window, no suppression. It memorizes nothing.
type SimpleRule struct {
	RuleID      string
	Description string
	Severity    string
	Match       Match
	// stale is set when the state file has data saved for this rule id by
	// another kind of rule: the next Save clears it.
	stale atomic.Bool
}

func (r *SimpleRule) ID() string { return r.RuleID }

// Evaluate returns the alerts an event raises.
func (r *SimpleRule) Evaluate(ev *event.Event) []*event.Alert {
	_, alerts := r.Process(ev)
	return alerts
}

// Process raises an alert if the event matches.
func (r *SimpleRule) Process(ev *event.Event) (bool, []*event.Alert) {
	if !r.Match.Matches(ev) {
		return false, nil
	}
	msg := ev.Message
	if msg == "" {
		msg = ev.Raw
	}
	if r.Description != "" {
		msg = r.Description + ": " + msg
	}
	return true, []*event.Alert{{
		ID:        newID(),
		RuleID:    r.RuleID,
		Timestamp: ev.Timestamp,
		Start:     ev.Timestamp,
		End:       ev.Timestamp,
		Severity:  r.Severity,
		Message:   msg,
		Events:    []*event.Event{ev},
		Metadata:  map[string]any{"count": 1},
	}}
}

// Expire, Trim: a simple rule memorizes nothing.
func (r *SimpleRule) Expire(time.Time) int { return 0 }
func (r *SimpleRule) Trim(time.Time) int   { return 0 }

// Save returns no data; it clears the data another kind of rule saved under
// the same id.
func (r *SimpleRule) Save() (json.RawMessage, bool, error) {
	return nil, r.stale.Swap(false), nil
}

// Restore ignores the data saved under the rule id, by another kind of rule
// (e.g. a threshold rule changed to simple).
func (r *SimpleRule) Restore(data json.RawMessage, _ time.Time) (int, error) {
	if len(data) == 0 || string(data) == "null" {
		return 0, nil
	}
	r.stale.Store(true)
	return 0, ErrRuleChanged
}
