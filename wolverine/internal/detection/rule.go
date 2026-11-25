package detection

import (
	"encoding/json"
	"errors"
	"time"

	"wolverine/internal/event"
)

// Rule inspects events one at a time and returns the alerts they trigger.
// Implementations must be safe for concurrent use.
type Rule interface {
	ID() string
	// Process tells whether the rule matched (counted) the event, and
	// returns the alerts it raised.
	Process(ev *event.Event) (matched bool, alerts []*event.Alert)
	// Expire forgets the data memorized before cutoff (wall clock), so no
	// data outlives the maximum lifetime, and returns how many items were
	// forgotten.
	Expire(cutoff time.Time) int
	// Trim forgets the log lines (the events) whose time, from the log, is
	// before cutoff, but not what the rule needs to evaluate the next ones
	// (their times), and returns how many were forgotten.
	Trim(cutoff time.Time) int
	// Save returns the data memorized by the rule, to restore after a
	// restart, and whether it changed since the previous call (or since
	// Restore).
	Save() (json.RawMessage, bool, error)
	// Restore loads the data saved by Save, except what was memorized
	// before cutoff, and returns how many items were restored. It restores
	// nothing if the data was saved by a different rule (see Signature).
	Restore(data json.RawMessage, cutoff time.Time) (int, error)
}

// ErrRuleChanged is returned by Restore when the data was saved by a
// different version of the rule: it would not count the same events.
var ErrRuleChanged = errors.New("the rule changed since the data was saved")
