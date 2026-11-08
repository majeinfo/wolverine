package detection

import "wolverine/internal/event"

// Rule inspects events one at a time and returns the alerts they trigger.
// Implementations must be safe for concurrent use.
type Rule interface {
	ID() string
	Evaluate(ev *event.Event) []*event.Alert
}
