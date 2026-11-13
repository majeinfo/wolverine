package detection

import (
	"time"

	"wolverine/internal/event"
)

// Rule inspects events one at a time and returns the alerts they trigger.
// Implementations must be safe for concurrent use.
type Rule interface {
	ID() string
	Evaluate(ev *event.Event) []*event.Alert
	// Expire forgets the data memorized before cutoff (wall clock), so no
	// data outlives the maximum lifetime, and returns how many items were
	// forgotten.
	Expire(cutoff time.Time) int
}
