package detection

import (
	"time"

	"wolverine/internal/event"
)

// Engine runs every rule against each event.
type Engine struct {
	Rules []Rule
}

func (e *Engine) Evaluate(ev *event.Event) []*event.Alert {
	var alerts []*event.Alert
	for _, r := range e.Rules {
		alerts = append(alerts, r.Evaluate(ev)...)
	}
	return alerts
}

// Expire makes every rule forget the data memorized before cutoff, and
// returns how many items were forgotten.
func (e *Engine) Expire(cutoff time.Time) int {
	n := 0
	for _, r := range e.Rules {
		n += r.Expire(cutoff)
	}
	return n
}
