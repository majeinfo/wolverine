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
	_, alerts := e.Process(ev)
	return alerts
}

// Process runs every rule against an event, and returns the ids of the rules
// that matched it and the alerts raised.
func (e *Engine) Process(ev *event.Event) (matched []string, alerts []*event.Alert) {
	for _, r := range e.Rules {
		m, a := r.Process(ev)
		if m {
			matched = append(matched, r.ID())
		}
		alerts = append(alerts, a...)
	}
	return matched, alerts
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

// Trim makes every rule forget the log lines whose time (from the log) is
// before cutoff, and returns how many were forgotten.
func (e *Engine) Trim(cutoff time.Time) int {
	n := 0
	for _, r := range e.Rules {
		n += r.Trim(cutoff)
	}
	return n
}
