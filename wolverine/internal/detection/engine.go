package detection

import "wolverine/internal/event"

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
