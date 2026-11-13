package action

import (
	"context"
	"log"
	"sync"
	"time"

	"wolverine/internal/event"
	"wolverine/internal/verbose"
)

// Dispatcher runs the actions attached to each alert's rule in a background
// goroutine, so that a slow action (e.g. an SMTP server) does not block
// detection. When the queue is full, alerts are dropped and logged.
type Dispatcher struct {
	routes map[string][]Action
	undo   *Scheduler
	queue  chan *event.Alert
	wg     sync.WaitGroup
}

// NewDispatcher starts a dispatcher. routes maps a rule id to its actions.
// The actions that succeed are given to undo, if not nil, to be undone
// later.
func NewDispatcher(ctx context.Context, routes map[string][]Action, queueSize int, undo *Scheduler) *Dispatcher {
	d := &Dispatcher{routes: routes, undo: undo, queue: make(chan *event.Alert, queueSize)}
	d.wg.Add(1)
	go d.run(ctx)
	return d
}

func (d *Dispatcher) Dispatch(a *event.Alert) {
	if len(d.routes[a.RuleID]) == 0 {
		verbose.Debugf("alert %s (%s): no enabled action", a.ID, a.RuleID)
		return
	}
	select {
	case d.queue <- a:
	default:
		log.Printf("action queue full, alert %s (%s) dropped", a.ID, a.RuleID)
	}
}

// Close waits for the queued alerts to be processed.
func (d *Dispatcher) Close() {
	close(d.queue)
	d.wg.Wait()
}

func (d *Dispatcher) run(ctx context.Context) {
	defer d.wg.Done()
	for a := range d.queue {
		for _, act := range d.routes[a.RuleID] {
			verbose.Debugf("action %s: running for alert %s (%s)", act.Name(), a.ID, a.RuleID)
			start := time.Now()
			if err := act.Execute(ctx, a); err != nil {
				log.Printf("action %s for alert %s (%s): %v", act.Name(), a.ID, a.RuleID, err)
				continue
			}
			verbose.Infof("action %s: done for alert %s (%s) in %s", act.Name(), a.ID, a.RuleID, time.Since(start).Round(time.Millisecond))
			d.undo.Schedule(act.Name(), a)
		}
	}
}
