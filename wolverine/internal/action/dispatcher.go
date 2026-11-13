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
	report event.Reporter
	queue  chan *event.Alert
	wg     sync.WaitGroup
}

// NewDispatcher starts a dispatcher. routes maps a rule id to its actions.
// The actions that succeed are given to undo, if not nil, to be undone
// later. report, if not nil, is told how each action went.
func NewDispatcher(ctx context.Context, routes map[string][]Action, queueSize int, undo *Scheduler, report event.Reporter) *Dispatcher {
	d := &Dispatcher{routes: routes, undo: undo, report: report, queue: make(chan *event.Alert, queueSize)}
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
		for _, act := range d.routes[a.RuleID] {
			d.reportRun(a.ID, event.ActionRun{Time: time.Now(), Action: act.Name(), Status: event.ActionDropped, Detail: "the queue of the actions was full"})
		}
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
			err := act.Execute(ctx, a)
			run := event.ActionRun{Time: time.Now(), Action: act.Name(), Status: event.ActionOK, Duration: time.Since(start).Round(time.Millisecond)}
			if err != nil {
				log.Printf("action %s for alert %s (%s): %v", act.Name(), a.ID, a.RuleID, err)
				run.Status, run.Error = event.ActionFailed, err.Error()
				d.reportRun(a.ID, run)
				continue
			}
			verbose.Infof("action %s: done for alert %s (%s) in %s", act.Name(), a.ID, a.RuleID, run.Duration)
			d.reportRun(a.ID, run)
			d.undo.Schedule(act.Name(), a)
		}
	}
}

func (d *Dispatcher) reportRun(alertID string, run event.ActionRun) {
	if d.report != nil {
		d.report(alertID, run)
	}
}
