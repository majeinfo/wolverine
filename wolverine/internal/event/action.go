package event

import "time"

// The statuses of an ActionRun.
const (
	// ActionOK: the action ran and succeeded.
	ActionOK = "ok"
	// ActionFailed: the action ran and failed (see Error). For an undo
	// action, Due is when it is tried again, if it is.
	ActionFailed = "failed"
	// ActionDropped: the action did not run, as the queue of the actions
	// was full.
	ActionDropped = "dropped"
	// ActionPlanned: the undo action will run at Due.
	ActionPlanned = "planned"
	// ActionPostponed: the undo action planned for this alert will run
	// for a later alert instead (see Detail), as the same thing was done
	// again.
	ActionPostponed = "postponed"
	// ActionSkipped: the undo action will not run (see Detail), e.g. it is
	// no longer configured.
	ActionSkipped = "skipped"
)

// ActionRun is something that happened to an action of an alert: it ran,
// or an undo was planned... An alert's runs make its action log.
type ActionRun struct {
	Time time.Time
	// Action is the id of the action.
	Action string
	// UndoOf is, for an undo action, the id of the action it undoes.
	UndoOf string `json:",omitempty"`
	Status string
	// Due is when an undo action is planned to run.
	Due time.Time `json:",omitzero"`
	// Duration is how long the action ran.
	Duration time.Duration `json:",omitempty"`
	Error    string        `json:",omitempty"`
	Detail   string        `json:",omitempty"`
}

// Reporter is told what happened to the actions of an alert.
type Reporter func(alertID string, run ActionRun)
