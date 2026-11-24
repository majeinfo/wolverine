package event

import "time"

type Alert struct {
	ID     string
	RuleID string
	// Timestamp is the time of the event that raised the alert, from the
	// log.
	Timestamp time.Time
	// Start and End are the times of the oldest and newest events that
	// raised the alert, from the log: the time range that produced it.
	// Zero for an alert saved by an older version (see EventRange).
	Start time.Time `json:",omitzero"`
	End   time.Time `json:",omitzero"`

	Severity string
	Message  string

	// Events are the events that raised the alert, but those whose log
	// line was forgotten (older than the log TTL, or freed to save memory):
	// see Count. Left out of the JSON when empty.
	Events   []*Event `json:",omitempty"`
	Metadata map[string]any
}

// Count returns how many events raised the alert: its "count" metadata,
// which includes the events no longer kept, or else len(Events).
func (a *Alert) Count() int {
	switch n := a.Metadata["count"].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64: // read from JSON
		return int(n)
	}
	return len(a.Events)
}

// EventRange returns the time range of the events that raised the alert:
// Start and End, or else Timestamp.
func (a *Alert) EventRange() (start, end time.Time) {
	if a.Start.IsZero() || a.End.IsZero() {
		return a.Timestamp, a.Timestamp
	}
	return a.Start, a.End
}

// Trimmed returns a copy of the alert with only its last event (the one the
// actions use), or a itself if it has no more. a is not modified: it may be
// shared.
func (a *Alert) Trimmed() *Alert {
	if len(a.Events) <= 1 {
		return a
	}
	c := *a
	c.Events = []*Event{a.Events[len(a.Events)-1]} // a new array: the old one is freed
	return &c
}
