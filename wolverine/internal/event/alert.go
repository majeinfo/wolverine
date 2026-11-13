package event

import "time"

type Alert struct {
	ID        string
	RuleID    string
	Timestamp time.Time

	Severity string
	Message  string

	// Events are the events that raised the alert. Left out of the JSON
	// when empty.
	Events   []*Event `json:",omitempty"`
	Metadata map[string]any
}
