package event

import "time"

type Alert struct {
	ID        string
	RuleID    string
	Timestamp time.Time

	Severity string
	Message  string

	Events   []*Event
	Metadata map[string]any
}
