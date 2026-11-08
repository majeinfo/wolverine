package event

import "time"

type Event struct {
	ID        string
	Timestamp time.Time

	Source   string
	Category string
	Severity string

	Hostname string
	Service  string

	SourceIP string
	DestIP   string

	Username string
	Action   string
	Status   string

	Message string

	Fields map[string]any

	Raw string
}
