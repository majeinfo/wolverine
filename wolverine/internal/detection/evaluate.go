package detection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"

	"wolverine/internal/event"
)

// Match selects events. Empty criteria match anything.
type Match struct {
	Category string
	Service  string
	Action   string
	Status   string
	// HasFields lists keys that must be present in Event.Fields.
	HasFields []string
	// MatchIf, if set, keeps only the events for which it returns true. It
	// is called after the other criteria.
	MatchIf func(*event.Event) bool
	// Exclude lists the exclude lists whose events are ignored (see
	// Event.ExcludedBy).
	Exclude []string
	// ExcludeIf, if set, ignores the events for which it returns true. It
	// is called last, only for the events that match otherwise.
	ExcludeIf func(*event.Event) bool
}

func (m Match) Matches(ev *event.Event) bool {
	if m.Category != "" && ev.Category != m.Category {
		return false
	}
	if m.Service != "" && ev.Service != m.Service {
		return false
	}
	if m.Action != "" && ev.Action != m.Action {
		return false
	}
	if m.Status != "" && ev.Status != m.Status {
		return false
	}
	for _, k := range m.HasFields {
		if _, ok := ev.Fields[k]; !ok {
			return false
		}
	}
	for _, id := range ev.ExcludedBy {
		if slices.Contains(m.Exclude, id) {
			return false
		}
	}
	if m.MatchIf != nil && !m.MatchIf(ev) {
		return false
	}
	if m.ExcludeIf != nil && m.ExcludeIf(ev) {
		return false
	}
	return true
}

// FieldValue returns an event attribute by name: one of the Event struct
// field names (SourceIP, Username, ...) or else a key of Event.Fields.
func FieldValue(ev *event.Event, name string) string {
	switch name {
	case "Source":
		return ev.Source
	case "Category":
		return ev.Category
	case "Severity":
		return ev.Severity
	case "Hostname":
		return ev.Hostname
	case "Service":
		return ev.Service
	case "SourceIP":
		return ev.SourceIP
	case "DestIP":
		return ev.DestIP
	case "Username":
		return ev.Username
	case "Action":
		return ev.Action
	case "Status":
		return ev.Status
	}
	if v, ok := ev.Fields[name]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
