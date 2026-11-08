package detection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

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
