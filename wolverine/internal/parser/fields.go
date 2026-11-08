package parser

import "wolverine/internal/event"

// eventFields are the names, as used by the named groups of a regexp, of the
// Event fields that can be set from a string.
var eventFields = map[string]func(*event.Event, string){
	"hostname":  func(ev *event.Event, v string) { ev.Hostname = v },
	"service":   func(ev *event.Event, v string) { ev.Service = v },
	"category":  func(ev *event.Event, v string) { ev.Category = v },
	"severity":  func(ev *event.Event, v string) { ev.Severity = v },
	"source_ip": func(ev *event.Event, v string) { ev.SourceIP = v },
	"dest_ip":   func(ev *event.Event, v string) { ev.DestIP = v },
	"username":  func(ev *event.Event, v string) { ev.Username = v },
	"action":    func(ev *event.Event, v string) { ev.Action = v },
	"status":    func(ev *event.Event, v string) { ev.Status = v },
}

// SetField sets the Event field called name (hostname, service, source_ip...)
// or, for any other name, stores value in ev.Fields. Empty values are
// ignored.
func SetField(ev *event.Event, name, value string) {
	if value == "" {
		return
	}
	if set, ok := eventFields[name]; ok {
		set(ev, value)
		return
	}
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	ev.Fields[name] = value
}

var severities = [...]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

var facilities = [...]string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

// Severity returns the name of a syslog severity level (0 to 7).
func Severity(level int) (string, bool) {
	if level < 0 || level >= len(severities) {
		return "", false
	}
	return severities[level], true
}

// Facility returns the name of a syslog facility (0 to 23).
func Facility(n int) (string, bool) {
	if n < 0 || n >= len(facilities) {
		return "", false
	}
	return facilities[n], true
}
