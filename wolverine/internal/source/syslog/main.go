// Package syslog implements the "logfile" source: it reads log files such
// as /var/log/messages line by line (a single file, or the files of a
// directory whose names match a regexp), optionally following them like
// tail -F, and parses each line into an event with a configurable regular
// expression.
package syslog

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"wolverine/internal/event"
	"wolverine/internal/parser"
	"wolverine/internal/source"
)

func trimEOL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// Parser: turning a line into an event
// ---------------------------------------------------------------------------

// ErrNoMatch is returned when a line does not match the regular expression.
var ErrNoMatch = errors.New("line does not match the regexp")

// Named groups of the regexp fill the Event fields of the same name (see
// parser.SetField). "timestamp" is parsed with TimestampFormats and "pri"
// (syslog priority) sets Severity and the "facility" field. Any other named
// group is stored in Event.Fields. When "timestamp" is missing or empty,
// "date" and "time" (both set) give the event time instead: they are joined
// by a space and parsed with TimestampFormats, then with DateTimeLayouts.

// Parser parses lines with a regular expression. It implements
// parser.Parser.
//
// The "message" group sets Event.Message; without it, the whole line is the
// message. Without a "timestamp" group (or "date" and "time" groups), the
// time the line was read is used.
type Parser struct {
	Regexp   *regexp.Regexp
	Category string
	// TimestampFormats are tried in order: "rfc3164" (Jan _2 15:04:05),
	// "rfc3339", or a Go time layout. When the parsed date has no year (as
	// in rfc3164), the current year is assumed, or the previous one if that
	// would put the date in the future.
	TimestampFormats []string
	Location         *time.Location
	Now              func() time.Time
}

// TimestampLayout returns the Go time layout for a timestamp format.
func TimestampLayout(format string) (string, error) {
	switch format {
	case "rfc3164":
		return time.Stamp, nil
	case "rfc3339":
		return time.RFC3339Nano, nil
	case "":
		return "", errors.New("empty timestamp format")
	default:
		return format, nil
	}
}

// DateTimeLayouts are tried, after the TimestampFormats, on the "date" and
// "time" groups joined by a space: an ISO date and a time, such as
// "2026-11-08 10:12:01" in the CloudFront and W3C (IIS) logs. A fractional
// second is accepted.
var DateTimeLayouts = []string{"2006-01-02 15:04:05", "2006-01-02 15:04:05Z07:00"}

func (p *Parser) Name() string { return "regexp" }

// Parse parses one line. When the line cannot be parsed, a minimal event
// carrying the raw line is returned along with the error, so that no data is
// lost.
func (p *Parser) Parse(rec *source.Record) (*event.Event, error) {
	line := string(rec.Data)
	ev := &event.Event{
		ID:        newID(),
		Timestamp: rec.Timestamp,
		Source:    rec.Source,
		Category:  p.Category,
		Message:   line,
		Raw:       line,
		Fields:    map[string]any{},
	}

	if f := rec.Fields["file"]; f != "" {
		ev.Fields["file"] = f
	}

	m := p.Regexp.FindStringSubmatch(line)
	if m == nil {
		ev.Fields["parse_error"] = ErrNoMatch.Error()
		return ev, ErrNoMatch
	}

	var ts, date, clock string
	for i, name := range p.Regexp.SubexpNames() {
		if name == "" {
			continue
		}
		v := m[i]
		switch name {
		case "message":
			ev.Message = v
		case "timestamp":
			ts = v
		case "date":
			date = v
			parser.SetField(ev, name, v)
		case "time":
			clock = v
			parser.SetField(ev, name, v)
		case "pri":
			if pri, err := strconv.Atoi(v); err == nil && pri >= 0 && pri <= 191 {
				ev.Severity, _ = parser.Severity(pri % 8)
				ev.Fields["facility"], _ = parser.Facility(pri / 8)
			}
		default:
			parser.SetField(ev, name, v)
		}
	}

	if ts != "" || (date != "" && clock != "") {
		t, err := p.parseTime(ts)
		if ts == "" {
			t, err = p.parseDateTime(date, clock)
		}
		if err != nil {
			ev.Fields["parse_error"] = err.Error()
			return ev, err
		}
		ev.Timestamp = t
	}
	return ev, nil
}

func (p *Parser) parseTime(s string) (time.Time, error) {
	if t, ok := p.parse(s, p.TimestampFormats); ok {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("timestamp %q does not match %v", s, p.TimestampFormats)
}

// parseDateTime parses the "date" and "time" groups, joined by a space.
func (p *Parser) parseDateTime(date, clock string) (time.Time, error) {
	s := date + " " + clock
	if t, ok := p.parse(s, p.TimestampFormats); ok {
		return t, nil
	}
	if t, ok := p.parse(s, DateTimeLayouts); ok {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("date and time %q do not match %v", s, append(slices.Clip(p.TimestampFormats), DateTimeLayouts...))
}

// parse parses s with the first format that matches it.
func (p *Parser) parse(s string, formats []string) (time.Time, bool) {
	loc := p.Location
	if loc == nil {
		loc = time.Local
	}
	for _, f := range formats {
		layout, err := TimestampLayout(f)
		if err != nil {
			continue
		}
		t, err := time.ParseInLocation(layout, s, loc)
		if err != nil {
			continue
		}
		if t.Year() == 0 {
			t = p.withYear(t, loc)
		}
		return t, true
	}
	return time.Time{}, false
}

// withYear sets the year of a date that has none: the current year, unless
// it puts the date in the future (e.g. December logs read in January).
func (p *Parser) withYear(t time.Time, loc *time.Location) time.Time {
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	now = now.In(loc)
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
