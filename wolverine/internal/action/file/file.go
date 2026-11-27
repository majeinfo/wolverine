// Package file implements the file action: it appends the alerts to a file,
// as JSON lines or as text.
package file

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"
	"sync"
	"time"

	"wolverine/internal/event"
)

// The formats of the file.
const (
	JSON = "json"
	Text = "text"
)

// Perm is the permission of a file created by the action: the alerts may
// hold log lines that are not for everyone.
const Perm = 0o640

// File appends each alert to a file. The file is opened for each alert, so
// that it can be rotated (logrotate without copytruncate) and is created
// again if removed.
type File struct {
	ID     string
	Path   string
	Format string // JSON (default) or Text
	// MaxEvents limits the log lines of each alert (0: all of them).
	MaxEvents int

	mu sync.Mutex
}

func (f *File) Name() string { return f.ID }

// Check opens the file for writing, creating it if needed: a configuration
// error shows when wolverine starts, not at the first alert.
func (f *File) Check() error {
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, Perm)
	if err != nil {
		return err
	}
	return fh.Close()
}

// Execute appends the alert to the file, in one write.
func (f *File) Execute(_ context.Context, a *event.Alert) error {
	var b []byte
	if f.Format == Text {
		b = f.text(a)
	} else {
		var err error
		if b, err = f.json(a); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, Perm)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// json returns the alert as one JSON line, with at most MaxEvents events
// (then Metadata.events_total gives how many it had).
func (f *File) json(a *event.Alert) ([]byte, error) {
	if f.MaxEvents > 0 && len(a.Events) > f.MaxEvents {
		c := *a // shared with the other actions: not modified
		c.Events = a.Events[:f.MaxEvents]
		c.Metadata = maps.Clone(a.Metadata)
		if c.Metadata == nil {
			c.Metadata = map[string]any{}
		}
		c.Metadata["events_total"] = len(a.Events)
		a = &c
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// text returns the alert as a line, then its log lines (at most
// MaxEvents), indented:
//
//	2026-11-27T10:00:05+01:00 [HIGH] ssh-failed-logins-per-ip: Repeated failed SSH logins: 3 events for SourceIP=203.0.113.7 within 1m12s (alert 9f3c…)
//	    Nov 27 10:00:01 host sshd[812]: Failed password for root from 203.0.113.7 port 52214 ssh2
//	    ...
func (f *File) text(a *event.Alert) []byte {
	var b bytes.Buffer
	sev := strings.ToUpper(a.Severity)
	if sev == "" {
		sev = "-"
	}
	fmt.Fprintf(&b, "%s [%s] %s: %s (alert %s)\n", a.Timestamp.Format(time.RFC3339), oneLine(sev), oneLine(a.RuleID), oneLine(a.Message), a.ID)
	for i, ev := range a.Events {
		if f.MaxEvents > 0 && i == f.MaxEvents {
			fmt.Fprintf(&b, "    ... %d more\n", len(a.Events)-i)
			break
		}
		line := ev.Raw
		if line == "" {
			line = ev.Message
		}
		fmt.Fprintf(&b, "    %s\n", oneLine(line))
	}
	return b.Bytes()
}

// oneLine replaces the control characters of a value from a log by spaces:
// a crafted log line cannot add lines to the file, or escape sequences for
// the terminal that displays it.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
