// Package systemd implements the "systemd-service" source: it reads the
// entries that a systemd service wrote to the journal, through the
// sd-journal API (libsystemd, loaded at run time).
//
// Unlike a log file, the journal records who wrote each entry: _SYSTEMD_UNIT
// is set by journald and cannot be forged by the logging process, so another
// program cannot inject fake sshd lines the way "logger -t sshd" can in
// /var/log/messages.
package systemd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"wolverine/internal/event"
	"wolverine/internal/parser"
	"wolverine/internal/source"
	"wolverine/internal/verbose"
)

// ---------------------------------------------------------------------------
// Source: reading the journal
// ---------------------------------------------------------------------------

const defaultPoll = 500 * time.Millisecond

// Journal reads the journal entries of one systemd unit. It implements
// source.Source and source.Resumer: the Position of a record is the journal
// cursor of its entry.
//
// When Follow is set, Read waits for new entries instead of returning
// io.EOF. StartAtEnd skips the entries already in the journal.
type Journal struct {
	ID string
	// Unit is the full unit name, e.g. "sshd.service".
	Unit       string
	Follow     bool
	StartAtEnd bool
	Poll       time.Duration

	j      *sdjournal.Journal
	read   int
	resume Position // where the previous run stopped
	start  any      // where Open positioned the journal, for Positions()
}

// Position is where a Journal stopped: after the entry Cursor, or, when the
// unit had no entry yet, at the time Since (microseconds since the epoch).
type Position struct {
	Cursor string `json:"cursor,omitempty"`
	Since  uint64 `json:"since_usec,omitempty"`
}

func (s *Journal) Name() string { return s.ID }

// Resume takes the position saved under the key "": the journal is a single
// stream.
func (s *Journal) Resume(positions map[string]json.RawMessage) error {
	if p, ok := positions[""]; ok {
		return json.Unmarshal(p, &s.resume)
	}
	return nil
}

func (s *Journal) Positions() (map[string]any, error) {
	if s.start == nil {
		return nil, nil
	}
	return map[string]any{"": s.start}, nil
}

func (s *Journal) Open(ctx context.Context) error {
	j, err := sdjournal.NewJournal()
	if err != nil {
		return err
	}
	if err := j.AddMatch(sdjournal.SD_JOURNAL_FIELD_SYSTEMD_UNIT + "=" + s.Unit); err != nil {
		j.Close()
		return err
	}
	s.j = j
	if err := s.seek(); err != nil {
		j.Close()
		s.j = nil
		return err
	}
	return nil
}

// seek positions the journal after the entry processed last by the previous
// run, or according to StartAtEnd when there is none.
func (s *Journal) seek() error {
	switch {
	case s.resume.Cursor != "":
		err := s.seekAfter(s.resume.Cursor)
		if err == nil {
			verbose.Infof("source %s: resuming the journal of %s after the last entry processed", s.ID, s.Unit)
			return nil
		}
		log.Printf("source %s: invalid saved cursor, ignored: %v", s.ID, err)
	case s.resume.Since != 0:
		verbose.Infof("source %s: resuming the journal of %s at %s", s.ID, s.Unit, time.UnixMicro(int64(s.resume.Since)).Format(time.DateTime))
		s.start = s.resume
		return s.j.SeekRealtimeUsec(s.resume.Since)
	}

	if s.StartAtEnd {
		verbose.Debugf("source %s: journal of %s opened at the end", s.ID, s.Unit)
		// After SeekTail, Next would return nothing until a new entry is
		// written; stepping back once makes Next return the first new one.
		if err := s.j.SeekTail(); err != nil {
			return err
		}
		n, err := s.j.Previous()
		if err != nil {
			return err
		}
		if n > 0 {
			// On the last entry: resume after it next time.
			cursor, err := s.j.GetCursor()
			if err != nil {
				return err
			}
			s.start = Position{Cursor: cursor}
		} else {
			// No entry yet for the unit: resume from now next time.
			s.start = Position{Since: uint64(time.Now().UnixMicro())}
		}
		return nil
	}
	verbose.Debugf("source %s: journal of %s opened at the beginning", s.ID, s.Unit)
	return s.j.SeekHead()
}

// seekAfter positions the journal so that Next returns the entry following
// the one at cursor.
func (s *Journal) seekAfter(cursor string) error {
	if err := s.j.SeekCursor(cursor); err != nil {
		return err
	}
	n, err := s.j.Next()
	if err != nil || n == 0 {
		return err
	}
	if s.j.TestCursor(cursor) == nil {
		s.start = Position{Cursor: cursor}
	} else {
		// The entry is gone (journal vacuumed): the journal is now on the
		// closest entry, which has not been read yet. Step back so that
		// Next returns it.
		verbose.Infof("source %s: the saved cursor's entry is no longer in the journal, resuming at the next one", s.ID)
		_, err = s.j.Previous()
	}
	return err
}

func (s *Journal) Close() error {
	if s.j == nil {
		return nil
	}
	err := s.j.Close()
	s.j = nil
	return err
}

// Read returns the next journal entry of the unit. At the end of the journal
// it returns io.EOF, unless Follow is set.
func (s *Journal) Read(ctx context.Context) (*source.Record, error) {
	poll := s.Poll
	if poll <= 0 {
		poll = defaultPoll
	}
	for {
		n, err := s.j.Next()
		if err != nil {
			return nil, err
		}
		if n > 0 {
			e, err := s.j.GetEntry()
			if err != nil {
				return nil, err
			}
			s.read++
			return &source.Record{
				Data:      []byte(e.Fields[sdjournal.SD_JOURNAL_FIELD_MESSAGE]),
				Timestamp: time.UnixMicro(int64(e.RealtimeTimestamp)),
				Source:    s.ID,
				Fields:    e.Fields,
				Position:  Position{Cursor: e.Cursor},
			}, nil
		}

		if !s.Follow {
			if s.read == 0 && s.start == nil {
				verbose.Infof("source %s: no journal entry for unit %s (the system journal is only readable by root and the systemd-journal, adm and wheel groups)", s.ID, s.Unit)
			}
			return nil, io.EOF
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Returns as soon as the journal changes, or after poll so that a
		// cancelled ctx is noticed.
		s.j.Wait(poll)
	}
}

// ---------------------------------------------------------------------------
// Parser: turning a journal entry into an event
// ---------------------------------------------------------------------------

// Parser builds events from the structured fields of journal entries:
//
//   - MESSAGE: Message
//   - _HOSTNAME: Hostname
//   - SYSLOG_IDENTIFIER (or _COMM): Service, e.g. "sshd-session"
//   - PRIORITY, SYSLOG_FACILITY: Severity and Fields["facility"]
//   - SYSLOG_PID (or _PID): Fields["pid"]
//   - _SYSTEMD_UNIT: Fields["unit"]
//
// When Regexp is set, it is applied to the message and its named groups fill
// the event like for the logfile source; "message" replaces the message.
// The regexp is optional and a message that does not match it is not an
// error, since the journal fields are already parsed.
//
// Parser implements parser.Parser.
type Parser struct {
	Regexp   *regexp.Regexp
	Category string
}

func (p *Parser) Name() string { return "journal" }

func (p *Parser) Parse(rec *source.Record) (*event.Event, error) {
	f := rec.Fields
	if f == nil {
		return nil, errors.New("not a journal entry")
	}
	msg := f[sdjournal.SD_JOURNAL_FIELD_MESSAGE]
	ev := &event.Event{
		ID:        newID(),
		Timestamp: rec.Timestamp,
		Source:    rec.Source,
		Category:  p.Category,
		Hostname:  f[sdjournal.SD_JOURNAL_FIELD_HOSTNAME],
		Service:   first(f[sdjournal.SD_JOURNAL_FIELD_SYSLOG_IDENTIFIER], f[sdjournal.SD_JOURNAL_FIELD_COMM]),
		Message:   msg,
		Fields:    map[string]any{},
	}
	pid := first(f[sdjournal.SD_JOURNAL_FIELD_SYSLOG_PID], f[sdjournal.SD_JOURNAL_FIELD_PID])
	parser.SetField(ev, "pid", pid)
	parser.SetField(ev, "unit", f[sdjournal.SD_JOURNAL_FIELD_SYSTEMD_UNIT])
	if n, err := strconv.Atoi(f[sdjournal.SD_JOURNAL_FIELD_PRIORITY]); err == nil {
		ev.Severity, _ = parser.Severity(n)
	}
	if n, err := strconv.Atoi(f[sdjournal.SD_JOURNAL_FIELD_SYSLOG_FACILITY]); err == nil {
		if name, ok := parser.Facility(n); ok {
			ev.Fields["facility"] = name
		}
	}

	// Raw looks like the line journalctl (and /var/log/messages) shows.
	ident := ev.Service
	if pid != "" {
		ident += "[" + pid + "]"
	}
	ev.Raw = fmt.Sprintf("%s %s %s: %s", ev.Timestamp.Format(time.Stamp), ev.Hostname, ident, msg)

	if p.Regexp != nil {
		if m := p.Regexp.FindStringSubmatch(msg); m != nil {
			for i, name := range p.Regexp.SubexpNames() {
				switch name {
				case "":
				case "message":
					ev.Message = m[i]
				default:
					parser.SetField(ev, name, m[i])
				}
			}
		}
	}
	return ev, nil
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
