package systemd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"testing"
	"time"

	"wolverine/internal/source"
)

func entry(fields map[string]string) *source.Record {
	return &source.Record{
		Data:      []byte(fields["MESSAGE"]),
		Timestamp: time.Date(2026, 11, 8, 10, 1, 0, 0, time.Local),
		Source:    "sshd-journal",
		Fields:    fields,
	}
}

func TestParse(t *testing.T) {
	p := &Parser{Category: "system"}
	ev, err := p.Parse(entry(map[string]string{
		"MESSAGE":           "Failed password for root from 203.0.113.7 port 4242 ssh2",
		"_HOSTNAME":         "myhost",
		"SYSLOG_IDENTIFIER": "sshd-session",
		"_COMM":             "sshd-session",
		"SYSLOG_PID":        "42",
		"_PID":              "42",
		"PRIORITY":          "6",
		"SYSLOG_FACILITY":   "10",
		"_SYSTEMD_UNIT":     "sshd.service",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Source != "sshd-journal" || ev.Hostname != "myhost" || ev.Service != "sshd-session" ||
		ev.Severity != "info" || ev.Category != "system" ||
		ev.Message != "Failed password for root from 203.0.113.7 port 4242 ssh2" {
		t.Errorf("unexpected event: %+v", ev)
	}
	if ev.Fields["pid"] != "42" || ev.Fields["facility"] != "authpriv" || ev.Fields["unit"] != "sshd.service" {
		t.Errorf("unexpected fields: %v", ev.Fields)
	}
	if want := "Nov  8 10:01:00 myhost sshd-session[42]: Failed password for root from 203.0.113.7 port 4242 ssh2"; ev.Raw != want {
		t.Errorf("raw:\n got %q\nwant %q", ev.Raw, want)
	}
}

func TestParseFallbacks(t *testing.T) {
	ev, err := (&Parser{}).Parse(entry(map[string]string{"MESSAGE": "hello", "_COMM": "myd", "_PID": "7", "PRIORITY": "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Service != "myd" || ev.Fields["pid"] != "7" || ev.Severity != "" {
		t.Errorf("unexpected event: %+v", ev)
	}
}

func TestParseRegexp(t *testing.T) {
	p := &Parser{Regexp: regexp.MustCompile(`^Failed (?P<auth_method>\S+) for (?P<username>\S+) from (?P<source_ip>\S+)`)}
	ev, _ := p.Parse(entry(map[string]string{"MESSAGE": "Failed password for root from 203.0.113.7 port 4242 ssh2"}))
	if ev.Username != "root" || ev.SourceIP != "203.0.113.7" || ev.Fields["auth_method"] != "password" {
		t.Errorf("unexpected event: %+v", ev)
	}
	// Not matching the optional regexp is not an error.
	ev, err := p.Parse(entry(map[string]string{"MESSAGE": "Server listening on :: port 22."}))
	if err != nil || ev.Message != "Server listening on :: port 22." {
		t.Errorf("got %+v, %v", ev, err)
	}
}

func TestParseNotJournal(t *testing.T) {
	if _, err := (&Parser{}).Parse(&source.Record{Data: []byte("x")}); err == nil {
		t.Fatal("expected an error for a record without journal fields")
	}
}

// The tests below read the real journal of this machine.

func TestReadUnknownUnit(t *testing.T) {
	s := &Journal{ID: "x", Unit: "wolverine-does-not-exist.service"}
	if err := s.Open(context.Background()); err != nil {
		t.Skipf("journal not available: %v", err)
	}
	defer s.Close()
	if _, err := s.Read(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}

func TestReadFollowCancel(t *testing.T) {
	s := &Journal{ID: "x", Unit: "wolverine-does-not-exist.service", Follow: true, StartAtEnd: true, Poll: 20 * time.Millisecond}
	if err := s.Open(context.Background()); err != nil {
		t.Skipf("journal not available: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.Read(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the context error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cancellation took %s", d)
	}
}

// TestReadUnit reads a few entries of a unit that logs on most machines.
func TestReadUnit(t *testing.T) {
	const unit = "systemd-journald.service"
	s := &Journal{ID: "x", Unit: unit}
	if err := s.Open(context.Background()); err != nil {
		t.Skipf("journal not available: %v", err)
	}
	defer s.Close()
	p := &Parser{}
	for i := range 3 {
		rec, err := s.Read(context.Background())
		if errors.Is(err, io.EOF) {
			if i == 0 {
				t.Skipf("no entry for %s readable by this user", unit)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		ev, err := p.Parse(rec)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Fields["unit"] != unit || ev.Timestamp.IsZero() || ev.Timestamp.After(time.Now()) {
			t.Errorf("unexpected event: %+v", ev)
		}
	}
}

// readCursors reads up to n entries and returns their positions.
func readCursors(t *testing.T, s *Journal, n int) []string {
	t.Helper()
	var cursors []string
	for range n {
		rec, err := s.Read(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		cursors = append(cursors, rec.Position.(Position).Cursor)
	}
	return cursors
}

func TestResume(t *testing.T) {
	const unit = "systemd-journald.service"
	ref := &Journal{ID: "x", Unit: unit}
	if err := ref.Open(context.Background()); err != nil {
		t.Skipf("journal not available: %v", err)
	}
	want := readCursors(t, ref, 4)
	ref.Close()
	if len(want) < 4 {
		t.Skipf("fewer than 4 entries for %s readable by this user", unit)
	}

	s := &Journal{ID: "x", Unit: unit}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := readCursors(t, s, 2)
	s.Close()
	pos, _ := json.Marshal(Position{Cursor: got[1]})

	// Resumes after the second entry, even with StartAtEnd.
	s = &Journal{ID: "x", Unit: unit, StartAtEnd: true}
	if err := s.Resume(pos); err != nil {
		t.Fatal(err)
	}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	got = append(got, readCursors(t, s, 2)...)
	s.Close()
	if !slices.Equal(got, want) {
		t.Errorf("entries read across the restart:\n got %v\nwant %v", got, want)
	}

	// An invalid cursor is ignored: start_at applies.
	s = &Journal{ID: "x", Unit: unit}
	s.Resume(json.RawMessage(`{"cursor": "garbage"}`))
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if first := readCursors(t, s, 1); len(first) != 1 || first[0] != want[0] {
		t.Errorf("with an invalid cursor: got %v, want the first entry %s", first, want[0])
	}
	s.Close()
}

func TestStartPosition(t *testing.T) {
	// A unit without entries: resume from the time it was opened.
	s := &Journal{ID: "x", Unit: "wolverine-does-not-exist.service", Follow: true, StartAtEnd: true}
	if err := s.Open(context.Background()); err != nil {
		t.Skipf("journal not available: %v", err)
	}
	pos, _ := s.Position()
	s.Close()
	if p, ok := pos.(Position); !ok || p.Cursor != "" || p.Since == 0 {
		t.Errorf("got %#v, want a Since position", pos)
	}

	// A unit with entries: resume after the last one.
	const unit = "systemd-journald.service"
	ref := &Journal{ID: "x", Unit: unit}
	ref.Open(context.Background())
	all := readCursors(t, ref, 1_000_000)
	ref.Close()
	if len(all) == 0 {
		t.Skipf("no entry for %s readable by this user", unit)
	}
	s = &Journal{ID: "x", Unit: unit, Follow: true, StartAtEnd: true}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	pos, _ = s.Position()
	s.Close()
	if p, ok := pos.(Position); !ok || p.Cursor != all[len(all)-1] {
		t.Errorf("got %#v, want the cursor of the last entry", pos)
	}

	// From the beginning there is nothing to save.
	s = &Journal{ID: "x", Unit: unit}
	s.Open(context.Background())
	pos, _ = s.Position()
	s.Close()
	if pos != nil {
		t.Errorf("got %#v, want nil", pos)
	}
}
