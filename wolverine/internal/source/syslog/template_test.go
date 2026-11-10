package syslog

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wolverine/internal/pathtemplate"
)

// clock is a settable clock, safe for the reading goroutine.
type clock struct{ t atomic.Pointer[time.Time] }

func newClock(s string) *clock {
	c := &clock{}
	c.set(s)
	return c
}

func (c *clock) set(s string) {
	t, err := time.ParseInLocation(time.DateTime, s, time.UTC)
	if err != nil {
		panic(err)
	}
	c.t.Store(&t)
}

func (c *clock) now() time.Time { return *c.t.Load() }

func templateSource(t *testing.T, path string, c *clock) *Files {
	t.Helper()
	tmpl, err := pathtemplate.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	return &Files{ID: "app", Template: tmpl, Location: time.UTC, Now: c.now}
}

func TestTemplateReadsTheDatedFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "app.log.2026-02-27"), "27\n")
	write(t, filepath.Join(dir, "app.log.2026-02-28"), "28\n")
	write(t, filepath.Join(dir, "app.log.2026-03-01"), "01\n")
	write(t, filepath.Join(dir, "app.log"), "current\n")

	// Yesterday's file, across the end of the month.
	s := templateSource(t, filepath.Join(dir, "app.log.${year}-${month}-${day-1}"), newClock("2026-03-01 08:00:00"))
	lines, _ := run(t, s, nil, -1)
	check(t, lines, "28")
}

func TestTemplateMissingFile(t *testing.T) {
	s := templateSource(t, filepath.Join(t.TempDir(), "app.log.${year}${month}${day}"), newClock("2026-11-10 08:00:00"))
	lines, _ := run(t, s, nil, -1)
	check(t, lines)
}

// When the date changes, the previous file is read to its end, then the new
// one from its beginning.
func TestTemplateFollowDateChange(t *testing.T) {
	dir := t.TempDir()
	day1 := filepath.Join(dir, "app-20261110.log")
	day2 := filepath.Join(dir, "app-20261111.log")
	write(t, day1, "old\n")
	c := newClock("2026-11-10 23:59:00")
	s := templateSource(t, filepath.Join(dir, "app-${year}${month}${day}.log"), c)
	s.Follow, s.StartAtEnd, s.Poll = true, true, 10*time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Open(ctx); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string)
	stopped := make(chan struct{})
	// Close once the reader has stopped: the source is not safe for
	// concurrent use.
	defer func() {
		cancel()
		for range lines {
		}
		<-stopped
		s.Close()
	}()
	go func() {
		defer close(stopped)
		defer close(lines)
		for {
			r, err := s.Read(ctx)
			if err != nil {
				return
			}
			if r.Data != nil {
				lines <- string(r.Data)
			}
		}
	}()
	expect := func(want string) {
		t.Helper()
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout waiting for %q", want)
		}
	}

	appendTo(t, day1, "10 a\n")
	expect("10 a") // "old" was skipped (start_at end)

	// Midnight: the new file does not exist yet, and the application writes
	// a last line to the old one.
	c.set("2026-11-11 00:00:01")
	appendTo(t, day1, "10 last\n")
	expect("10 last")
	write(t, day2, "11 a\n")
	expect("11 a") // read from its beginning
	appendTo(t, day2, "11 b\n")
	expect("11 b")
}

// After a restart on another day, the rest of the previous day's file is
// read, then the new file.
func TestTemplateResumeNextDay(t *testing.T) {
	dir := t.TempDir()
	day1 := filepath.Join(dir, "app-20261110.log")
	day2 := filepath.Join(dir, "app-20261111.log")
	tmpl := filepath.Join(dir, "app-${year}${month}${day}.log")
	write(t, day1, "a\nb\n")

	lines, saved := run(t, templateSource(t, tmpl, newClock("2026-11-10 22:00:00")), nil, -1)
	check(t, lines, "a", "b")

	appendTo(t, day1, "c\n")
	write(t, day2, "d\n")
	lines, _ = run(t, templateSource(t, tmpl, newClock("2026-11-11 09:00:00")), saved, -1)
	check(t, lines, "c", "d")
}
