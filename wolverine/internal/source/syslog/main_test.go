package syslog

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"wolverine/internal/source"
)

// Same regexp as in config/wolverine.yaml.
const syslogRegexp = `^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+) (?P<hostname>\S+) (?:(?P<service>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?)?(?P<message>.*)$`

var paris = mustLoad("Europe/Paris")

func mustLoad(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return loc
}

func syslogParser() *Parser {
	return &Parser{
		Regexp:           regexp.MustCompile(syslogRegexp),
		Category:         "system",
		TimestampFormats: []string{"rfc3164", "rfc3339"},
		Location:         paris,
		Now:              func() time.Time { return time.Date(2026, 11, 8, 12, 0, 0, 0, paris) },
	}
}

func rec(line string) *source.Record {
	return &source.Record{Data: []byte(line), Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Source: "messages"}
}

func TestParseSyslog(t *testing.T) {
	p := syslogParser()
	tests := []struct {
		line                                   string
		ts                                     time.Time
		host, service, msg, severity, facility string
		pid                                    any
	}{
		{"Nov  8 10:12:01 myhost sshd[1234]: Accepted password for jd from 10.0.0.1 port 2222 ssh2",
			time.Date(2026, 11, 8, 10, 12, 1, 0, paris), "myhost", "sshd", "Accepted password for jd from 10.0.0.1 port 2222 ssh2", "", "", "1234"},
		{"<38>Dec 31 23:59:59 myhost postfix/smtpd[99]: connect from x",
			time.Date(2025, 12, 31, 23, 59, 59, 0, paris), "myhost", "postfix/smtpd", "connect from x", "info", "auth", "99"},
		{"2026-11-08T10:12:01.123456+01:00 web01 kernel: Out of memory",
			time.Date(2026, 11, 8, 10, 12, 1, 123456000, paris), "web01", "kernel", "Out of memory", "", "", nil},
		{"Nov  8 10:13:00 myhost systemd: Started foo.",
			time.Date(2026, 11, 8, 10, 13, 0, 0, paris), "myhost", "systemd", "Started foo.", "", "", nil},
		{"Nov  8 10:14:00 myhost no tag here",
			time.Date(2026, 11, 8, 10, 14, 0, 0, paris), "myhost", "", "no tag here", "", "", nil},
	}
	for _, tt := range tests {
		ev, err := p.Parse(rec(tt.line))
		if err != nil {
			t.Errorf("%q: %v", tt.line, err)
			continue
		}
		if !ev.Timestamp.Equal(tt.ts) || ev.Hostname != tt.host || ev.Service != tt.service || ev.Message != tt.msg || ev.Severity != tt.severity {
			t.Errorf("%q:\ngot  ts=%s host=%q service=%q msg=%q severity=%q", tt.line, ev.Timestamp, ev.Hostname, ev.Service, ev.Message, ev.Severity)
		}
		if ev.Fields["pid"] != tt.pid {
			t.Errorf("%q: pid=%v, want %v", tt.line, ev.Fields["pid"], tt.pid)
		}
		if f, _ := ev.Fields["facility"].(string); f != tt.facility {
			t.Errorf("%q: facility=%q, want %q", tt.line, f, tt.facility)
		}
		if ev.Source != "messages" || ev.Category != "system" || ev.Raw != tt.line || ev.ID == "" {
			t.Errorf("%q: unexpected event %+v", tt.line, ev)
		}
	}
}

func TestParseNoMatch(t *testing.T) {
	r := rec("not a syslog line")
	ev, err := syslogParser().Parse(r)
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("got %v, want ErrNoMatch", err)
	}
	if ev == nil || ev.Message != "not a syslog line" || ev.Raw != "not a syslog line" || !ev.Timestamp.Equal(r.Timestamp) || ev.Fields["parse_error"] == nil {
		t.Errorf("unexpected fallback event: %+v", ev)
	}
}

func TestParseBadTimestamp(t *testing.T) {
	_, err := syslogParser().Parse(rec("2026-13-45T99:00:00Z host svc: msg"))
	if err == nil {
		t.Fatal("expected a timestamp error")
	}
}

// Any log format can be parsed: here an Apache/nginx access log with a Go
// layout and custom groups.
func TestParseCustomFormat(t *testing.T) {
	p := &Parser{
		Regexp:           regexp.MustCompile(`^(?P<source_ip>\S+) \S+ (?P<username>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3})`),
		TimestampFormats: []string{"02/Jan/2006:15:04:05 -0700"},
		Category:         "web",
	}
	ev, err := p.Parse(rec(`203.0.113.7 - alice [08/Nov/2026:10:12:01 +0100] "GET /admin HTTP/1.1" 403 512`))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 8, 10, 12, 1, 0, time.FixedZone("", 3600))
	if !ev.Timestamp.Equal(want) || ev.SourceIP != "203.0.113.7" || ev.Username != "alice" || ev.Status != "403" ||
		ev.Fields["method"] != "GET" || ev.Fields["path"] != "/admin" || ev.Category != "web" {
		t.Errorf("unexpected event: %+v", ev)
	}
	// No message group: the message is the whole line.
	if ev.Message != ev.Raw {
		t.Errorf("message = %q, want the whole line", ev.Message)
	}
}

func readAll(t *testing.T, s *Files) []string {
	t.Helper()
	var lines []string
	for {
		r, err := s.Read(context.Background())
		if errors.Is(err, io.EOF) {
			return lines
		}
		if err != nil {
			t.Fatal(err)
		}
		if r.Data == nil {
			continue
		}
		lines = append(lines, string(r.Data))
	}
}

func TestFileRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	os.WriteFile(path, []byte("line 1\nline 2\r\n\nlast line without newline"), 0o644)

	s := &Files{ID: "messages", Path: path}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := readAll(t, s)
	want := []string{"line 1", "line 2", "", "last line without newline"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestFileOpenMissing(t *testing.T) {
	s := &Files{Path: filepath.Join(t.TempDir(), "nope")}
	if err := s.Open(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// follow mode: new lines, rotation and truncation; start_at end.
func TestFileFollow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	os.WriteFile(path, []byte("old line\n"), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := &Files{ID: "messages", Path: path, Follow: true, StartAtEnd: true, Poll: 10 * time.Millisecond}
	if err := s.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	lines := make(chan string)
	go func() {
		for {
			r, err := s.Read(ctx)
			if err != nil {
				close(lines)
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
	appendLine := func(line string) {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString(line)
		f.Close()
	}

	appendLine("new line\n")
	expect("new line") // "old line" was skipped (start_at end)

	appendLine("before rotation\n")
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("after rotation\n"), 0o644)
	expect("before rotation")
	expect("after rotation")

	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte("truncated\n"), 0o644) // shorter: truncation
	expect("truncated")

	cancel()
	for range lines {
	}
}
