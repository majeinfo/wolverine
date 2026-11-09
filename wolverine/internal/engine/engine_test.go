package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wolverine/internal/config"
	"wolverine/internal/event"
	"wolverine/internal/source/syslog"
)

// The shipped configuration, with its source pointed at a test file, must
// parse syslog lines, enrich sshd events and raise the brute-force alert.
func TestRunShippedConfig(t *testing.T) {
	var log strings.Builder
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&log, "Nov  8 10:0%d:00 myhost sshd[%d]: Failed password for root from 203.0.113.7 port 4%d ssh2\n", i, i, i)
		fmt.Fprintf(&log, "Nov  8 10:0%d:00 myhost sshd[%d]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root\n", i, i)
	}
	log.WriteString("garbage line\n")
	path := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(path, []byte(log.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load("../../config/wolverine.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Only the log file source: the others (journal) depend on the machine
	// and may follow forever.
	var messages config.Source
	for _, src := range cfg.Sources {
		if src.ID == "messages" {
			messages = src
		}
	}
	messages.Path, messages.Follow, messages.StartAt, messages.Disabled = path, false, "", false
	cfg.Sources = []config.Source{messages}
	cfg.StateFile = ""

	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out, events bytes.Buffer
	eng.Alerts = &out
	eng.Events = &events
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	var alerts []event.Alert
	dec := json.NewDecoder(&out)
	for dec.More() {
		var a event.Alert
		if err := dec.Decode(&a); err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, a)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1:\n%s", len(alerts), out.String())
	}
	a := alerts[0]
	if a.RuleID != "ssh-failed-logins-per-ip" || len(a.Events) != 5 || a.Metadata["value"] != "203.0.113.7" {
		t.Errorf("unexpected alert: %+v", a)
	}
	ev := a.Events[0]
	if ev.Source != "messages" || ev.Hostname != "myhost" || ev.Service != "sshd" || ev.Username != "root" || ev.Category != "authentication" {
		t.Errorf("unexpected event: %+v", ev)
	}

	var nEvents, nUnparsed int
	dec = json.NewDecoder(&events)
	for dec.More() {
		var ev event.Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		nEvents++
		if ev.Fields["parse_error"] != nil {
			nUnparsed++
		}
	}
	if nEvents != 13 || nUnparsed != 1 {
		t.Errorf("printed %d events (%d unparsed), want 13 (1 unparsed)", nEvents, nUnparsed)
	}

	if in := eng.inputs[0]; in.lines.Load() != 13 || in.unparsed.Load() != 1 {
		t.Errorf("lines=%d unparsed=%d, want 13 and 1", in.lines.Load(), in.unparsed.Load())
	}
}

func TestRunMissingFile(t *testing.T) {
	eng, err := New(&config.Config{Sources: []config.Source{logfile(filepath.Join(t.TempDir(), "nope"))}})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("got %v, want a missing file error", err)
	}
}

func logfile(path string) config.Source {
	return config.Source{ID: "messages", Type: "logfile", Path: path, Regexp: `^(?P<message>.*)$`}
}

func TestBuildSourcesErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*config.Source)
		want string
	}{
		{"missing id", func(c *config.Source) { c.ID = "" }, "missing id"},
		{"missing type", func(c *config.Source) { c.Type = "" }, "missing type"},
		{"unknown type", func(c *config.Source) { c.Type = "kafka" }, "unknown type"},
		{"no path", func(c *config.Source) { c.Path = "" }, "path is required"},
		{"no regexp", func(c *config.Source) { c.Regexp = "" }, "regexp is required"},
		{"bad regexp", func(c *config.Source) { c.Regexp = "(?P<x" }, "regexp:"},
		{"empty timestamp format", func(c *config.Source) { c.TimestampFormats = []string{""} }, "timestamp_formats"},
		{"bad timezone", func(c *config.Source) { c.Timezone = "Mars/Olympus" }, "timezone"},
		{"bad start_at", func(c *config.Source) { c.StartAt = "middle" }, "start_at"},
		{"end without follow", func(c *config.Source) { c.StartAt = "end" }, "requires follow"},
		{"all disabled", func(c *config.Source) { c.Disabled = true }, "no source enabled"},
	}
	for _, tt := range tests {
		c := logfile("/var/log/messages")
		tt.mod(&c)
		if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}
	c := logfile("/var/log/messages")
	if _, err := buildSources([]config.Source{c, c}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate ids: got %v", err)
	}
}

func TestRunResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	os.WriteFile(path, []byte("one\ntwo\n"), 0o644)
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "lib", "state.json"),
		Sources:   []config.Source{logfile(path)},
	}
	run := func() int64 {
		t.Helper()
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := eng.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return eng.inputs[0].lines.Load()
	}

	if n := run(); n != 2 {
		t.Fatalf("first run: %d lines, want 2", n)
	}
	if n := run(); n != 0 {
		t.Fatalf("second run: %d lines, want 0", n)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("three\n")
	f.Close()
	if n := run(); n != 1 {
		t.Fatalf("after appending a line: %d lines, want 1", n)
	}

	b, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"type": "logfile"`) || !strings.Contains(string(b), `"offset": 14`) {
		t.Errorf("unexpected state file:\n%s", b)
	}
}

func TestBuildLogfileDirectory(t *testing.T) {
	c := config.Source{ID: "web", Type: "logfile", Directory: "/var/log/nginx", FilenameRegexp: `access\.log$`, Regexp: `^(?P<message>.*)$`}
	inputs, err := buildSources([]config.Source{c})
	if err != nil {
		t.Fatal(err)
	}
	f := inputs[0].source.(*syslog.Files)
	if f.Dir != "/var/log/nginx" || f.Pattern.String() != `access\.log$` || f.Path != "" {
		t.Errorf("unexpected source: %+v", f)
	}

	tests := []struct {
		mod  func(*config.Source)
		want string
	}{
		{func(c *config.Source) { c.Path = "/var/log/messages" }, "either path, or directory"},
		{func(c *config.Source) { c.FilenameRegexp = "" }, "directory requires filename_regexp"},
		{func(c *config.Source) { c.Directory = "" }, "filename_regexp requires directory"},
		{func(c *config.Source) { c.FilenameRegexp = "(" }, "filename_regexp:"},
	}
	for _, tt := range tests {
		c := c
		tt.mod(&c)
		if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("got error %v, want it to contain %q", err, tt.want)
		}
	}
}

// Two files of a directory, then a third one appearing between two runs.
func TestRunDirectory(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.Mkdir(logs, 0o755)
	os.WriteFile(filepath.Join(logs, "a.log"), []byte("a1\na2\n"), 0o644)
	os.WriteFile(filepath.Join(logs, "b.log"), []byte("b1\n"), 0o644)
	os.WriteFile(filepath.Join(logs, "notes.txt"), []byte("x\n"), 0o644)
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "state.json"),
		Sources: []config.Source{{ID: "app", Type: "logfile", Directory: logs, FilenameRegexp: `\.log$`,
			Regexp: `^(?P<message>.*)$`}},
	}
	run := func() (int64, string) {
		t.Helper()
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var events bytes.Buffer
		eng.Events = &events
		if err := eng.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return eng.inputs[0].lines.Load(), events.String()
	}

	n, events := run()
	if n != 3 || !strings.Contains(events, `"file":"`+filepath.Join(logs, "a.log")+`"`) {
		t.Fatalf("first run: %d lines, want 3; events:\n%s", n, events)
	}
	os.WriteFile(filepath.Join(logs, "c.log"), []byte("c1\n"), 0o644)
	if n, _ := run(); n != 1 {
		t.Fatalf("second run: %d lines, want 1 (c.log)", n)
	}
	if n, _ := run(); n != 0 {
		t.Fatalf("third run: %d lines, want 0", n)
	}
}
