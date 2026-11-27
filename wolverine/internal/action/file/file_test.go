package file

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wolverine/internal/event"
)

func alert(id string, raws ...string) *event.Alert {
	a := &event.Alert{ID: id, RuleID: "ssh", Severity: "high", Message: "3 events for SourceIP=192.0.2.1",
		Timestamp: time.Date(2026, 11, 27, 10, 0, 5, 0, time.UTC), Metadata: map[string]any{"value": "192.0.2.1", "count": len(raws)}}
	for _, r := range raws {
		a.Events = append(a.Events, &event.Event{Raw: r})
	}
	return a
}

// JSON: one alert per line, appended; at most MaxEvents events.
func TestJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.json")
	f := &File{ID: "f", Path: path, Format: JSON, MaxEvents: 2}
	if err := f.Check(); err != nil {
		t.Fatal(err)
	}
	a := alert("a1", "one", "two", "three")
	for _, x := range []*event.Alert{a, alert("a2", "four")} {
		if err := f.Execute(context.Background(), x); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines:\n%s", len(lines), b)
	}
	var got event.Alert
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "a1" || len(got.Events) != 2 || got.Events[1].Raw != "two" || got.Metadata["events_total"] != 3.0 {
		t.Errorf("first alert: %+v", got)
	}
	if len(a.Events) != 3 || a.Metadata["events_total"] != nil {
		t.Error("the alert was modified: the other actions use it")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != Perm {
		t.Errorf("permission %o", fi.Mode().Perm())
	}
}

// Text: a line per alert and its log lines, indented; the control
// characters of the logs cannot add lines.
func TestText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.log")
	f := &File{ID: "f", Path: path, Format: Text, MaxEvents: 2}
	a := alert("a1", "one", "two\r\nFAKE ALERT\x1b[2J", "three")
	a.Message += "\ninjected"
	if err := f.Execute(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	noSev := alert("a2")
	noSev.Severity = ""
	f.Execute(context.Background(), noSev)
	b, _ := os.ReadFile(path)
	want := "2026-11-27T10:00:05Z [HIGH] ssh: 3 events for SourceIP=192.0.2.1 injected (alert a1)\n" +
		"    one\n" +
		"    two  FAKE ALERT [2J\n" +
		"    ... 1 more\n" +
		"2026-11-27T10:00:05Z [-] ssh: 3 events for SourceIP=192.0.2.1 (alert a2)\n"
	if string(b) != want {
		t.Errorf("got:\n%q\nwant:\n%q", b, want)
	}
}

// The file is opened for each alert: after a rotation (rename), the
// alerts go to a new file.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.json")
	f := &File{ID: "f", Path: path, Format: JSON}
	f.Execute(context.Background(), alert("a1", "x"))
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	f.Execute(context.Background(), alert("a2", "y"))
	old, _ := os.ReadFile(path + ".1")
	cur, _ := os.ReadFile(path)
	if !strings.Contains(string(old), `"a1"`) || strings.Contains(string(old), `"a2"`) || !strings.Contains(string(cur), `"a2"`) {
		t.Errorf("old: %s\nnew: %s", old, cur)
	}

	// An error (here, the file is a directory) is returned: the action
	// log shows it.
	os.Remove(path)
	os.Mkdir(path, 0o755)
	if err := f.Execute(context.Background(), alert("a3")); err == nil {
		t.Error("no error")
	}
}
