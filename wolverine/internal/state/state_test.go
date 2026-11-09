package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lib", "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Get("messages", "logfile") != nil {
		t.Fatal("empty store returned positions")
	}
	s.Set("messages", "logfile", "1:10", map[string]int{"offset": 42})
	s.Set("messages", "logfile", "1:11", map[string]int{"offset": 7})
	s.Set("sshd-journal", "systemd-service", "", "s=abc;i=1")
	s.Set("old", "logfile", "1:12", 1)
	s.Retain([]string{"messages", "sshd-journal"})
	s.Delete("messages", "1:11")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get("messages", "logfile"); len(got) != 1 || string(got["1:10"]) != `{"offset":42}` {
		t.Errorf("messages: got %s", got)
	}
	if got := string(s.Get("sshd-journal", "systemd-service")[""]); got != `"s=abc;i=1"` {
		t.Errorf("sshd-journal: got %s", got)
	}
	if s.Get("old", "logfile") != nil {
		t.Error("a removed source was kept")
	}
	if s.Get("messages", "systemd-service") != nil {
		t.Error("positions saved for another type were returned")
	}

	// Nothing changed: the file is not rewritten.
	s.Set("messages", "logfile", "1:10", map[string]int{"offset": 42})
	s.Replace("sshd-journal", "systemd-service", map[string]any{"": "s=abc;i=1"})
	if s.dirty {
		t.Error("setting the same positions made the store dirty")
	}
	s.Replace("messages", "logfile", map[string]any{"1:13": 0})
	if got := s.Get("messages", "logfile"); len(got) != 1 || got["1:13"] == nil {
		t.Errorf("after Replace: got %s", got)
	}
}

func TestUpgradeVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte(`{"version": 1, "sources": {
		"messages": {"type": "logfile", "position": {"path": "/var/log/messages", "dev": 64768, "inode": 42, "offset": 120}},
		"sshd-journal": {"type": "systemd-service", "position": {"cursor": "s=abc"}}}}`), 0o600)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(s.Get("messages", "logfile")["64768:42"]); !strings.Contains(got, `"offset":120`) {
		t.Errorf("messages: got %s", got)
	}
	if got := string(s.Get("sshd-journal", "systemd-service")[""]); got != `{"cursor":"s=abc"}` {
		t.Errorf("sshd-journal: got %s", got)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"version": 2`) || strings.Contains(string(b), `"position":`) {
		t.Errorf("not saved as version 2:\n%s", b)
	}
}

func TestInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte("{garbage"), 0o600)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "delete it") {
		t.Fatalf("got %v", err)
	}
	os.WriteFile(path, []byte(`{"version": 99}`), 0o600)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("got %v", err)
	}
}
