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
		t.Fatal("empty store returned a position")
	}
	s.Set("messages", "logfile", map[string]int{"offset": 42})
	s.Set("sshd-journal", "systemd-service", "s=abc;i=1")
	s.Set("old", "logfile", 1)
	s.Retain([]string{"messages", "sshd-journal"})
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
	if got := string(s.Get("messages", "logfile")); got != `{"offset":42}` {
		t.Errorf("messages: got %s", got)
	}
	if got := string(s.Get("sshd-journal", "systemd-service")); got != `"s=abc;i=1"` {
		t.Errorf("sshd-journal: got %s", got)
	}
	if s.Get("old", "logfile") != nil {
		t.Error("a removed source was kept")
	}
	if s.Get("messages", "systemd-service") != nil {
		t.Error("a position saved for another type was returned")
	}

	// Nothing changed: the file is not rewritten.
	s.Set("messages", "logfile", map[string]int{"offset": 42})
	if s.dirty {
		t.Error("setting the same position made the store dirty")
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
