package syslog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// readN reads n lines and returns them with the position after the last one.
func readN(t *testing.T, s *File, n int) ([]string, json.RawMessage) {
	t.Helper()
	var lines []string
	var pos any
	for range n {
		rec, err := s.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(rec.Data))
		pos = rec.Position
	}
	b, err := json.Marshal(pos)
	if err != nil {
		t.Fatal(err)
	}
	return lines, b
}

// resumed opens path at the saved position and reads it to the end.
func resumed(t *testing.T, path string, pos json.RawMessage) []string {
	t.Helper()
	s := &File{ID: "messages", Path: path, StartAtEnd: true}
	if err := s.Resume(pos); err != nil {
		t.Fatal(err)
	}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return readAll(t, s)
}

// firstRun writes content, reads n lines and returns the position.
func firstRun(t *testing.T, content string, n int) (string, json.RawMessage) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &File{ID: "messages", Path: path}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, pos := readN(t, s, n)
	return path, pos
}

func appendTo(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(text)
}

func check(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResumeSameFile(t *testing.T) {
	path, pos := firstRun(t, "a\nb\nc\n", 2)
	appendTo(t, path, "d\n")
	// StartAtEnd is ignored when resuming.
	check(t, resumed(t, path, pos), "c", "d")
}

func TestResumeRotatedWhileStopped(t *testing.T) {
	path, pos := firstRun(t, "a\nb\nc\n", 2)
	appendTo(t, path, "d\n")
	// logrotate: rename, then a new file.
	if err := os.Rename(path, path+"-20261108"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("e\nf\n"), 0o644)
	check(t, resumed(t, path, pos), "c", "d", "e", "f")
}

func TestResumeRotatedAway(t *testing.T) {
	// The old file was compressed or deleted: the new one is read entirely.
	path, pos := firstRun(t, "a\nb\nc\n", 2)
	os.Remove(path)
	os.WriteFile(path, []byte("e\nf\n"), 0o644)
	check(t, resumed(t, path, pos), "e", "f")
}

func TestResumeTruncated(t *testing.T) {
	path, pos := firstRun(t, "a\nb\nc\n", 3)
	os.WriteFile(path, []byte("x\n"), 0o644) // same inode, shorter
	check(t, resumed(t, path, pos), "x")
}

func TestResumeOverwritten(t *testing.T) {
	// Same inode and long enough, but different content: not the same file.
	path, pos := firstRun(t, "a\nb\nc\n", 2)
	os.WriteFile(path, []byte("x\ny\nz\n"), 0o644)
	check(t, resumed(t, path, pos), "x", "y", "z")
}

func TestResumeLongHead(t *testing.T) {
	// Lines beyond the checksummed head: the checksum stops growing.
	var b strings.Builder
	for range 200 {
		b.WriteString("0123456789\n")
	}
	path, pos := firstRun(t, b.String()+"last\n", 200)
	var p Position
	json.Unmarshal(pos, &p)
	if p.HeadLen != headSize || p.Offset != 2200 {
		t.Errorf("position %+v, want head_len %d and offset 2200", p, headSize)
	}
	check(t, resumed(t, path, pos), "last")
}

// With start_at end and nothing read, the starting position is saved, so
// that lines written while stopped are read after a restart.
func TestStartPosition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages")
	os.WriteFile(path, []byte("old 1\nold 2\n"), 0o644)
	s := &File{ID: "messages", Path: path, Follow: true, StartAtEnd: true}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	pos, err := s.Position()
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if p := pos.(*Position); p.Offset != 12 || p.HeadLen != 12 {
		t.Fatalf("start position %+v, want offset 12", p)
	}
	b, _ := json.Marshal(pos)
	appendTo(t, path, "new\n")
	check(t, resumed(t, path, b), "new")
}
