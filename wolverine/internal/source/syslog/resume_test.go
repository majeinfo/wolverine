package syslog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// run opens s, reads up to n lines (all if n < 0) and returns them with the
// positions to give to the next run, as the engine saves them.
func run(t *testing.T, s *Files, saved map[string]json.RawMessage, n int) ([]string, map[string]json.RawMessage) {
	t.Helper()
	if saved != nil {
		if err := s.Resume(saved); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	positions := map[string]json.RawMessage{}
	start, err := s.Positions()
	if err != nil {
		t.Fatal(err)
	}
	for k, p := range start {
		positions[k], _ = json.Marshal(p)
	}
	var lines []string
	for n < 0 || len(lines) < n {
		rec, err := s.Read(context.Background())
		if err != nil {
			break
		}
		for _, k := range rec.Forget {
			delete(positions, k)
		}
		if rec.Position != nil {
			positions[rec.PositionKey], _ = json.Marshal(rec.Position)
		}
		if rec.Data != nil {
			lines = append(lines, string(rec.Data))
		}
	}
	return lines, positions
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
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

// single returns a single-file source and its path, with content written.
func single(t *testing.T, content string) (func() *Files, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "messages")
	write(t, path, content)
	return func() *Files { return &Files{ID: "messages", Path: path} }, path
}

func TestResumeSameFile(t *testing.T) {
	src, path := single(t, "a\nb\nc\n")
	_, pos := run(t, src(), nil, 2)
	appendTo(t, path, "d\n")
	s := src()
	s.StartAtEnd = true // ignored when resuming
	got, _ := run(t, s, pos, -1)
	check(t, got, "c", "d")
}

func TestResumeRotatedWhileStopped(t *testing.T) {
	src, path := single(t, "a\nb\nc\n")
	_, pos := run(t, src(), nil, 2)
	appendTo(t, path, "d\n")
	os.Rename(path, path+"-20261108") // logrotate: rename, then a new file
	write(t, path, "e\nf\n")
	got, pos := run(t, src(), pos, -1)
	check(t, got, "c", "d", "e", "f")
	if len(pos) != 1 {
		t.Errorf("the rotated file's position was not forgotten: %s", pos)
	}
}

func TestResumeRotatedAway(t *testing.T) {
	// The old file was compressed or deleted: the new one is read entirely.
	src, path := single(t, "a\nb\nc\n")
	_, pos := run(t, src(), nil, 2)
	os.Remove(path)
	write(t, path, "e\nf\n")
	got, _ := run(t, src(), pos, -1)
	check(t, got, "e", "f")
}

func TestResumeTruncated(t *testing.T) {
	src, path := single(t, "a\nb\nc\n")
	_, pos := run(t, src(), nil, 3)
	write(t, path, "x\n") // same inode, shorter
	got, _ := run(t, src(), pos, -1)
	check(t, got, "x")
}

func TestResumeOverwritten(t *testing.T) {
	// Same inode and long enough, but different content: not the same file.
	src, path := single(t, "a\nb\nc\n")
	_, pos := run(t, src(), nil, 2)
	write(t, path, "x\ny\nz\n")
	got, _ := run(t, src(), pos, -1)
	check(t, got, "x", "y", "z")
}

func TestResumeLongHead(t *testing.T) {
	// Lines beyond the checksummed head: the checksum stops growing.
	src, _ := single(t, strings.Repeat("0123456789\n", 200)+"last\n")
	_, pos := run(t, src(), nil, 200)
	var p Position
	for _, raw := range pos {
		json.Unmarshal(raw, &p)
	}
	if p.HeadLen != headSize || p.Offset != 2200 {
		t.Errorf("position %+v, want head_len %d and offset 2200", p, headSize)
	}
	got, _ := run(t, src(), pos, -1)
	check(t, got, "last")
}

// With start_at end and nothing read, the starting position is saved, so
// that lines written while stopped are read after a restart.
func TestStartPosition(t *testing.T) {
	src, path := single(t, "old 1\nold 2\n")
	s := src()
	s.Follow, s.StartAtEnd = true, true
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	start, err := s.Positions()
	s.Close()
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]json.RawMessage{}
	for k, p := range start {
		if p.(*Position).Offset != 12 {
			t.Fatalf("start position %+v, want offset 12", p)
		}
		pos[k], _ = json.Marshal(p)
	}
	appendTo(t, path, "new\n")
	got, _ := run(t, src(), pos, -1)
	check(t, got, "new")
}

// ---------------------------------------------------------------------------
// Files selected by a regexp
// ---------------------------------------------------------------------------

func dirSource(dir, pattern string) *Files {
	return &Files{ID: "web", Dir: dir, Pattern: regexp.MustCompile(pattern), Poll: 10 * time.Millisecond}
}

func TestPatternReadsMatchingFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.log"), "a1\na2\n")
	write(t, filepath.Join(dir, "b.log"), "b1\n")
	write(t, filepath.Join(dir, "c.txt"), "c1\n")
	os.Mkdir(filepath.Join(dir, "d.log"), 0o755) // directories are ignored

	got, pos := run(t, dirSource(dir, `\.log$`), nil, -1)
	slices.Sort(got)
	check(t, got, "a1", "a2", "b1")
	if len(pos) != 2 {
		t.Errorf("got %d positions, want 2", len(pos))
	}
}

func TestPatternFileField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.log")
	write(t, path, "x\n")
	s := dirSource(dir, `\.log$`)
	s.Open(context.Background())
	defer s.Close()
	rec, err := s.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Fields["file"] != path {
		t.Errorf("file field %q, want %q", rec.Fields["file"], path)
	}
}

func TestPatternNoFile(t *testing.T) {
	got, _ := run(t, dirSource(t.TempDir(), `\.log$`), nil, -1)
	check(t, got)
}

func TestPatternMissingDirectory(t *testing.T) {
	s := dirSource(filepath.Join(t.TempDir(), "nope"), `\.log$`)
	if err := s.Open(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// A rotated file whose new name still matches is not read again, after a
// restart too.
func TestPatternRotatedNameMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	write(t, path, "1\n2\n")
	_, pos := run(t, dirSource(dir, `^access`), nil, -1)
	appendTo(t, path, "3\n")
	os.Rename(path, filepath.Join(dir, "access.log.1"))
	write(t, path, "4\n")
	got, pos := run(t, dirSource(dir, `^access`), pos, -1)
	slices.Sort(got)
	check(t, got, "3", "4")
	got, _ = run(t, dirSource(dir, `^access`), pos, -1)
	check(t, got)
}

// Following: new files are read from their beginning, rotated ones are not
// read twice, and the positions of files that are gone are forgotten.
func TestPatternFollow(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.log"), "old\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := dirSource(dir, `\.log(\.\d+)?$`)
	s.Follow, s.StartAtEnd = true, true
	if err := s.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	type item struct {
		line   string
		forget []string
	}
	items := make(chan item)
	go func() {
		defer close(items)
		for {
			r, err := s.Read(ctx)
			if err != nil {
				return
			}
			if r.Data != nil || r.Forget != nil {
				items <- item{string(r.Data), r.Forget}
			}
		}
	}()
	expect := func(want string) {
		t.Helper()
		select {
		case got := <-items:
			if got.line != want || got.forget != nil {
				t.Fatalf("got %+v, want %q", got, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout waiting for %q", want)
		}
	}

	appendTo(t, filepath.Join(dir, "a.log"), "a new\n")
	expect("a new") // "old" was skipped (start_at end)

	write(t, filepath.Join(dir, "b.log"), "b1\n")
	expect("b1") // new file: read from the beginning

	// Rotation to a matching name, then a new a.log.
	appendTo(t, filepath.Join(dir, "a.log"), "a last\n")
	expect("a last")
	os.Rename(filepath.Join(dir, "a.log"), filepath.Join(dir, "a.log.1"))
	write(t, filepath.Join(dir, "a.log"), "a next\n")
	expect("a next")

	// Deletion: the file is read to its end, then its position forgotten.
	os.Remove(filepath.Join(dir, "b.log"))
	select {
	case got := <-items:
		if len(got.forget) != 1 {
			t.Fatalf("got %+v, want b.log to be forgotten", got)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for b.log to be forgotten")
	}

	cancel()
	for range items {
	}
}
