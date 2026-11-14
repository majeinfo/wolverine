package syslog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const header = "date,host,message\n# fields: 3\n"

func skipping(s *Files) *Files {
	s.SkipLines = 2
	return s
}

func TestSkipLines(t *testing.T) {
	src, path := single(t, header+"a\nb\n")
	got, pos := run(t, skipping(src()), nil, 1)
	check(t, got, "a")

	// Resumed after the header: no line of data is skipped.
	appendTo(t, path, "c\n")
	got, _ = run(t, skipping(src()), pos, -1)
	check(t, got, "b", "c")

	// Without skip_lines, the header is read.
	got, _ = run(t, src(), nil, -1)
	check(t, got, "date,host,message", "# fields: 3", "a", "b", "c")

	// More lines to skip than the file has.
	s := src()
	s.SkipLines = 10
	got, _ = run(t, s, nil, -1)
	check(t, got)
}

// Every file of a directory has its header skipped, compressed ones
// included.
func TestSkipLinesFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "app.log"), header+"1\n")
	writeGzip(t, filepath.Join(dir, "app.log.1.gz"), header+"0\n")
	got, _ := run(t, skipping(dirSource(dir, `^app\.log`)), nil, -1)
	if len(got) != 2 || !(got[0] == "0" && got[1] == "1" || got[0] == "1" && got[1] == "0") {
		t.Errorf("got %q, want 0 and 1", got)
	}
}

// Rotated and compressed while stopped: the rest is read from the
// compressed copy, without skipping lines of data.
func TestSkipLinesCompressedWhileStopped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	write(t, path, header+"1\n2\n")
	got, pos := run(t, skipping(dirSource(dir, `^app\.log$`)), nil, -1)
	check(t, got, "1", "2")
	appendTo(t, path, "3\n")
	os.Rename(path, path+".1")
	gzipFile(t, path+".1")
	write(t, path, header+"4\n")

	got, _ = run(t, skipping(dirSource(dir, `^app\.log$`)), pos, -1)
	check(t, got, "3", "4")
}

// start_at: end starts after the header, and a truncated file has its new
// header skipped.
func TestSkipLinesFollow(t *testing.T) {
	src, path := single(t, header+"old\n")
	s := skipping(src())
	s.Follow, s.StartAtEnd, s.Poll = true, true, 10*time.Millisecond
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	next := func() string {
		t.Helper()
		for {
			rec, err := s.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Data != nil {
				return string(rec.Data)
			}
		}
	}
	appendTo(t, path, "new\n")
	if got := next(); got != "new" {
		t.Errorf("after start at end: %q", got)
	}
	write(t, path, header) // truncated (shorter), then the data
	// Let the source notice the truncation before the file grows again.
	short, cancelShort := context.WithTimeout(ctx, 100*time.Millisecond)
	if rec, err := s.Read(short); err == nil && rec.Data != nil {
		t.Errorf("header read after truncation: %q", rec.Data)
	}
	cancelShort()
	appendTo(t, path, "after truncation\n")
	if got := next(); got != "after truncation" {
		t.Errorf("after truncation: %q", got)
	}
}

// A position inside the header (e.g. saved by a run without skip_lines):
// the rest of the header is still skipped.
func TestSkipLinesResumeInHeader(t *testing.T) {
	src, path := single(t, header+"a\n")
	_, pos := run(t, src(), nil, 1) // "date,host,message" only
	got, _ := run(t, skipping(src()), pos, -1)
	check(t, got, "a")

	// Same with a compressed copy.
	dir := t.TempDir()
	path = filepath.Join(dir, "app.log")
	write(t, path, header+"1\n")
	_, pos = run(t, dirSource(dir, `^app\.log$`), nil, 1)
	os.Rename(path, path+".1")
	gzipFile(t, path+".1")
	got, _ = run(t, skipping(dirSource(dir, `^app\.log$`)), pos, -1)
	check(t, got, "1")
}
