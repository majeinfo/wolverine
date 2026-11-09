package syslog

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// gzipFile compresses path into path.gz and removes path, like logrotate.
func gzipFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeGzip(t, path+".gz", string(data))
	os.Remove(path)
}

func writeGzip(t *testing.T, path, content string) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(out)
	zw.Write([]byte(content))
	zw.Close()
	out.Close()
}

func TestCompressedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "messages-20261101.gz")
	writeGzip(t, path, "z1\nz2\nlast without newline")
	src := func() *Files { return &Files{ID: "old", Path: path} }
	got, pos := run(t, src(), nil, -1)
	check(t, got, "z1", "z2", "last without newline")

	var p Position
	for _, raw := range pos {
		json.Unmarshal(raw, &p)
	}
	if !p.Done || p.Compressed != "gzip" || p.Offset != 26 {
		t.Errorf("position %+v, want done, gzip, offset 26", p)
	}
	got, _ = run(t, src(), pos, -1)
	check(t, got)
}

func TestCompressedBzip2(t *testing.T) {
	if _, err := exec.LookPath("bzip2"); err != nil {
		t.Skip("bzip2 not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	write(t, path, "b1\nb2\n")
	if out, err := exec.Command("bzip2", path).CombinedOutput(); err != nil {
		t.Fatalf("bzip2: %v %s", err, out)
	}
	got, _ := run(t, &Files{ID: "old", Path: path + ".bz2"}, nil, -1)
	check(t, got, "b1", "b2")
}

// The current file and older compressed rotations are all read on a first
// run from the beginning.
func TestCompressedRotationsFirstRun(t *testing.T) {
	dir := t.TempDir()
	writeGzip(t, filepath.Join(dir, "app.log.2.gz"), "old1\n")
	writeGzip(t, filepath.Join(dir, "app.log.1.gz"), "old2\n")
	write(t, filepath.Join(dir, "app.log"), "new\n")
	got, pos := run(t, dirSource(dir, `^app\.log`), nil, -1)
	slices.Sort(got)
	check(t, got, "new", "old1", "old2")

	// Nothing is read again, and the compressed files are not decompressed
	// again: they are done.
	got, _ = run(t, dirSource(dir, `^app\.log`), pos, -1)
	check(t, got)
	done := 0
	for _, raw := range pos {
		var p Position
		json.Unmarshal(raw, &p)
		if p.Done {
			done++
		}
	}
	if done != 2 {
		t.Errorf("%d compressed files done, want 2", done)
	}
}

// With start_at end, existing compressed files are skipped.
func TestCompressedStartAtEnd(t *testing.T) {
	dir := t.TempDir()
	writeGzip(t, filepath.Join(dir, "app.log.1.gz"), "old\n")
	s := dirSource(dir, `^app\.log`)
	s.StartAtEnd, s.Follow = true, true
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for {
		rec, err := s.Read(ctx)
		if err != nil {
			break
		}
		if rec.Data != nil {
			t.Fatalf("read %q, want nothing", rec.Data)
		}
	}
}

// Rotated and compressed while stopped, under a name the regexp does not
// match: the rest of the file is read from its compressed copy, once.
func TestCompressedWhileStopped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	write(t, path, "1\n2\n")
	_, pos := run(t, dirSource(dir, `^app\.log$`), nil, -1)
	appendTo(t, path, "3\n")
	os.Rename(path, path+".1")
	gzipFile(t, path+".1")
	write(t, path, "4\n")

	got, pos := run(t, dirSource(dir, `^app\.log$`), pos, -1)
	check(t, got, "3", "4")
	got, _ = run(t, dirSource(dir, `^app\.log$`), pos, -1)
	check(t, got)
}

// Rotated then compressed while following, under a name the regexp
// matches: no line is read twice.
func TestCompressedWhileFollowing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	write(t, path, "1\n2\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := dirSource(dir, `^app\.log`)
	s.Follow = true
	if err := s.Open(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	lines := make(chan string)
	go func() {
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
	var got []string
	next := func() {
		t.Helper()
		select {
		case l := <-lines:
			got = append(got, l)
		case <-ctx.Done():
			t.Fatalf("timeout; got %q", got)
		}
	}
	next()
	next()
	appendTo(t, path, "3\n")
	os.Rename(path, path+".1")
	gzipFile(t, path+".1")
	write(t, path, "4\n")
	next()
	next()

	// Nothing more comes (no duplicate from app.log.1.gz).
	select {
	case l := <-lines:
		t.Fatalf("unexpected line %q after %q", l, got)
	case <-time.After(300 * time.Millisecond):
	}
	check(t, got, "1", "2", "3", "4")
	cancel()
	for range lines {
	}
}
