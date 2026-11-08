// Package syslog implements the "logfile" source: it reads a log file such
// as /var/log/messages line by line, optionally following it like tail -F,
// and parses each line into an event with a configurable regular expression.
package syslog

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wolverine/internal/event"
	"wolverine/internal/parser"
	"wolverine/internal/source"
	"wolverine/internal/verbose"
)

// ---------------------------------------------------------------------------
// Source: reading the file
// ---------------------------------------------------------------------------

const (
	defaultPoll = 500 * time.Millisecond
	// headSize is the number of bytes at the start of a file used to
	// recognize it: an inode number alone can be reused by a new file.
	headSize = 1024
)

// File reads a log file line by line. It implements source.Source and
// source.Resumer.
//
// When Follow is set, Read waits for new lines at end of file and reopens
// the file when it is rotated or truncated, like "tail -F". StartAtEnd skips
// the lines already in the file when it is first opened.
type File struct {
	ID         string
	Path       string
	Follow     bool
	StartAtEnd bool
	Poll       time.Duration

	f       *os.File
	r       *bufio.Reader
	name    string // of the open file: Path, or a rotated file being drained
	offset  int64
	pending string
	resume  *Position
	// draining is set while reading the rest of a file that was rotated
	// while wolverine was stopped; at its end, Path is opened.
	draining bool
	headLen  int
	headSum  string
	dev, ino uint64 // of the open file
}

// Position is where a File stopped. The file is identified by its device
// and inode numbers, and by a checksum of its first bytes.
type Position struct {
	Path    string `json:"path"`
	Dev     uint64 `json:"dev"`
	Inode   uint64 `json:"inode"`
	Offset  int64  `json:"offset"`
	HeadLen int    `json:"head_len"`
	HeadSum string `json:"head_sha256"`
}

func (s *File) Name() string { return s.ID }

func (s *File) Resume(position json.RawMessage) error {
	var p Position
	if err := json.Unmarshal(position, &p); err != nil {
		return err
	}
	s.resume = &p
	return nil
}

func (s *File) Open(ctx context.Context) error {
	if s.resume != nil {
		return s.openResume(*s.resume)
	}
	if err := s.open(s.Path); err != nil {
		return err
	}
	if s.StartAtEnd {
		end, err := s.f.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		s.offset = end
		s.r.Reset(s.f)
	}
	verbose.Debugf("source %s: %s opened at offset %d", s.ID, s.Path, s.offset)
	return nil
}

// openResume opens the file where the previous run stopped.
func (s *File) openResume(p Position) error {
	if name, ok := s.findFile(p); ok {
		if err := s.open(name); err != nil {
			return err
		}
		if _, err := s.f.Seek(p.Offset, io.SeekStart); err != nil {
			return err
		}
		s.offset = p.Offset
		s.r.Reset(s.f)
		if name == s.Path {
			verbose.Infof("source %s: resuming %s at offset %d", s.ID, s.Path, p.Offset)
		} else {
			s.draining = true
			verbose.Infof("source %s: %s was rotated while stopped: reading the rest of %s from offset %d first", s.ID, s.Path, name, p.Offset)
		}
		return nil
	}
	// The file was replaced, truncated or rotated away (e.g. compressed):
	// what is in Path now has not been read.
	verbose.Infof("source %s: the file read by the previous run is gone or was truncated, reading %s from the beginning", s.ID, s.Path)
	return s.open(s.Path)
}

// findFile looks for the file described by p: Path itself, or a rotated
// copy in the same directory (messages.1, messages-20261108...).
func (s *File) findFile(p Position) (string, bool) {
	if s.matches(s.Path, p) {
		return s.Path, true
	}
	dir, base := filepath.Split(s.Path)
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		name := filepath.Join(dir, e.Name())
		if e.Name() != base && strings.HasPrefix(e.Name(), base) && e.Type().IsRegular() && s.matches(name, p) {
			return name, true
		}
	}
	return "", false
}

// matches tells whether the file name is the one described by p and still
// holds at least p.Offset bytes.
func (s *File) matches(name string, p Position) bool {
	fi, err := os.Stat(name)
	if err != nil {
		return false
	}
	dev, ino := fileID(fi)
	if dev != p.Dev || ino != p.Inode || fi.Size() < p.Offset {
		return false
	}
	sum, n, err := head(name, p.HeadLen)
	return err == nil && n == p.HeadLen && sum == p.HeadSum
}

func fileID(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino
	}
	return 0, 0
}

// head returns the checksum of the first n bytes of a file (fewer if it is
// shorter) and how many bytes were read.
func head(name string, n int) (string, int, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return headOf(f, n)
}

func headOf(r io.ReaderAt, n int) (string, int, error) {
	buf := make([]byte, n)
	m, err := r.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", 0, err
	}
	sum := sha256.Sum256(buf[:m])
	return hex.EncodeToString(sum[:]), m, nil
}

func (s *File) open(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	if s.f != nil {
		s.f.Close()
	}
	s.f, s.r, s.name, s.offset, s.pending = f, bufio.NewReaderSize(f, 64*1024), name, 0, ""
	s.headLen, s.headSum = 0, ""
	if fi, err := f.Stat(); err == nil {
		s.dev, s.ino = fileID(fi)
	}
	return nil
}

func (s *File) Close() error {
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Read returns the next line, without its line ending. At end of file it
// returns io.EOF, unless Follow is set.
func (s *File) Read(ctx context.Context) (*source.Record, error) {
	line, err := s.next(ctx)
	if err != nil {
		return nil, err
	}
	pos, err := s.position()
	if err != nil {
		return nil, err
	}
	return &source.Record{Data: []byte(line), Timestamp: time.Now(), Source: s.ID, Position: pos}, nil
}

// Position returns where the file is opened, before the first Read.
func (s *File) Position() (any, error) {
	if s.draining {
		// Resuming a rotated file: its position is already saved.
		return nil, nil
	}
	return s.position()
}

// position returns the current position, right after the last line read.
func (s *File) position() (*Position, error) {
	// The checksum covers the first headSize bytes; until the file is that
	// long, it is updated as lines are read.
	if s.headLen < headSize && s.offset > int64(s.headLen) {
		sum, n, err := headOf(s.f, int(min(s.offset, headSize)))
		if err != nil {
			return nil, err
		}
		s.headLen, s.headSum = n, sum
	}
	return &Position{Path: s.name, Dev: s.dev, Inode: s.ino, Offset: s.offset, HeadLen: s.headLen, HeadSum: s.headSum}, nil
}

func (s *File) next(ctx context.Context) (string, error) {
	poll := s.Poll
	if poll <= 0 {
		poll = defaultPoll
	}
	waited := false
	for {
		chunk, err := s.r.ReadString('\n')
		s.offset += int64(len(chunk))
		s.pending += chunk
		if err == nil {
			line := s.pending
			s.pending = ""
			return trimEOL(line), nil
		}
		if !errors.Is(err, io.EOF) {
			return "", err
		}
		if s.draining {
			// End of the rotated file: return its unterminated last line,
			// if any, then continue with the current file.
			if s.pending != "" {
				line := s.pending
				s.pending = ""
				return trimEOL(line), nil
			}
			verbose.Infof("source %s: done with %s, now reading %s", s.ID, s.name, s.Path)
			s.draining = false
			if err := s.open(s.Path); err != nil {
				return "", err
			}
			continue
		}
		if !s.Follow {
			if s.pending != "" {
				line := s.pending
				s.pending = ""
				return trimEOL(line), nil
			}
			return "", io.EOF
		}

		// Following: only look for a rotation once the current file is fully
		// drained (nothing new read since the last wait), so no line is lost.
		if chunk == "" && waited {
			if err := s.checkRotation(); err != nil {
				return "", err
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
		waited = true
	}
}

func (s *File) checkRotation() error {
	cur, err := s.f.Stat()
	if err != nil {
		return err
	}
	onDisk, err := os.Stat(s.Path)
	if err != nil {
		// The file may be briefly missing during rotation; keep waiting.
		return nil
	}
	if !os.SameFile(cur, onDisk) {
		// Rotated: the old file has been read up to EOF, switch to the new one.
		verbose.Infof("source %s: %s rotated, reopening it", s.ID, s.Path)
		return s.open(s.Path)
	}
	if cur.Size() < s.offset {
		// Truncated in place (copytruncate).
		verbose.Infof("source %s: %s truncated, reading it from the beginning", s.ID, s.Path)
		if _, err := s.f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		s.r.Reset(s.f)
		s.offset, s.pending = 0, ""
		s.headLen, s.headSum = 0, ""
	}
	return nil
}

func trimEOL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// ---------------------------------------------------------------------------
// Parser: turning a line into an event
// ---------------------------------------------------------------------------

// ErrNoMatch is returned when a line does not match the regular expression.
var ErrNoMatch = errors.New("line does not match the regexp")

// Named groups of the regexp fill the Event fields of the same name (see
// parser.SetField). "timestamp" is parsed with TimestampFormats and "pri"
// (syslog priority) sets Severity and the "facility" field. Any other named
// group is stored in Event.Fields.

// Parser parses lines with a regular expression. It implements
// parser.Parser.
//
// The "message" group sets Event.Message; without it, the whole line is the
// message. Without a "timestamp" group, the time the line was read is used.
type Parser struct {
	Regexp   *regexp.Regexp
	Category string
	// TimestampFormats are tried in order: "rfc3164" (Jan _2 15:04:05),
	// "rfc3339", or a Go time layout. When the parsed date has no year (as
	// in rfc3164), the current year is assumed, or the previous one if that
	// would put the date in the future.
	TimestampFormats []string
	Location         *time.Location
	Now              func() time.Time
}

// TimestampLayout returns the Go time layout for a timestamp format.
func TimestampLayout(format string) (string, error) {
	switch format {
	case "rfc3164":
		return time.Stamp, nil
	case "rfc3339":
		return time.RFC3339Nano, nil
	case "":
		return "", errors.New("empty timestamp format")
	default:
		return format, nil
	}
}

func (p *Parser) Name() string { return "regexp" }

// Parse parses one line. When the line cannot be parsed, a minimal event
// carrying the raw line is returned along with the error, so that no data is
// lost.
func (p *Parser) Parse(rec *source.Record) (*event.Event, error) {
	line := string(rec.Data)
	ev := &event.Event{
		ID:        newID(),
		Timestamp: rec.Timestamp,
		Source:    rec.Source,
		Category:  p.Category,
		Message:   line,
		Raw:       line,
		Fields:    map[string]any{},
	}

	m := p.Regexp.FindStringSubmatch(line)
	if m == nil {
		ev.Fields["parse_error"] = ErrNoMatch.Error()
		return ev, ErrNoMatch
	}

	var ts string
	for i, name := range p.Regexp.SubexpNames() {
		if name == "" {
			continue
		}
		v := m[i]
		switch name {
		case "message":
			ev.Message = v
		case "timestamp":
			ts = v
		case "pri":
			if pri, err := strconv.Atoi(v); err == nil && pri >= 0 && pri <= 191 {
				ev.Severity, _ = parser.Severity(pri % 8)
				ev.Fields["facility"], _ = parser.Facility(pri / 8)
			}
		default:
			parser.SetField(ev, name, v)
		}
	}

	if ts != "" {
		t, err := p.parseTime(ts)
		if err != nil {
			ev.Fields["parse_error"] = err.Error()
			return ev, err
		}
		ev.Timestamp = t
	}
	return ev, nil
}

func (p *Parser) parseTime(s string) (time.Time, error) {
	loc := p.Location
	if loc == nil {
		loc = time.Local
	}
	for _, f := range p.TimestampFormats {
		layout, err := TimestampLayout(f)
		if err != nil {
			continue
		}
		t, err := time.ParseInLocation(layout, s, loc)
		if err != nil {
			continue
		}
		if t.Year() == 0 {
			t = p.withYear(t, loc)
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("timestamp %q does not match %v", s, p.TimestampFormats)
}

// withYear sets the year of a date that has none: the current year, unless
// it puts the date in the future (e.g. December logs read in January).
func (p *Parser) withYear(t time.Time, loc *time.Location) time.Time {
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	now = now.In(loc)
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
