package syslog

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"wolverine/internal/source"
	"wolverine/internal/verbose"
)

const (
	defaultPoll = 500 * time.Millisecond
	// headSize is the number of bytes at the start of a file used to
	// recognize it: an inode number alone can be reused by a new file, and
	// a compressed copy of a file has another inode.
	headSize = 1024
	// drainPolls is how many polls without new data a file that no longer
	// matches (rotated away, deleted) is kept open, in case its writer has
	// not switched to the new file yet.
	drainPolls = 2
	// maxHistory is how many files read to their end and dropped are
	// remembered, to recognize their compressed copies.
	maxHistory = 200
)

// Files reads log files line by line: a single file (Path), or every file
// of directory Dir whose name matches Pattern. It implements source.Source
// and source.Resumer.
//
// Each file is tracked by its identity (device and inode), not by its name:
// a file renamed to another matching name (messages -> messages-20261108)
// is not read again, and a file that no longer matches (renamed to a
// non-matching name, deleted) is read to its end, then dropped.
//
// Compressed files (gzip, bzip2, recognized by their content) are
// decompressed. They do not grow: each is read once, then remembered as
// done. A compressed file whose content starts like a file already read
// (logrotate compressing a rotated file) is that file: its reading
// continues where it stopped instead of starting over.
//
// When Follow is set, Read waits for new lines, notices new matching files
// (read from their beginning) and truncated files (copytruncate), like
// "tail -F". Otherwise, every file is read once and Read returns io.EOF.
// StartAtEnd skips the lines already in the files when the source has no
// saved positions.
type Files struct {
	ID      string
	Path    string
	Dir     string
	Pattern *regexp.Regexp
	Follow  bool
	// StartAtEnd only applies to the files present when the source is
	// first opened without saved positions.
	StartAtEnd bool
	Poll       time.Duration

	files   []*file
	next    int                 // round robin between the files
	done    map[string]Position // compressed files read to their end, by key
	saved   map[string]Position
	history []Position // plain files dropped, to recognize their compressed copies
	updates []*source.Record
}

type file struct {
	name     string
	f        *os.File
	r        *bufio.Reader
	dev, ino uint64
	size     int64  // of the file on disk, for compressed files
	comp     string // "gzip", "bzip2", or "" for a plain file
	offset   int64  // in the uncompressed data
	pending  string // start of a line not terminated yet
	headLen  int
	headSum  string
	head     []byte // first bytes of the uncompressed data, for compressed files
	draining bool   // no longer matches: read to the end, then dropped
	idle     int    // consecutive polls without new data
}

// Position is where the reading of one file stopped. The file is identified
// by its device and inode numbers, and by a checksum of its first bytes
// (uncompressed). Path is the name it had, for information.
type Position struct {
	Path    string `json:"path"`
	Dev     uint64 `json:"dev"`
	Inode   uint64 `json:"inode"`
	Offset  int64  `json:"offset"`
	HeadLen int    `json:"head_len"`
	HeadSum string `json:"head_sha256"`
	// Compressed files: the compression, the size of the file on disk, and
	// whether it was read to its end.
	Compressed string `json:"compressed,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Done       bool   `json:"done,omitempty"`
}

func key(dev, ino uint64) string { return fmt.Sprintf("%d:%d", dev, ino) }

func (p Position) key() string { return key(p.Dev, p.Inode) }

// continues tells whether a file whose first uncompressed bytes are head is
// the file read up to p.
func (p Position) continues(head []byte) bool {
	if p.HeadLen == 0 || len(head) < p.HeadLen {
		return false
	}
	return checksum(head[:p.HeadLen]) == p.HeadSum
}

func (s *Files) Name() string { return s.ID }

func (s *Files) dir() string {
	if s.Path != "" {
		return filepath.Dir(s.Path)
	}
	return s.Dir
}

func (s *Files) matches(name string) bool {
	if s.Path != "" {
		return name == filepath.Base(s.Path)
	}
	return s.Pattern.MatchString(name)
}

func (s *Files) Resume(positions map[string]json.RawMessage) error {
	s.saved = map[string]Position{}
	for k, raw := range positions {
		var p Position
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("position %s: %w", k, err)
		}
		s.saved[k] = p
	}
	return nil
}

// entry is a regular file of the directory.
type entry struct {
	name     string
	path     string
	size     int64
	dev, ino uint64
}

// scan lists the regular files of the directory (following symbolic links).
func (s *Files) scan() ([]entry, error) {
	des, err := os.ReadDir(s.dir())
	if err != nil {
		return nil, err
	}
	var entries []entry
	for _, de := range des {
		path := filepath.Join(s.dir(), de.Name())
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		dev, ino := fileID(fi)
		entries = append(entries, entry{de.Name(), path, fi.Size(), dev, ino})
	}
	return entries, nil
}

// known tells whether a file is being read or was read to its end.
func (s *Files) known(dev, ino uint64) bool {
	if _, ok := s.done[key(dev, ino)]; ok {
		return true
	}
	for _, f := range s.files {
		if f.dev == dev && f.ino == ino {
			return true
		}
	}
	return false
}

func (s *Files) Open(ctx context.Context) error {
	s.done = map[string]Position{}
	if s.Path != "" {
		// A missing single file is a configuration error.
		if _, err := os.Stat(s.Path); err != nil {
			return err
		}
	}
	entries, err := s.scan()
	if err != nil {
		return err
	}

	// Files read by the previous run, wherever they are now.
	for _, p := range s.saved {
		e, ok := findEntry(entries, p)
		switch {
		case !ok:
			// Gone, truncated, or compressed under a new inode: see below.
			s.remember(p)
		case p.Done:
			if s.matches(e.name) {
				s.done[p.key()] = p
			}
		default:
			f, err := openFile(e.path, p.Offset)
			if err != nil {
				return err
			}
			f.headLen, f.headSum = p.HeadLen, p.HeadSum
			f.draining = !s.matches(e.name)
			s.files = append(s.files, f)
			if f.draining {
				verbose.Infof("source %s: %s was rotated while stopped: reading the rest of %s from offset %d", s.ID, p.Path, e.path, p.Offset)
			} else {
				verbose.Infof("source %s: resuming %s at offset %d", s.ID, e.path, p.Offset)
			}
		}
	}

	// Files rotated and compressed while stopped: finish them from their
	// compressed copy, whatever its name.
	if len(s.history) > 0 {
		for _, e := range entries {
			if len(s.history) == 0 {
				break
			}
			if s.known(e.dev, e.ino) {
				continue
			}
			f, err := openFile(e.path, 0)
			if err != nil || f.comp == "" {
				if f != nil {
					f.f.Close()
				}
				continue
			}
			if p, ok := s.fromHistory(f.head); ok {
				if err := f.skip(p.Offset); err != nil {
					f.f.Close()
					continue
				}
				f.draining = !s.matches(e.name)
				s.files = append(s.files, f)
				verbose.Infof("source %s: %s was rotated and compressed while stopped: reading the rest of %s from offset %d", s.ID, p.Path, e.path, p.Offset)
				continue
			}
			f.f.Close()
		}
	}
	for _, p := range s.history {
		verbose.Infof("source %s: %s is gone, rotated away or was truncated", s.ID, p.Path)
	}

	// The other matching files. After a restart they are new (created while
	// stopped): read them entirely. start_at only applies to the first run.
	atEnd := s.StartAtEnd && len(s.saved) == 0
	for _, e := range entries {
		if s.matches(e.name) && !s.known(e.dev, e.ino) {
			s.openNew(e, atEnd)
		}
	}
	if len(s.files) == 0 && len(s.done) == 0 {
		verbose.Infof("source %s: no file in %s matches %s", s.ID, s.dir(), s.Pattern)
	}
	return nil
}

// openNew starts reading a matching file seen for the first time. A
// compressed file may be the copy of a file already read: it then
// continues where that file stopped, or is skipped if that file is still
// being read.
func (s *Files) openNew(e entry, atEnd bool) bool {
	f, err := openFile(e.path, 0)
	if err != nil {
		verbose.Debugf("source %s: %v", s.ID, err)
		return false
	}
	if f.comp == "" {
		if atEnd {
			if f.offset, err = f.f.Seek(0, io.SeekEnd); err != nil {
				f.f.Close()
				return false
			}
			f.r.Reset(f.f)
		}
		s.files = append(s.files, f)
		verbose.Debugf("source %s: %s opened at offset %d", s.ID, e.path, f.offset)
		return true
	}

	for _, t := range s.files {
		if t.comp == "" && (Position{HeadLen: t.headLen, HeadSum: t.headSum}).continues(f.head) {
			verbose.Infof("source %s: %s is a compressed copy of %s, which is being read: skipped", s.ID, e.path, t.name)
			s.finish(f)
			return false
		}
	}
	if p, ok := s.fromHistory(f.head); ok {
		if err := f.skip(p.Offset); err != nil {
			verbose.Infof("source %s: %s: %v", s.ID, e.path, err)
			f.f.Close()
			return false
		}
		verbose.Infof("source %s: %s is a compressed copy of %s: reading from offset %d", s.ID, e.path, p.Path, p.Offset)
	} else if atEnd {
		verbose.Debugf("source %s: %s skipped (start_at: end)", s.ID, e.path)
		s.finish(f)
		return false
	} else {
		verbose.Infof("source %s: reading compressed file %s", s.ID, e.path)
	}
	s.files = append(s.files, f)
	return true
}

// fromHistory returns, and forgets, the dropped file that a compressed file
// whose first uncompressed bytes are head is a copy of.
func (s *Files) fromHistory(head []byte) (Position, bool) {
	for i, p := range s.history {
		if p.Compressed == "" && p.continues(head) {
			s.history = append(s.history[:i], s.history[i+1:]...)
			return p, true
		}
	}
	return Position{}, false
}

func (s *Files) remember(p Position) {
	s.history = append(s.history, p)
	if len(s.history) > maxHistory {
		s.history = s.history[1:]
	}
}

// findEntry looks for the file described by p: same identity and same first
// bytes, and, for a plain file, still at least p.Offset bytes long.
func findEntry(entries []entry, p Position) (entry, bool) {
	for _, e := range entries {
		if e.dev != p.Dev || e.ino != p.Inode {
			continue
		}
		if p.Compressed != "" {
			// Compressed files do not change: the size is enough.
			if e.size == p.Size {
				return e, true
			}
			continue
		}
		if e.size < p.Offset {
			continue
		}
		sum, n, err := head(e.path, p.HeadLen)
		if err == nil && n == p.HeadLen && sum == p.HeadSum {
			return e, true
		}
	}
	return entry{}, false
}

// compression returns the compression of a file from its first bytes.
func compression(fd *os.File) string {
	var b [3]byte
	n, _ := fd.ReadAt(b[:], 0)
	switch {
	case n >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case n >= 3 && string(b[:]) == "BZh":
		return "bzip2"
	}
	return ""
}

func decompress(comp string, r io.Reader) (io.Reader, error) {
	switch comp {
	case "gzip":
		return gzip.NewReader(r)
	case "bzip2":
		return bzip2.NewReader(r), nil
	}
	return r, nil
}

// openFile opens a file at offset (of the uncompressed data).
func openFile(path string, offset int64) (*file, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, err
	}
	f := &file{name: path, f: fd, size: fi.Size(), comp: compression(fd)}
	f.dev, f.ino = fileID(fi)

	if f.comp == "" {
		if offset > 0 {
			if _, err := fd.Seek(offset, io.SeekStart); err != nil {
				fd.Close()
				return nil, err
			}
		}
		f.r, f.offset = bufio.NewReaderSize(fd, 64*1024), offset
		return f, nil
	}

	// The checksum of a compressed file is computed once, from a separate
	// reader: it cannot be read back at random.
	hr, err := decompress(f.comp, io.NewSectionReader(fd, 0, f.size))
	if err != nil {
		fd.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.head = make([]byte, headSize)
	n, err := io.ReadFull(hr, f.head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		fd.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.head = f.head[:n]
	f.headLen, f.headSum = n, checksum(f.head)

	dr, err := decompress(f.comp, fd)
	if err != nil {
		fd.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.r = bufio.NewReaderSize(dr, 64*1024)
	if err := f.skip(offset); err != nil {
		fd.Close()
		return nil, err
	}
	return f, nil
}

// skip moves a compressed file forward to offset (of the uncompressed data).
func (f *file) skip(offset int64) error {
	if offset <= f.offset {
		return nil
	}
	n, err := io.CopyN(io.Discard, f.r, offset-f.offset)
	f.offset += n
	if err != nil {
		return fmt.Errorf("%s: shorter than the saved position %d: %w", f.name, offset, err)
	}
	return nil
}

func (s *Files) Positions() (map[string]any, error) {
	positions := map[string]any{}
	for k, p := range s.done {
		positions[k] = p
	}
	for _, f := range s.files {
		p, err := f.position()
		if err != nil {
			return nil, err
		}
		positions[key(f.dev, f.ino)] = p
	}
	return positions, nil
}

func (s *Files) Close() error {
	var err error
	for _, f := range s.files {
		if cerr := f.f.Close(); err == nil {
			err = cerr
		}
	}
	s.files = nil
	return err
}

// Read returns the next line of one of the files, without its line ending.
// The files being drained (rotated) are read first, so that their last lines
// come before those of the files that replaced them. The other files are
// read in turn, so a busy file does not starve the others.
func (s *Files) Read(ctx context.Context) (*source.Record, error) {
	poll := s.Poll
	if poll <= 0 {
		poll = defaultPoll
	}
	for {
		if len(s.updates) > 0 {
			rec := s.updates[0]
			s.updates = s.updates[1:]
			return rec, nil
		}

		for _, draining := range []bool{true, false} {
			for i := range s.files {
				n := (s.next + i) % len(s.files)
				f := s.files[n]
				if f.draining != draining {
					continue
				}
				rec, err := s.readLine(f)
				if rec != nil || err != nil {
					if !draining {
						s.next = n + 1
					}
					return rec, err
				}
			}
		}

		// Nothing new in any file.
		s.dropFinished()
		if len(s.updates) > 0 {
			continue
		}
		if !s.Follow {
			return nil, io.EOF
		}
		added, err := s.rescan()
		if err != nil {
			return nil, err
		}
		if added || len(s.updates) > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
		for _, f := range s.files {
			f.idle++
		}
	}
}

// readLine returns the next line of f as a record, or nil if there is none
// for now.
func (s *Files) readLine(f *file) (*source.Record, error) {
	// A compressed file does not grow: its end is final.
	final := !s.Follow || f.comp != "" || (f.draining && f.idle >= drainPolls)
	line, ok, err := f.line(final)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.name, err)
	}
	if !ok {
		return nil, nil
	}
	f.idle = 0
	pos, err := f.position()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.name, err)
	}
	data := []byte(line)
	if data == nil {
		data = []byte{} // nil data marks the records that carry no line
	}
	return &source.Record{
		Data:        data,
		Timestamp:   time.Now(),
		Source:      s.ID,
		Fields:      map[string]string{"file": f.name},
		Position:    pos,
		PositionKey: key(f.dev, f.ino),
	}, nil
}

// line returns the next complete line of the file, if any. At the end of
// the file, an unterminated last line is only returned when final is set.
func (f *file) line(final bool) (string, bool, error) {
	chunk, err := f.r.ReadString('\n')
	f.offset += int64(len(chunk))
	f.pending += chunk
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, err
	}
	if err == nil || (final && f.pending != "") {
		line := f.pending
		f.pending = ""
		return trimEOL(line), true, nil
	}
	return "", false, nil
}

// dropFinished closes the files read to their end that will not grow: the
// ones that no longer match (their positions are forgotten) and the
// compressed ones (remembered as done).
func (s *Files) dropFinished() {
	kept := s.files[:0]
	for _, f := range s.files {
		switch {
		case f.pending != "":
		case f.draining && (!s.Follow || f.comp != "" || f.idle >= drainPolls):
			verbose.Infof("source %s: done with %s", s.ID, f.name)
			f.f.Close()
			if f.comp == "" {
				if p, err := f.position(); err == nil {
					s.remember(*p)
				}
			}
			s.updates = append(s.updates, &source.Record{Source: s.ID, Forget: []string{key(f.dev, f.ino)}})
			continue
		case f.comp != "":
			verbose.Debugf("source %s: done with compressed file %s", s.ID, f.name)
			s.finish(f)
			continue
		}
		kept = append(kept, f)
	}
	s.files = kept
	if s.next >= len(s.files) {
		s.next = 0
	}
}

// finish closes a compressed file and remembers it as done, so that it is
// neither read again nor decompressed again after a restart.
func (s *Files) finish(f *file) {
	f.f.Close()
	p, _ := f.position()
	p.Done = true
	s.done[p.key()] = *p
	s.updates = append(s.updates, &source.Record{Source: s.ID, Position: *p, PositionKey: p.key()})
}

// rescan looks for the files that appeared, no longer match or were
// truncated. It tells whether new files were added.
func (s *Files) rescan() (bool, error) {
	entries, err := s.scan()
	if err != nil {
		// The directory may be briefly unavailable; try again later.
		verbose.Debugf("source %s: %v", s.ID, err)
		return false, nil
	}

	for _, f := range s.files {
		if !f.draining && !hasMatching(s, entries, f.dev, f.ino) {
			verbose.Infof("source %s: %s was rotated or deleted, reading it to the end", s.ID, f.name)
			f.draining, f.idle = true, 0
		}
		if f.comp != "" {
			continue
		}
		fi, err := f.f.Stat()
		if err != nil {
			return false, fmt.Errorf("%s: %w", f.name, err)
		}
		if fi.Size() < f.offset {
			verbose.Infof("source %s: %s truncated, reading it from the beginning", s.ID, f.name)
			if _, err := f.f.Seek(0, io.SeekStart); err != nil {
				return false, err
			}
			f.r.Reset(f.f)
			f.offset, f.pending, f.headLen, f.headSum = 0, "", 0, ""
		}
	}

	// Compressed files deleted (old rotations): forget them.
	for k, p := range s.done {
		if !hasMatching(s, entries, p.Dev, p.Inode) {
			delete(s.done, k)
			s.updates = append(s.updates, &source.Record{Source: s.ID, Forget: []string{k}})
		}
	}

	added := false
	for _, e := range entries {
		if s.matches(e.name) && !s.known(e.dev, e.ino) {
			if s.openNew(e, false) {
				verbose.Infof("source %s: new file %s", s.ID, e.path)
				added = true
			}
		}
	}
	return added, nil
}

func hasMatching(s *Files, entries []entry, dev, ino uint64) bool {
	for _, e := range entries {
		if e.dev == dev && e.ino == ino && s.matches(e.name) {
			return true
		}
	}
	return false
}

// position returns the position right after the last line read.
func (f *file) position() (*Position, error) {
	// The checksum covers the first headSize bytes; until a plain file is
	// that long, it is updated as lines are read.
	if f.comp == "" && f.headLen < headSize && f.offset > int64(f.headLen) {
		sum, n, err := headOf(f.f, int(min(f.offset, headSize)))
		if err != nil {
			return nil, err
		}
		f.headLen, f.headSum = n, sum
	}
	p := &Position{Path: f.name, Dev: f.dev, Inode: f.ino, Offset: f.offset - int64(len(f.pending)),
		HeadLen: f.headLen, HeadSum: f.headSum, Compressed: f.comp}
	if f.comp != "" {
		p.Size = f.size
	}
	return p, nil
}

func fileID(fi os.FileInfo) (dev, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), st.Ino
	}
	return 0, 0
}

func checksum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
	return checksum(buf[:m]), m, nil
}
