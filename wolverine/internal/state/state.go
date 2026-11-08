// Package state keeps, in a JSON file, the position of each source, so that
// a restart resumes after the last record processed.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const version = 1

type file struct {
	Version int                `json:"version"`
	Sources map[string]*Source `json:"sources"`
}

// Source is the saved position of one source.
type Source struct {
	Type     string          `json:"type"`
	Position json.RawMessage `json:"position"`
}

// Store holds the positions in memory; Save writes them to the file. It is
// not safe for concurrent use.
type Store struct {
	path    string
	sources map[string]*Source
	dirty   bool
}

// Open loads the state file. A missing file gives an empty store; an
// unreadable or invalid one is an error, rather than silently reading every
// source again from the start.
func Open(path string) (*Store, error) {
	s := &Store{path: path, sources: map[string]*Source{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("state file %s: %w (delete it to read the sources from start_at again)", path, err)
	}
	if f.Version != version {
		return nil, fmt.Errorf("state file %s: unsupported version %d", path, f.Version)
	}
	for id, src := range f.Sources {
		// Compact, as Set encodes them, to tell whether a position changed.
		var buf bytes.Buffer
		if src == nil || json.Compact(&buf, src.Position) != nil {
			return nil, fmt.Errorf("state file %s: source %q: invalid position", path, id)
		}
		src.Position = buf.Bytes()
		s.sources[id] = src
	}
	return s, nil
}

func (s *Store) Path() string { return s.path }

// Get returns the saved position of a source, or nil if there is none or it
// was saved for another type of source (the source was changed).
func (s *Store) Get(id, typ string) json.RawMessage {
	src := s.sources[id]
	if src == nil || src.Type != typ {
		return nil
	}
	return src.Position
}

// Set records the position of a source.
func (s *Store) Set(id, typ string, position any) error {
	b, err := json.Marshal(position)
	if err != nil {
		return err
	}
	if src := s.sources[id]; src != nil && src.Type == typ && string(src.Position) == string(b) {
		return nil
	}
	s.sources[id] = &Source{Type: typ, Position: b}
	s.dirty = true
	return nil
}

// Retain forgets the sources whose id is not in ids (removed from the
// configuration).
func (s *Store) Retain(ids []string) {
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
	}
	for id := range s.sources {
		if !keep[id] {
			delete(s.sources, id)
			s.dirty = true
		}
	}
}

// Save writes the file if something changed. It is replaced atomically, so
// a crash never leaves it half written. The directory is created if needed.
func (s *Store) Save() error {
	if !s.dirty {
		return nil
	}
	b, err := json.MarshalIndent(file{Version: version, Sources: s.sources}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.path)
	}
	if err != nil {
		return fmt.Errorf("saving the state: %w", err)
	}
	s.dirty = false
	return nil
}
