// Package state keeps, in a JSON file, the position of each source, so that
// a restart resumes after the last record processed, and the data memorized
// by the rules and the alerts raised within the maximum lifetime.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"wolverine/internal/event"
)

// version 2 has several positions per source (one per log file); version 1
// had a single one.
const version = 2

type file struct {
	Version int                `json:"version"`
	Sources map[string]*Source `json:"sources"`
	// Rules is the data each rule memorized, by rule id (see
	// detection.Rule.Save).
	Rules  map[string]json.RawMessage `json:"rules,omitempty"`
	Alerts []Alert                    `json:"alerts,omitempty"`
}

// Alert is an alert memorized by the engine, with the wall-clock time it
// was memorized: it expires at that time plus the maximum lifetime.
type Alert struct {
	MemorizedAt time.Time    `json:"memorized_at"`
	Alert       *event.Alert `json:"alert"`
}

// Source is the saved positions of one source, by key.
type Source struct {
	Type      string                     `json:"type"`
	Positions map[string]json.RawMessage `json:"positions,omitempty"`
	// Position is the version 1 field, only read.
	Position json.RawMessage `json:"position,omitempty"`
}

// Store holds the positions in memory; Save writes them to the file. It is
// not safe for concurrent use.
type Store struct {
	path    string
	sources map[string]*Source
	rules   map[string]json.RawMessage
	alerts  []Alert
	dirty   bool
}

// Open loads the state file. A missing file gives an empty store; an
// unreadable or invalid one is an error, rather than silently reading every
// source again from the start.
func Open(path string) (*Store, error) {
	s := &Store{path: path, sources: map[string]*Source{}, rules: map[string]json.RawMessage{}}
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
	if f.Version != 1 && f.Version != version {
		return nil, fmt.Errorf("state file %s: unsupported version %d", path, f.Version)
	}
	for i, a := range f.Alerts {
		if a.Alert == nil {
			return nil, fmt.Errorf("state file %s: alert #%d: no data", path, i+1)
		}
	}
	s.alerts = f.Alerts
	s.rules = f.Rules
	if s.rules == nil {
		s.rules = map[string]json.RawMessage{}
	}
	for id, src := range f.Sources {
		if src == nil {
			return nil, fmt.Errorf("state file %s: source %q: no data", path, id)
		}
		if f.Version == 1 {
			if err := upgrade(src); err != nil {
				return nil, fmt.Errorf("state file %s: source %q: %w", path, id, err)
			}
			s.dirty = true
		}
		for k, pos := range src.Positions {
			// Compact, as Set encodes them, to tell whether a position
			// changed.
			var buf bytes.Buffer
			if json.Compact(&buf, pos) != nil {
				return nil, fmt.Errorf("state file %s: source %q: invalid position", path, id)
			}
			src.Positions[k] = buf.Bytes()
		}
		s.sources[id] = src
	}
	return s, nil
}

// upgrade converts a version 1 source: a log file position is keyed by the
// file identity, as the logfile source does; any other is keyed by "".
func upgrade(src *Source) error {
	key := ""
	if src.Type == "logfile" {
		var p struct {
			Dev   uint64 `json:"dev"`
			Inode uint64 `json:"inode"`
		}
		if err := json.Unmarshal(src.Position, &p); err != nil {
			return err
		}
		key = fmt.Sprintf("%d:%d", p.Dev, p.Inode)
	}
	src.Positions = map[string]json.RawMessage{key: src.Position}
	src.Position = nil
	return nil
}

func (s *Store) Path() string { return s.path }

// Get returns the saved positions of a source, or nil if there are none or
// they were saved for another type of source (the source was changed).
func (s *Store) Get(id, typ string) map[string]json.RawMessage {
	src := s.sources[id]
	if src == nil || src.Type != typ {
		return nil
	}
	return src.Positions
}

func (s *Store) source(id, typ string) *Source {
	src := s.sources[id]
	if src == nil || src.Type != typ {
		src = &Source{Type: typ}
		s.sources[id] = src
		s.dirty = true
	}
	if src.Positions == nil {
		src.Positions = map[string]json.RawMessage{}
	}
	return src
}

// Set records one position of a source.
func (s *Store) Set(id, typ, key string, position any) error {
	b, err := json.Marshal(position)
	if err != nil {
		return err
	}
	src := s.source(id, typ)
	if old, ok := src.Positions[key]; ok && bytes.Equal(old, b) {
		return nil
	}
	src.Positions[key] = b
	s.dirty = true
	return nil
}

// Replace replaces all the positions of a source.
func (s *Store) Replace(id, typ string, positions map[string]any) error {
	encoded := map[string]json.RawMessage{}
	for k, p := range positions {
		b, err := json.Marshal(p)
		if err != nil {
			return err
		}
		encoded[k] = b
	}
	src := s.source(id, typ)
	if !maps.EqualFunc(src.Positions, encoded, func(a, b json.RawMessage) bool { return bytes.Equal(a, b) }) {
		src.Positions = encoded
		s.dirty = true
	}
	return nil
}

// Delete forgets positions of a source.
func (s *Store) Delete(id string, keys ...string) {
	src := s.sources[id]
	if src == nil {
		return
	}
	for _, k := range keys {
		if _, ok := src.Positions[k]; ok {
			delete(src.Positions, k)
			s.dirty = true
		}
	}
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

// Rule returns the saved data of a rule, or nil.
func (s *Store) Rule(id string) json.RawMessage { return s.rules[id] }

// SetRule replaces the saved data of a rule.
func (s *Store) SetRule(id string, data json.RawMessage) {
	s.rules[id] = data
	s.dirty = true
}

// RetainRules forgets the data of the rules whose id is not in ids (removed
// from the configuration or disabled).
func (s *Store) RetainRules(ids []string) {
	for id := range s.rules {
		if !slices.Contains(ids, id) {
			delete(s.rules, id)
			s.dirty = true
		}
	}
}

// Alerts returns the saved alerts.
func (s *Store) Alerts() []Alert { return s.alerts }

// SetAlerts replaces the saved alerts.
func (s *Store) SetAlerts(alerts []Alert) {
	s.alerts = alerts
	s.dirty = true
}

// Save writes the file if something changed. It is replaced atomically, so
// a crash never leaves it half written. The directory is created if needed.
func (s *Store) Save() error {
	if !s.dirty {
		return nil
	}
	b, err := json.MarshalIndent(file{Version: version, Sources: s.sources, Rules: s.rules, Alerts: s.alerts}, "", "  ")
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
