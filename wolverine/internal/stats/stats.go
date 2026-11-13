// Package stats counts what wolverine processes, per source and per rule, in
// one-minute buckets of wall-clock time, so that the counts of any interval
// (at a minute's resolution) can be computed. The buckets older than the
// maximum lifetime are dropped by Expire; the totals since the start are
// kept apart.
package stats

import (
	"sort"
	"sync"
	"time"
)

// Resolution is the duration of a bucket.
const Resolution = time.Minute

// Source counts the records of a source.
type Source struct {
	// Lines are the records read (log lines, journal entries...), empty
	// ones included.
	Lines int64 `json:"lines"`
	// Events are the lines the source's regexp parsed.
	Events int64 `json:"events"`
	// Unparsed are the lines the regexp did not parse. They are still
	// processed, with only their raw text.
	Unparsed int64 `json:"unparsed"`
	// Excluded are the events dropped by the source's exclude lists and
	// exclude_if.
	Excluded int64 `json:"excluded"`
}

func (s *Source) add(o *Source) {
	s.Lines += o.Lines
	s.Events += o.Events
	s.Unparsed += o.Unparsed
	s.Excluded += o.Excluded
}

// Rule counts what a rule did.
type Rule struct {
	// Matches are the events the rule matched (counted toward its
	// threshold).
	Matches int64 `json:"matches"`
	// Alerts are the alerts it raised.
	Alerts int64 `json:"alerts"`
}

func (r *Rule) add(o *Rule) {
	r.Matches += o.Matches
	r.Alerts += o.Alerts
}

// Totals sums the counters of every source and rule.
type Totals struct {
	Source
	Rule
}

// Counts are the counters of an interval.
type Counts struct {
	Totals  Totals             `json:"totals"`
	Sources map[string]*Source `json:"sources"`
	Rules   map[string]*Rule   `json:"rules"`
}

func newCounts() *Counts {
	return &Counts{Sources: map[string]*Source{}, Rules: map[string]*Rule{}}
}

func (c *Counts) source(id string) *Source {
	s := c.Sources[id]
	if s == nil {
		s = &Source{}
		c.Sources[id] = s
	}
	return s
}

func (c *Counts) rule(id string) *Rule {
	r := c.Rules[id]
	if r == nil {
		r = &Rule{}
		c.Rules[id] = r
	}
	return r
}

// add adds the counters of o.
func (c *Counts) add(o *Counts) {
	c.Totals.Source.add(&o.Totals.Source)
	c.Totals.Rule.add(&o.Totals.Rule)
	for id, s := range o.Sources {
		c.source(id).add(s)
	}
	for id, r := range o.Rules {
		c.rule(id).add(r)
	}
}

type bucket struct {
	start time.Time
	*Counts
}

// Store holds the counters. It is safe for concurrent use.
type Store struct {
	// Now gives the current time (nil: time.Now).
	Now func() time.Time

	mu      sync.Mutex
	started time.Time
	total   *Counts
	buckets []*bucket // in time order, at most one per minute
}

// New creates a store, with the ids of the sources and rules, so that they
// are reported even before they count anything.
func New(sources, rules []string) *Store {
	s := &Store{total: newCounts()}
	s.started = s.now()
	for _, id := range sources {
		s.total.source(id)
	}
	for _, id := range rules {
		s.total.rule(id)
	}
	return s
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Started returns when the store was created.
func (s *Store) Started() time.Time { return s.started }

// record adds to the counters of the current bucket and to the totals.
func (s *Store) record(f func(*Counts)) {
	start := s.now().Truncate(Resolution)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.buckets)
	if n == 0 || s.buckets[n-1].start.Before(start) {
		s.buckets = append(s.buckets, &bucket{start, newCounts()})
		n++
	}
	f(s.buckets[n-1].Counts)
	f(s.total)
}

// Line counts a line read by a source: parsed by its regexp, unparsed, or
// neither (empty).
func (s *Store) Line(source string, parsed, unparsed bool) {
	s.record(func(c *Counts) {
		src := c.source(source)
		src.Lines++
		c.Totals.Lines++
		if parsed {
			src.Events++
			c.Totals.Events++
		}
		if unparsed {
			src.Unparsed++
			c.Totals.Unparsed++
		}
	})
}

// Excluded counts an event dropped by its source's exclusions.
func (s *Store) Excluded(source string) {
	s.record(func(c *Counts) {
		c.source(source).Excluded++
		c.Totals.Excluded++
	})
}

// Matched counts the rules that matched an event, and the alerts raised.
func (s *Store) Matched(rules []string, alerts []string) {
	if len(rules) == 0 && len(alerts) == 0 {
		return
	}
	s.record(func(c *Counts) {
		for _, id := range rules {
			c.rule(id).Matches++
			c.Totals.Matches++
		}
		for _, id := range alerts {
			c.rule(id).Alerts++
			c.Totals.Alerts++
		}
	})
}

// Total returns the counters since the store was created.
func (s *Store) Total() *Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := newCounts()
	c.add(s.total)
	return c
}

// skeleton returns empty counters for every source and rule known.
func (s *Store) skeleton() *Counts {
	c := newCounts()
	for id := range s.total.Sources {
		c.source(id)
	}
	for id := range s.total.Rules {
		c.rule(id)
	}
	return c
}

// Interval returns the counters of the buckets that start in [from, to).
func (s *Store) Interval(from, to time.Time) *Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.skeleton()
	for _, b := range s.buckets {
		if !b.start.Before(from.Truncate(Resolution)) && b.start.Before(to) {
			c.add(b.Counts)
		}
	}
	return c
}

// Bucket is the counters of a step of a series.
type Bucket struct {
	Start time.Time `json:"start"`
	*Counts
}

// Series returns the counters of [from, to) by step (a multiple of
// Resolution): one bucket per step, from from rounded down to the step,
// empty ones included.
func (s *Store) Series(from, to time.Time, step time.Duration) []Bucket {
	step = max(step.Truncate(Resolution), Resolution)
	start := from.Truncate(step)
	s.mu.Lock()
	defer s.mu.Unlock()
	var series []Bucket
	for t := start; t.Before(to); t = t.Add(step) {
		series = append(series, Bucket{t, s.skeleton()})
	}
	// Buckets are in time order: find the first one in the series.
	i := sort.Search(len(s.buckets), func(i int) bool { return !s.buckets[i].start.Before(start) })
	for ; i < len(s.buckets) && s.buckets[i].start.Before(to); i++ {
		b := s.buckets[i]
		series[int(b.start.Sub(start)/step)].add(b.Counts)
	}
	return series
}

// Oldest returns the start of the oldest bucket kept (zero if none).
func (s *Store) Oldest() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buckets) == 0 {
		return time.Time{}
	}
	return s.buckets[0].start
}

// Expire drops the buckets that ended before cutoff, and returns how many.
func (s *Store) Expire(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := 0
	for i < len(s.buckets) && s.buckets[i].start.Add(Resolution).Before(cutoff) {
		i++
	}
	if i > 0 {
		s.buckets = append([]*bucket(nil), s.buckets[i:]...)
	}
	return i
}
