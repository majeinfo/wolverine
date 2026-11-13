// Package engine wires the pipeline together: sources -> parsers ->
// processors (enrichment, then exclude lists) -> detection rules -> actions.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"wolverine/internal/action"
	"wolverine/internal/config"
	"wolverine/internal/detection"
	"wolverine/internal/event"
	"wolverine/internal/parser"
	"wolverine/internal/processor"
	"wolverine/internal/processor/enrichment"
	"wolverine/internal/processor/filter"
	"wolverine/internal/source"
	"wolverine/internal/state"
	"wolverine/internal/stats"
	"wolverine/internal/verbose"
)

// maxLoggedParseErrors is the number of unparsed lines logged per source;
// the others are only counted.
const maxLoggedParseErrors = 10

type input struct {
	source source.Source
	parser parser.Parser
	typ    string // source type in the configuration

	lines, unparsed, excluded atomic.Int64
}

type Engine struct {
	inputs     []*input
	processors []processor.Processor
	detector   *detection.Engine
	routes     map[string][]action.Action
	undo       *action.Scheduler
	state      *state.Store // nil: positions are not saved
	history    history
	stats      *stats.Store
	watchers   hub
	info       Info

	// MaxLifetime is how long the data memorized by the rules and the
	// alerts raised are kept (from max_lifetime, DefaultMaxLifetime if not
	// set). Run flushes them periodically.
	MaxLifetime time.Duration

	// Alerts receives every alert as a JSON line (nil: not written).
	Alerts io.Writer
	// AlertEvents tells which of the events that raised an alert are
	// included in the alerts written to Alerts. Actions always get them all.
	AlertEvents AlertEvents
	// Events receives every event as a JSON line, after the processors and
	// before the detection rules (nil: not written).
	Events io.Writer
}

// AlertEvents tells which events an alert written to Engine.Alerts includes.
type AlertEvents int

const (
	// NoAlertEvents leaves the events out: the count is in Metadata.
	NoAlertEvents AlertEvents = iota
	// LastAlertEvent includes the last event, the one that raised the
	// alert.
	LastAlertEvent
	// AllAlertEvents includes every event.
	AllAlertEvents
)

// apply returns the alert as written: a copy when events are left out.
func (m AlertEvents) apply(a *event.Alert) *event.Alert {
	if m == AllAlertEvents || len(a.Events) == 0 {
		return a
	}
	short := *a
	short.Events = nil
	if m == LastAlertEvent {
		short.Events = a.Events[len(a.Events)-1:]
	}
	return &short
}

// New builds the engine described by the configuration.
func New(cfg *config.Config) (*Engine, error) {
	inputs, err := buildSources(cfg.Sources)
	if err != nil {
		return nil, err
	}
	exclude, ruleConditions, err := buildExclude(cfg)
	if err != nil {
		return nil, err
	}
	rules, err := detection.BuildRules(cfg.Rules, ruleConditions)
	if err != nil {
		return nil, err
	}
	lifetime := cfg.MaxLifetime
	if lifetime == 0 {
		lifetime = config.DefaultMaxLifetime
	}
	if err := checkLifetime(cfg.Rules, lifetime); err != nil {
		return nil, err
	}
	actions, err := action.Build(cfg.Actions)
	if err != nil {
		return nil, err
	}
	routes, err := action.Routes(cfg.Rules, actions)
	if err != nil {
		return nil, err
	}
	undos, err := action.BuildUndos(cfg.Actions, actions)
	if err != nil {
		return nil, err
	}
	describe(cfg)
	verbose.Infof("maximum lifetime of the memorized data and alerts: %s", lifetime)
	info := Info{MaxLifetime: lifetime.String()}
	var sourceIDs, ruleIDs []string
	for _, in := range inputs {
		sourceIDs = append(sourceIDs, in.source.Name())
		info.Sources = append(info.Sources, SourceInfo{ID: in.source.Name(), Type: in.typ})
	}
	for _, r := range cfg.Rules {
		if !r.Disabled {
			ruleIDs = append(ruleIDs, r.ID)
			info.Rules = append(info.Rules, RuleInfo{ID: r.ID, Description: r.Description, Severity: r.Severity, Actions: append([]string{}, r.Actions...)})
		}
	}
	e := &Engine{
		inputs:      inputs,
		processors:  []processor.Processor{enrichment.SSHD{}, exclude},
		detector:    &detection.Engine{Rules: rules},
		routes:      routes,
		undo:        action.NewScheduler(undos, actions),
		stats:       stats.New(sourceIDs, ruleIDs),
		info:        info,
		MaxLifetime: lifetime,
	}
	e.info.Started = e.stats.Started()
	e.undo.Report = e.recordAction
	if len(undos) > 0 && cfg.StateFile == "" {
		log.Print("warning: without a state file, the actions not undone yet when wolverine stops are never undone")
	}
	if cfg.StateFile != "" {
		if e.state, err = state.Open(cfg.StateFile); err != nil {
			return nil, err
		}
		// Forget the sources removed from the configuration; disabled ones
		// keep their position.
		var ids []string
		for _, s := range cfg.Sources {
			ids = append(ids, s.ID)
		}
		e.state.Retain(ids)
		if err := e.resume(); err != nil {
			return nil, err
		}
		e.restoreRules(time.Now().Add(-lifetime))
		// The alerts first: restoring the undos may add to their action
		// logs.
		if saved := e.state.Alerts(); len(saved) > 0 {
			n := e.history.restore(saved, time.Now().Add(-lifetime))
			verbose.Infof("state file: %d alerts restored, %d expired", n, len(saved)-n)
		}
		var pending []action.Pending
		for _, u := range e.state.Undos() {
			pending = append(pending, action.Pending(u))
		}
		e.undo.Restore(pending)
	}
	return e, nil
}

// checkLifetime checks that no rule needs to memorize data longer than the
// maximum lifetime.
func checkLifetime(rules []config.Rule, lifetime time.Duration) error {
	if lifetime < 0 {
		return fmt.Errorf("max_lifetime must be a positive duration (e.g. 24h)")
	}
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		if r.Window > lifetime {
			return fmt.Errorf("rule %q: window %s exceeds the maximum lifetime %s (max_lifetime or -max-lifetime)", r.ID, r.Window, lifetime)
		}
		if r.Suppress > lifetime {
			return fmt.Errorf("rule %q: suppress %s exceeds the maximum lifetime %s (max_lifetime or -max-lifetime)", r.ID, r.Suppress, lifetime)
		}
	}
	return nil
}

// expireInterval returns how often the data older than lifetime is flushed:
// a tenth of it, between a second and a minute.
func expireInterval(lifetime time.Duration) time.Duration {
	return min(max(lifetime/10, time.Second), time.Minute)
}

// expire flushes the data memorized by the rules and the alerts raised
// before cutoff.
func (e *Engine) expire(cutoff time.Time) {
	n := e.detector.Expire(cutoff)
	a := e.history.expire(cutoff)
	e.stats.Expire(cutoff)
	if n > 0 || a > 0 {
		verbose.Debugf("expired (memorized before %s): %d rule data, %d alerts", cutoff.Format(time.DateTime), n, a)
	}
}

// Info describes the engine: its sources and rules.
type Info struct {
	Started     time.Time    `json:"started"`
	MaxLifetime string       `json:"max_lifetime"`
	Sources     []SourceInfo `json:"sources"`
	Rules       []RuleInfo   `json:"rules"`
}

type SourceInfo struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type RuleInfo struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Actions     []string `json:"actions"`
}

// Info describes the engine's sources and enabled rules.
func (e *Engine) Info() Info { return e.info }

// Stats returns the counters of what the engine processed.
func (e *Engine) Stats() *stats.Store { return e.stats }

// Watch returns a channel that receives the alerts raised from now on, and
// the runs added to their action logs, and a function to call when done.
// The channel is closed when Run returns, or if the receiver lags too far
// behind.
func (e *Engine) Watch() (<-chan Notice, func()) { return e.watchers.subscribe() }

// RecentAlerts returns the alerts raised within the maximum lifetime, oldest
// first, with all their events.
func (e *Engine) RecentAlerts() []*event.Alert {
	return e.history.list()
}

// AlertRecords returns the alerts raised within the maximum lifetime, oldest
// first, with all their events and their action logs.
func (e *Engine) AlertRecords() []AlertRecord {
	return e.history.records()
}

// recordAction adds a run to the action log of an alert (if still
// memorized) and tells the watchers.
func (e *Engine) recordAction(alertID string, run event.ActionRun) {
	if a := e.history.record(alertID, run); a != nil {
		e.watchers.publish(Notice{Alert: a, Action: &run})
	}
}

// buildExclude resolves the exclude lists, checks those the sources and
// rules name, and compiles their exclude_if conditions. The processor only
// checks the lists of the enabled ones. The rules' conditions are returned
// by rule id.
func buildExclude(cfg *config.Config) (*filter.Exclude, map[string]func(*event.Event) bool, error) {
	lists, err := filter.BuildLists(cfg.ExcludeLists)
	if err != nil {
		return nil, nil, err
	}
	x := &filter.Exclude{Sources: map[string][]*filter.List{}, Conditions: map[string]*filter.Condition{}}
	// A rule sees the events of every source: its conditions can use the
	// groups of all their regexps.
	var allGroups []string
	for _, s := range cfg.Sources {
		if !s.Disabled {
			allGroups = append(allGroups, regexpGroups(s.Regexp)...)
		}
	}
	for _, s := range cfg.Sources {
		if s.ExcludeIf != "" {
			cond, err := filter.CompileCondition(s.ExcludeIf, regexpGroups(s.Regexp), lists)
			if err != nil {
				return nil, nil, fmt.Errorf("source %q: exclude_if: %w", s.ID, err)
			}
			cond.Owner = fmt.Sprintf("source %q", s.ID)
			if !s.Disabled {
				x.Conditions[s.ID] = cond
			}
		}
		for _, id := range s.Exclude {
			l, ok := lists[id]
			if !ok {
				return nil, nil, fmt.Errorf("source %q: exclude: unknown exclude list %q", s.ID, id)
			}
			if !s.Disabled && !slices.Contains(x.Sources[s.ID], l) {
				x.Sources[s.ID] = append(x.Sources[s.ID], l)
			}
		}
	}
	used := map[string]bool{}
	ruleConditions := map[string]func(*event.Event) bool{}
	for _, r := range cfg.Rules {
		if r.ExcludeIf != "" {
			cond, err := filter.CompileCondition(r.ExcludeIf, allGroups, lists)
			if err != nil {
				return nil, nil, fmt.Errorf("rule %q: exclude_if: %w", r.ID, err)
			}
			cond.Owner = fmt.Sprintf("rule %q", r.ID)
			ruleConditions[r.ID] = cond.Excludes
		}
		for _, id := range r.Exclude {
			l, ok := lists[id]
			if !ok {
				return nil, nil, fmt.Errorf("rule %q: exclude: unknown exclude list %q", r.ID, id)
			}
			if !r.Disabled && !used[id] {
				used[id] = true
				x.Lists = append(x.Lists, l)
			}
		}
	}
	return x, ruleConditions, nil
}

// restoreRules gives each rule the data it saved, except what was memorized
// before cutoff, and forgets the data of the rules that are gone.
func (e *Engine) restoreRules(cutoff time.Time) {
	var ids []string
	for _, r := range e.detector.Rules {
		ids = append(ids, r.ID())
		data := e.state.Rule(r.ID())
		if data == nil {
			continue
		}
		n, err := r.Restore(data, cutoff)
		switch {
		case errors.Is(err, detection.ErrRuleChanged):
			verbose.Infof("rule %s: saved data ignored: the rule changed (match, exclude, exclude_if or group_by)", r.ID())
		case err != nil:
			// Better start without the data than not start.
			log.Printf("state file %s: rule %s: %v (data ignored)", e.state.Path(), r.ID(), err)
		default:
			verbose.Infof("rule %s: %d events and suppressions restored", r.ID(), n)
		}
	}
	e.state.RetainRules(ids)
}

// resume gives each source its saved positions.
func (e *Engine) resume() error {
	for _, in := range e.inputs {
		r, ok := in.source.(source.Resumer)
		if !ok {
			continue
		}
		pos := e.state.Get(in.source.Name(), in.typ)
		if pos == nil {
			verbose.Infof("source %s: no saved position, starting from start_at", in.source.Name())
			continue
		}
		if err := r.Resume(pos); err != nil {
			return fmt.Errorf("state file %s: source %s: %w", e.state.Path(), in.source.Name(), err)
		}
	}
	return nil
}

// stateSaveInterval is how often the state file is written while events
// keep coming. It is also written when Run returns.
const stateSaveInterval = 5 * time.Second

// item is a record read from a source, once parsed, or a change of the
// source's positions.
type item struct {
	in       *input
	ev       *event.Event // nil for an empty line or a change of positions
	line     bool         // a line was read (maybe empty)
	unparsed bool         // the line did not match the regexp
	key      string
	position any
	forget   []string
	// start, when set, replaces all the positions of the source: where it
	// starts, given right after Open.
	start map[string]any
	done  func() // source.Record.Done
}

// Run reads every source until they are all exhausted (sources that follow
// their file never are) or ctx is cancelled. It returns the first source
// error, after having processed the events of the other sources.
func (e *Engine) Run(ctx context.Context) error {
	verbose.Infof("starting: %d sources, %d rules", len(e.inputs), len(e.detector.Rules))

	events := make(chan item, 1024)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)
	for _, in := range e.inputs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.read(ctx, in, events); err != nil {
				log.Printf("source %s: %v", in.source.Name(), err)
				errOnce.Do(func() { firstErr = fmt.Errorf("source %s: %w", in.source.Name(), err) })
			}
		}()
	}
	go func() {
		wg.Wait()
		close(events)
	}()

	e.undo.Start()
	dispatcher := action.NewDispatcher(ctx, e.routes, 100, e.undo, e.recordAction)
	var alertEnc, eventEnc *json.Encoder
	if e.Alerts != nil {
		alertEnc = json.NewEncoder(e.Alerts)
	}
	if e.Events != nil {
		eventEnc = json.NewEncoder(e.Events)
	}

	lifetime := e.MaxLifetime
	if lifetime <= 0 {
		lifetime = config.DefaultMaxLifetime
	}
	expireTicker := time.NewTicker(expireInterval(lifetime))
	defer expireTicker.Stop()

	var tick <-chan time.Time
	if e.state != nil {
		t := time.NewTicker(stateSaveInterval)
		defer t.Stop()
		tick = t.C
	}

	var nEvents, nAlerts int
	handle := func(it item) {
		// The position is recorded once the event has been processed, so a
		// restart never skips an event that was read but not processed.
		defer e.setPosition(it)
		if it.done != nil {
			defer it.done()
		}
		if it.line {
			e.stats.Line(it.in.source.Name(), it.ev != nil && !it.unparsed, it.unparsed)
		}
		if it.ev == nil {
			return
		}
		nEvents++
		ev := e.process(ctx, it.ev)
		if ev == nil {
			it.in.excluded.Add(1) // only the exclude lists drop events
			e.stats.Excluded(it.in.source.Name())
			return
		}
		if eventEnc != nil {
			if err := eventEnc.Encode(ev); err != nil {
				log.Printf("writing event: %v", err)
			}
		}
		matched, alerts := e.detector.Process(ev)
		var alerted []string
		for _, a := range alerts {
			alerted = append(alerted, a.RuleID)
		}
		e.stats.Matched(matched, alerted)
		for _, a := range alerts {
			nAlerts++
			e.history.add(a, time.Now())
			verbose.Infof("alert %s: %s", a.RuleID, a.Message)
			if alertEnc != nil {
				if err := alertEnc.Encode(e.AlertEvents.apply(a)); err != nil {
					log.Printf("writing alert: %v", err)
				}
			}
			// The alert first, then what its actions do.
			e.watchers.publish(Notice{Alert: a})
			dispatcher.Dispatch(a)
		}
	}

loop:
	for {
		select {
		case <-tick:
			e.saveState()
		case now := <-expireTicker.C:
			e.expire(now.Add(-lifetime))
		case it, ok := <-events:
			if !ok {
				break loop
			}
			handle(it)
		}
	}
	dispatcher.Close()
	e.undo.Stop()
	// After the actions: the watchers get what they did.
	e.watchers.close()
	e.saveState()
	if pending, _ := e.undo.Pending(); len(pending) > 0 {
		where := "saved in the state file"
		if e.state == nil {
			where = "lost: no state file"
		}
		log.Printf("%d actions not undone yet (%s), the first one due at %s", len(pending), where, pending[0].Due.Format(time.DateTime))
	}

	for _, in := range e.inputs {
		msg := fmt.Sprintf("source %s: %d lines, %d unparsed", in.source.Name(), in.lines.Load(), in.unparsed.Load())
		if n := in.excluded.Load(); n > 0 {
			msg += fmt.Sprintf(", %d excluded", n)
		}
		log.Print(msg)
	}
	log.Printf("%d events, %d alerts", nEvents, nAlerts)
	return firstErr
}

func (e *Engine) setPosition(it item) {
	if e.state == nil {
		return
	}
	id := it.in.source.Name()
	var err error
	if it.start != nil {
		err = e.state.Replace(id, it.in.typ, it.start)
	}
	e.state.Delete(id, it.forget...)
	if it.position != nil && err == nil {
		err = e.state.Set(id, it.in.typ, it.key, it.position)
	}
	if err != nil {
		log.Printf("source %s: position: %v", id, err)
	}
}

func (e *Engine) saveState() {
	if e.state == nil {
		return
	}
	for _, r := range e.detector.Rules {
		data, changed, err := r.Save()
		if err != nil {
			log.Printf("rule %s: saving its data: %v", r.ID(), err)
		} else if changed {
			e.state.SetRule(r.ID(), data)
		}
	}
	if alerts, changed := e.history.saved(); changed {
		e.state.SetAlerts(alerts)
	}
	if pending, changed := e.undo.Pending(); changed {
		undos := make([]state.Undo, len(pending))
		for i, p := range pending {
			undos[i] = state.Undo(p)
		}
		e.state.SetUndos(undos)
	}
	if err := e.state.Save(); err != nil {
		log.Print(err)
		return
	}
	verbose.Debugf("state saved in %s", e.state.Path())
}

// read sends the events of one source until it is exhausted or ctx is
// cancelled.
func (e *Engine) read(ctx context.Context, in *input, events chan<- item) error {
	if err := in.source.Open(ctx); err != nil {
		return err
	}
	defer in.source.Close()

	// Save where the source starts, in case nothing is read before the
	// next restart. This also drops the saved positions that no longer
	// apply (log files gone).
	if r, ok := in.source.(source.Resumer); ok {
		start, err := r.Positions()
		if err != nil {
			return err
		}
		if start == nil {
			start = map[string]any{}
		}
		select {
		case events <- item{in: in, start: start}:
		case <-ctx.Done():
			return nil
		}
	}

	for {
		rec, err := in.source.Read(ctx)
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
		if rec.Data == nil {
			// No line: only a change of positions.
			select {
			case events <- item{in: in, forget: rec.Forget, key: rec.PositionKey, position: rec.Position, done: rec.Done}:
			case <-ctx.Done():
				return nil
			}
			continue
		}
		n := in.lines.Add(1)
		it := item{in: in, key: rec.PositionKey, position: rec.Position, done: rec.Done, line: true}
		if len(rec.Data) > 0 {
			ev, err := in.parser.Parse(rec)
			if err != nil {
				it.unparsed = true
				switch u := in.unparsed.Add(1); {
				case u <= maxLoggedParseErrors || verbose.Level >= 2:
					log.Printf("source %s: line %d: %v: %q", in.source.Name(), n, err, rec.Data)
				case u == maxLoggedParseErrors+1:
					log.Printf("source %s: more unparsed lines, not logged (use -v -v to see them all)", in.source.Name())
				}
			}
			it.ev = ev
		}
		select {
		case events <- it:
		case <-ctx.Done():
			return nil
		}
	}
}

func (e *Engine) process(ctx context.Context, ev *event.Event) *event.Event {
	for _, p := range e.processors {
		var err error
		if ev, err = p.Process(ctx, ev); err != nil {
			log.Printf("processor %s: %v", p.Name(), err)
		}
		if ev == nil {
			return nil // dropped by the processor
		}
	}
	return ev
}
