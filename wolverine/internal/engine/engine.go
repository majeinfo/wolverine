// Package engine wires the pipeline together: sources -> parsers ->
// processors -> detection rules -> actions.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	"wolverine/internal/source"
	"wolverine/internal/state"
	"wolverine/internal/verbose"
)

// maxLoggedParseErrors is the number of unparsed lines logged per source;
// the others are only counted.
const maxLoggedParseErrors = 10

type input struct {
	source source.Source
	parser parser.Parser
	typ    string // source type in the configuration

	lines, unparsed atomic.Int64
}

type Engine struct {
	inputs     []*input
	processors []processor.Processor
	detector   *detection.Engine
	routes     map[string][]action.Action
	state      *state.Store // nil: positions are not saved

	// Alerts receives every alert as a JSON line (nil: not written).
	Alerts io.Writer
	// Events receives every event as a JSON line, after the processors and
	// before the detection rules (nil: not written).
	Events io.Writer
}

// New builds the engine described by the configuration.
func New(cfg *config.Config) (*Engine, error) {
	inputs, err := buildSources(cfg.Sources)
	if err != nil {
		return nil, err
	}
	rules, err := detection.BuildRules(cfg.Rules)
	if err != nil {
		return nil, err
	}
	actions, err := action.Build(cfg.Actions, cfg.Allowlist)
	if err != nil {
		return nil, err
	}
	routes, err := action.Routes(cfg.Rules, actions)
	if err != nil {
		return nil, err
	}
	describe(cfg)
	e := &Engine{
		inputs:     inputs,
		processors: []processor.Processor{enrichment.SSHD{}},
		detector:   &detection.Engine{Rules: rules},
		routes:     routes,
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
	}
	return e, nil
}

// resume gives each source its saved position.
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

// item is a record read from a source, once parsed.
type item struct {
	in       *input
	ev       *event.Event // nil for an empty line
	position any
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

	dispatcher := action.NewDispatcher(ctx, e.routes, 100)
	var alertEnc, eventEnc *json.Encoder
	if e.Alerts != nil {
		alertEnc = json.NewEncoder(e.Alerts)
	}
	if e.Events != nil {
		eventEnc = json.NewEncoder(e.Events)
	}

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
		if it.ev == nil {
			return
		}
		nEvents++
		ev := e.process(ctx, it.ev)
		if ev == nil {
			return
		}
		if eventEnc != nil {
			if err := eventEnc.Encode(ev); err != nil {
				log.Printf("writing event: %v", err)
			}
		}
		for _, a := range e.detector.Evaluate(ev) {
			nAlerts++
			verbose.Infof("alert %s: %s", a.RuleID, a.Message)
			if alertEnc != nil {
				if err := alertEnc.Encode(a); err != nil {
					log.Printf("writing alert: %v", err)
				}
			}
			dispatcher.Dispatch(a)
		}
	}

loop:
	for {
		select {
		case <-tick:
			e.saveState()
		case it, ok := <-events:
			if !ok {
				break loop
			}
			handle(it)
		}
	}
	dispatcher.Close()
	e.saveState()

	for _, in := range e.inputs {
		log.Printf("source %s: %d lines, %d unparsed", in.source.Name(), in.lines.Load(), in.unparsed.Load())
	}
	log.Printf("%d events, %d alerts", nEvents, nAlerts)
	return firstErr
}

func (e *Engine) setPosition(it item) {
	if e.state == nil || it.position == nil {
		return
	}
	if err := e.state.Set(it.in.source.Name(), it.in.typ, it.position); err != nil {
		log.Printf("source %s: position: %v", it.in.source.Name(), err)
	}
}

func (e *Engine) saveState() {
	if e.state == nil {
		return
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
	// next restart.
	if r, ok := in.source.(source.Resumer); ok {
		pos, err := r.Position()
		if err != nil {
			return err
		}
		if pos != nil {
			select {
			case events <- item{in: in, position: pos}:
			case <-ctx.Done():
				return nil
			}
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
		n := in.lines.Add(1)
		it := item{in: in, position: rec.Position}
		if len(rec.Data) > 0 {
			ev, err := in.parser.Parse(rec)
			if err != nil {
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
