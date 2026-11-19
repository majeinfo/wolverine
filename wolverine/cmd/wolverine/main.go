// Command wolverine reads the sources described in its configuration (log
// files...), parses and enriches their lines, runs the detection rules on
// them and runs the actions (email, ssh, webhook) attached to the rules that
// fire. Alerts are also written as JSON lines on stdout.
//
//	wolverine -config config/wolverine.yaml
//
// With -events FILE, every event is appended to FILE as a JSON line, after
// parsing and enrichment, which helps to check the regexp of a source.
// "-events -" writes them on stdout, mixed with the alerts.
//
// -state FILE overrides the state_file of the configuration (where the
// position of each source is saved); "-state none" disables it.
//
// -max-lifetime DURATION overrides the max_lifetime of the configuration:
// how long the data memorized by the rules and the alerts raised are kept.
//
// -log-ttl DURATION overrides the log_ttl of the configuration (default 1h):
// how long the log lines are kept in memory (and in the state file). After
// it, an event counted by a rule keeps only its time, and an alert only its
// last event.
//
// -memory-limit PERCENT overrides the memory_limit of the configuration
// (default 60): the percentage of the memory (of the machine, or of the
// cgroup if lower) wolverine may use. Above it, the least recently
// memorized log lines, then events and alerts, are forgotten. 0: no limit.
//
// -http ADDR overrides the http.listen of the configuration: the address of
// the embedded web server (REST API and dashboard); "-http none" disables
// it. When it runs, wolverine keeps serving after reading sources that are
// not followed, until it is stopped.
//
// -v describes the configuration and what wolverine is doing on stderr;
// -v -v (or -vv) adds debugging details.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/engine"
	"wolverine/internal/verbose"
	"wolverine/internal/web"
)

func main() {
	configPath := flag.String("config", "config/wolverine.yaml", "configuration file")
	flag.Var(verbose.Flag{Step: 1}, "v", "verbose: describe the configuration and the activity (repeat for debug details)")
	flag.Var(verbose.Flag{Step: 2}, "vv", "same as -v -v")
	statePath := flag.String("state", "", "state `file` where the position of each source is saved, overriding state_file (\"none\": do not save positions)")
	eventsPath := flag.String("events", "", "append every parsed event as a JSON line to this `file` (\"-\": stdout)")
	detailedEvents := flag.Bool("detailed-events", false, "include in the alerts written to stdout the events (log lines) that raised them")
	maxLifetime := flag.Duration("max-lifetime", 0, "how long the data memorized by the rules (events counted, suppressions) and the alerts raised are kept, e.g. 12h, overriding max_lifetime (default 24h)")
	logTTL := flag.Duration("log-ttl", 0, "how long the log lines are kept in memory and in the state file, e.g. 30m, overriding log_ttl (default 1h); after it, an event counted keeps only its time and an alert its last event")
	memoryLimit := flag.Int("memory-limit", -1, "`percentage` of the memory (of the machine, or of the cgroup if lower) wolverine may use, overriding memory_limit (default 60); above it, the oldest log lines, then events and alerts, are forgotten. 0: no limit")
	httpAddr := flag.String("http", "", "`address` of the web server (REST API and dashboard), e.g. 127.0.0.1:8080, overriding http.listen (\"none\": no web server)")
	minimalEvents := flag.Bool("minimal-events", false, "include in the alerts written to stdout the last event (log line) that raised them")
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("wolverine: ")

	alertEvents := engine.NoAlertEvents
	switch {
	case *detailedEvents && *minimalEvents:
		log.Fatal("-detailed-events and -minimal-events cannot be used together")
	case *detailedEvents:
		alertEvents = engine.AllAlertEvents
	case *minimalEvents:
		alertEvents = engine.LastAlertEvent
	}

	if abs, err := filepath.Abs(*configPath); err == nil {
		verbose.Infof("configuration file: %s", abs)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *maxLifetime < 0 {
		log.Fatal("-max-lifetime must be a positive duration")
	}
	if *maxLifetime > 0 {
		cfg.MaxLifetime = *maxLifetime
	}
	if *logTTL < 0 {
		log.Fatal("-log-ttl must be a positive duration")
	}
	if *logTTL > 0 {
		cfg.LogTTL = *logTTL
	}
	if *memoryLimit > 100 || *memoryLimit < -1 {
		log.Fatal("-memory-limit: a percentage, from 0 (no limit) to 100")
	}
	if *memoryLimit >= 0 {
		cfg.MemoryLimit = memoryLimit
	}
	switch *httpAddr {
	case "":
	case "none":
		cfg.HTTP.Listen = ""
	default:
		cfg.HTTP.Listen = *httpAddr
	}
	switch *statePath {
	case "":
	case "none":
		cfg.StateFile = ""
	default:
		cfg.StateFile = *statePath
	}
	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("%s: %v", *configPath, err)
	}
	eng.Alerts = os.Stdout
	eng.AlertEvents = alertEvents
	switch *eventsPath {
	case "":
	case "-":
		eng.Events = os.Stdout
		verbose.Infof("events written to stdout")
	default:
		f, err := os.OpenFile(*eventsPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		eng.Events = f
		verbose.Infof("events appended to %s", *eventsPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var srv *web.Server
	if cfg.HTTP.Listen != "" {
		if srv, err = web.New(eng, cfg.HTTP); err != nil {
			log.Fatalf("%s: %v", *configPath, err)
		}
		if err := srv.Start(); err != nil {
			log.Fatal(err)
		}
	}

	runErr := eng.Run(ctx)
	if srv != nil {
		if runErr == nil && ctx.Err() == nil {
			// The sources are read: keep showing the results.
			log.Printf("all sources read; the web server on http://%s/ keeps running until wolverine is stopped (Ctrl-C)", srv.Addr())
			<-ctx.Done()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("http: %v", err)
		}
		cancel()
	}
	if runErr != nil {
		log.Fatal(runErr)
	}
}
