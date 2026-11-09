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

	"wolverine/internal/config"
	"wolverine/internal/engine"
	"wolverine/internal/verbose"
)

func main() {
	configPath := flag.String("config", "config/wolverine.yaml", "configuration file")
	flag.Var(verbose.Flag{Step: 1}, "v", "verbose: describe the configuration and the activity (repeat for debug details)")
	flag.Var(verbose.Flag{Step: 2}, "vv", "same as -v -v")
	statePath := flag.String("state", "", "state `file` where the position of each source is saved, overriding state_file (\"none\": do not save positions)")
	eventsPath := flag.String("events", "", "append every parsed event as a JSON line to this `file` (\"-\": stdout)")
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("wolverine: ")

	if abs, err := filepath.Abs(*configPath); err == nil {
		verbose.Infof("configuration file: %s", abs)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
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

	if err := eng.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
