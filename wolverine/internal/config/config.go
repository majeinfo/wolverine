// Package config loads the wolverine configuration: a main file and the
// *.yaml / *.yml files of its include directory.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Allowlist holds the IP addresses and CIDR ranges that blocking actions
	// (ssh) must never act on.
	Allowlist []string `yaml:"allowlist"`
	// StateFile is where the position of every source is saved, so that a
	// restart resumes after the last line or entry processed. Optional.
	StateFile string `yaml:"state_file"`
	// IncludeDir is a directory of additional configuration files, relative
	// to the main file's directory. Absent: DefaultIncludeDir, if it exists.
	// Empty: no include directory.
	IncludeDir *string  `yaml:"include_dir"`
	Sources    []Source `yaml:"sources"`
	Actions    []Action `yaml:"actions"`
	Rules      []Rule   `yaml:"rules"`

	// Files lists the files the configuration was read from: the main file
	// first, then the included ones in the order they were read.
	Files []string `yaml:"-"`
}

// DefaultIncludeDir is the include directory used when the main file does
// not set include_dir.
const DefaultIncludeDir = "rules.d"

// Source describes where events come from. Which fields apply depends on
// Type.
type Source struct {
	ID       string `yaml:"id"`
	Type     string `yaml:"type"`
	Disabled bool   `yaml:"disabled"`

	// logfile: the file to read, or the files of Directory whose names
	// match FilenameRegexp.
	Path           string `yaml:"path"`
	Directory      string `yaml:"directory"`
	FilenameRegexp string `yaml:"filename_regexp"`
	// systemd-service: the service whose journal entries are read, e.g.
	// "sshd" or "sshd.service".
	Unit string `yaml:"unit"`

	// Follow keeps reading new lines as they are appended, like tail -F
	// (logfile) or journalctl -f (systemd-service).
	Follow bool `yaml:"follow"`
	// StartAt is "beginning" (default) or "end" (only new lines; requires
	// follow). When state_file holds a position for the source, it is used
	// instead.
	StartAt string `yaml:"start_at"`
	// Regexp parses each line; its named groups fill the event fields.
	// Required for logfile. Optional for systemd-service, where it is
	// applied to the message only, the other fields coming from the journal.
	Regexp string `yaml:"regexp"`

	// logfile only. TimestampFormats parse the "timestamp" group: rfc3164, rfc3339 or a
	// Go time layout. Default: [rfc3164, rfc3339].
	TimestampFormats []string `yaml:"timestamp_formats"`
	// Timezone for timestamps without one (default: local time).
	Timezone string `yaml:"timezone"`
	// Category set on the events (default: system).
	Category string `yaml:"category"`
}

// Action describes what to do when an alert fires. Which fields apply
// depends on Type.
type Action struct {
	ID       string `yaml:"id"`
	Type     string `yaml:"type"`
	Disabled bool   `yaml:"disabled"`

	// email
	SMTP      SMTP     `yaml:"smtp"`
	From      string   `yaml:"from"`
	To        []string `yaml:"to"`
	MaxEvents int      `yaml:"max_events"`

	// ssh
	SSH     SSH    `yaml:"ssh"`
	Command string `yaml:"command"`

	// webhook
	Webhook Webhook `yaml:"webhook"`
	// UseAllowlist skips the alerts involving an allowlisted IP (always on
	// for ssh actions).
	UseAllowlist bool `yaml:"use_allowlist"`
}

type Webhook struct {
	URL string `yaml:"url"`
	// URLEnv names the environment variable holding the URL, for services
	// where the URL itself is the secret (Slack, Teams...).
	URLEnv  string            `yaml:"url_env"`
	Headers map[string]string `yaml:"headers"`
	// HeadersEnv maps header names to the environment variables holding
	// their values (tokens), so that they are not stored in the file.
	HeadersEnv map[string]string `yaml:"headers_env"`
	Timeout    time.Duration     `yaml:"timeout"`
	Retries    int               `yaml:"retries"`
	// Body is a template for the request body (default: the alert as JSON).
	Body string `yaml:"body"`
	// Escape is how values are escaped in Body: json (default) or slack.
	Escape string `yaml:"escape"`
}

type SSH struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	User         string        `yaml:"user"`
	IdentityFile string        `yaml:"identity_file"`
	Timeout      time.Duration `yaml:"timeout"`
}

type SMTP struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	// PasswordEnv names the environment variable holding the password, so
	// that it is not stored in the configuration file.
	PasswordEnv string        `yaml:"password_env"`
	Timeout     time.Duration `yaml:"timeout"`
}

// Rule describes a detection rule. Which fields apply depends on Type.
type Rule struct {
	ID          string `yaml:"id"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Disabled    bool   `yaml:"disabled"`
	Match       Match  `yaml:"match"`
	// Actions lists the ids of the actions run when the rule fires.
	Actions []string `yaml:"actions"`

	// threshold
	GroupBy string        `yaml:"group_by"`
	Count   int           `yaml:"count"`
	Window  time.Duration `yaml:"window"`
	// Suppress silences further alerts for the same group during this
	// duration after an alert (0 = never).
	Suppress time.Duration `yaml:"suppress"`
}

type Match struct {
	Category  string   `yaml:"category"`
	Service   string   `yaml:"service"`
	Action    string   `yaml:"action"`
	Status    string   `yaml:"status"`
	HasFields []string `yaml:"has_fields"`
}

// Load reads the main configuration file, then the *.yaml and *.yml files of
// its include directory in lexical order. The allowlist, sources, actions and
// rules of the included files are added to those of the main file;
// state_file and include_dir may only be set in the main file. Unknown keys
// are rejected so that typos do not silently disable part of a rule.
func Load(path string) (*Config, error) {
	cfg, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	cfg.Files = []string{path}

	ids := newIDs()
	if err := ids.add(cfg, path); err != nil {
		return nil, err
	}

	dir, required := DefaultIncludeDir, false
	if cfg.IncludeDir != nil {
		dir, required = *cfg.IncludeDir, true
	}
	if dir == "" {
		return cfg, nil
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(filepath.Dir(path), dir)
	}
	files, err := includedFiles(dir, required)
	if err != nil {
		return nil, fmt.Errorf("%s: include_dir: %w", path, err)
	}
	for _, f := range files {
		part, err := loadFile(f)
		if err != nil {
			return nil, err
		}
		if part.StateFile != "" || part.IncludeDir != nil {
			return nil, fmt.Errorf("%s: state_file and include_dir are only allowed in the main configuration file %s", f, path)
		}
		if err := ids.add(part, f); err != nil {
			return nil, err
		}
		cfg.Allowlist = append(cfg.Allowlist, part.Allowlist...)
		cfg.Sources = append(cfg.Sources, part.Sources...)
		cfg.Actions = append(cfg.Actions, part.Actions...)
		cfg.Rules = append(cfg.Rules, part.Rules...)
		cfg.Files = append(cfg.Files, f)
	}
	return cfg, nil
}

// loadFile decodes one configuration file. An empty file is valid.
func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// includedFiles returns the configuration files of dir, sorted by name:
// regular files (or links to them) named *.yaml or *.yml, except hidden
// ones (editor backups...). Subdirectories are not read. A missing directory
// is an error only if required.
func includedFiles(dir string, required bool) ([]string, error) {
	entries, err := os.ReadDir(dir) // sorted by name
	if errors.Is(err, fs.ErrNotExist) && !required {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		ext := filepath.Ext(name)
		if strings.HasPrefix(name, ".") || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		fi, err := os.Stat(path) // follows links
		if err != nil {
			return nil, err
		}
		if fi.Mode().IsRegular() {
			files = append(files, path)
		}
	}
	return files, nil
}

// ids detects the sources, actions and rules defined twice, possibly in
// different files, and tells where.
type ids map[string]map[string]string // kind -> id -> file

func newIDs() ids {
	return ids{"source": {}, "action": {}, "rule": {}}
}

func (d ids) add(cfg *Config, file string) error {
	check := func(kind, id string) error {
		if id == "" {
			return nil // reported when the configuration is built
		}
		if first, dup := d[kind][id]; dup {
			if first == file {
				return fmt.Errorf("%s: %s %q is defined twice", file, kind, id)
			}
			return fmt.Errorf("%s: %s %q is already defined in %s", file, kind, id, first)
		}
		d[kind][id] = file
		return nil
	}
	for _, s := range cfg.Sources {
		if err := check("source", s.ID); err != nil {
			return err
		}
	}
	for _, a := range cfg.Actions {
		if err := check("action", a.ID); err != nil {
			return err
		}
	}
	for _, r := range cfg.Rules {
		if err := check("rule", r.ID); err != nil {
			return err
		}
	}
	return nil
}
