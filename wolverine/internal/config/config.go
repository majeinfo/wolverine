// Package config loads the wolverine configuration file.
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Allowlist holds the IP addresses and CIDR ranges that blocking actions
	// (ssh) must never act on.
	Allowlist []string `yaml:"allowlist"`
	// StateFile is where the position of every source is saved, so that a
	// restart resumes after the last line or entry processed. Optional.
	StateFile string   `yaml:"state_file"`
	Sources   []Source `yaml:"sources"`
	Actions   []Action `yaml:"actions"`
	Rules     []Rule   `yaml:"rules"`
}

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

// Load reads and decodes the configuration file. Unknown keys are rejected
// so that typos do not silently disable part of a rule.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}
