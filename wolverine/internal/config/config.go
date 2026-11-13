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
	// ExcludeLists are named lists of IP addresses that rules may ignore
	// (Rule.Exclude).
	ExcludeLists []ExcludeList `yaml:"exclude_lists"`
	// StateFile is where the position of every source is saved, so that a
	// restart resumes after the last line or entry processed. Optional.
	StateFile string `yaml:"state_file"`
	// MaxLifetime is how long the data memorized to evaluate the rules
	// (events counted, suppressions) and the alerts raised are kept, at
	// most. Zero: DefaultMaxLifetime.
	MaxLifetime time.Duration `yaml:"max_lifetime"`
	// HTTP configures the embedded web server (REST API and dashboard).
	HTTP HTTP `yaml:"http"`
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

// ExcludeList is a named list of IP addresses: the events whose Field is
// in it are ignored by the rules that name the list in their exclude.
type ExcludeList struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	// Field is the event field holding the IP address to check: an Event
	// field name (SourceIP, DestIP...) or a key of Event.Fields. Default:
	// SourceIP.
	Field string `yaml:"field"`
	// Entries are IP addresses, CIDR ranges, or ids of other exclude lists
	// whose entries are added.
	Entries []string `yaml:"entries"`
}

// HTTP configures the embedded web server.
type HTTP struct {
	// Listen is the address to listen on, e.g. "127.0.0.1:8080". Empty: no
	// web server.
	Listen string `yaml:"listen"`
	// TokenEnv names the environment variable holding the token the API
	// requires (Authorization: Bearer <token>). Empty: no token.
	TokenEnv string `yaml:"token_env"`
}

// DefaultMaxLifetime is the maximum lifetime when max_lifetime is not set.
const DefaultMaxLifetime = 24 * time.Hour

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
	// match FilenameRegexp. Path may contain date macros in its file name
	// (app.log.${year}-${month}-${day-1}, see package pathtemplate): the
	// file read is then the one named after the current date.
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

	// aws-s3: the SQS queue receiving the notifications of the objects
	// created in the bucket; the objects are downloaded and read line by
	// line.
	QueueURL string `yaml:"queue_url"`
	// aws-s3: only the objects whose key matches it are read (default:
	// all).
	KeyRegexp string `yaml:"key_regexp"`
	// aws-s3: how long a message stays hidden from other receivers while
	// its object is read; extended while reading takes longer (default:
	// 5m).
	VisibilityTimeout time.Duration `yaml:"visibility_timeout"`
	// aws-s3: credentials and region.
	AWS AWS `yaml:"aws"`

	// logfile and aws-s3. TimestampFormats parse the "timestamp" group:
	// rfc3164, rfc3339 or a Go time layout. Default: [rfc3164, rfc3339].
	TimestampFormats []string `yaml:"timestamp_formats"`
	// Timezone for timestamps without one (default: local time).
	Timezone string `yaml:"timezone"`
	// Category set on the events (default: system).
	Category string `yaml:"category"`
	// Exclude lists the ids of the exclude lists whose events are dropped
	// from this source: no rule sees them.
	Exclude []string `yaml:"exclude"`
	// ExcludeIf is a CEL expression: the events of this source for which it
	// is true are dropped too.
	ExcludeIf string `yaml:"exclude_if"`
}

// AWS holds the credentials and region of an aws-s3 source or an
// aws-waf-ipset action. Without any of
// them, the AWS SDK's defaults apply: the AWS_* environment variables, then
// the default profile of ~/.aws/credentials and ~/.aws/config, then the
// role of the EC2 instance or ECS task.
type AWS struct {
	// Region, e.g. eu-west-3. Default: from the profile or AWS_REGION,
	// else from the queue URL.
	Region string `yaml:"region"`
	// Profile of the shared credentials and config files.
	Profile string `yaml:"profile"`
	// CredentialsFile and ConfigFile replace ~/.aws/credentials and
	// ~/.aws/config.
	CredentialsFile string `yaml:"credentials_file"`
	ConfigFile      string `yaml:"config_file"`
	// The names of the environment variables holding the keys of this
	// source, so that they are not stored in the configuration file.
	AccessKeyIDEnv     string `yaml:"access_key_id_env"`
	SecretAccessKeyEnv string `yaml:"secret_access_key_env"`
	SessionTokenEnv    string `yaml:"session_token_env"`
	// EndpointURL replaces the AWS endpoints (SQS and S3, or WAF), for
	// compatible services (LocalStack, MinIO...).
	EndpointURL string `yaml:"endpoint_url"`
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

	// aws-waf-ipset: the IP set, and the credentials and region, as for an
	// aws-s3 source.
	IPSet WAFIPSet `yaml:"ipset"`
	AWS   AWS      `yaml:"aws"`

	// Undo runs other actions some time after this one succeeded, e.g. to
	// unblock an IP address blocked by this action.
	Undo *Undo `yaml:"undo"`
}

// Undo tells which actions undo an action, and when.
type Undo struct {
	// After is how long the action lasts: the undo actions run that long
	// after it succeeded.
	After time.Duration `yaml:"after"`
	// Actions are the ids of the actions run then, with the same alert.
	Actions []string `yaml:"actions"`
}

// WAFIPSet is an AWS WAF (v2) IP set, to which an aws-waf-ipset action adds
// an address of the alert, or from which it removes it.
type WAFIPSet struct {
	// Name of the IP set.
	Name string `yaml:"name"`
	// ID of the IP set. Default: looked up by name.
	ID string `yaml:"id"`
	// Scope is REGIONAL (default: ALB, API Gateway...) or CLOUDFRONT.
	Scope string `yaml:"scope"`
	// Operation is add (default) or remove, e.g. in the undo of an add.
	Operation string `yaml:"operation"`
	// Field is the event field holding the address, in the last event of
	// the alert (default: SourceIP).
	Field   string        `yaml:"field"`
	Timeout time.Duration `yaml:"timeout"`
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
	// Exclude lists the ids of the exclude lists whose events the rule
	// ignores.
	Exclude []string `yaml:"exclude"`
	// ExcludeIf is a CEL expression: the rule ignores the events for which
	// it is true.
	ExcludeIf string `yaml:"exclude_if"`

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
// its include directory in lexical order. The exclude lists, sources, actions
// and rules of the included files are added to those of the main file;
// state_file, max_lifetime, http and include_dir may only be set in the main
// file. Unknown keys
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
		if part.StateFile != "" || part.MaxLifetime != 0 || part.HTTP != (HTTP{}) || part.IncludeDir != nil {
			return nil, fmt.Errorf("%s: state_file, max_lifetime, http and include_dir are only allowed in the main configuration file %s", f, path)
		}
		if err := ids.add(part, f); err != nil {
			return nil, err
		}
		cfg.ExcludeLists = append(cfg.ExcludeLists, part.ExcludeLists...)
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
		if obsolete(data) {
			return nil, fmt.Errorf("%s: allowlist and use_allowlist were replaced by exclude_lists and the exclude of each rule (see the README)", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// obsolete reports whether a configuration file uses the allowlist settings
// of earlier versions.
func obsolete(data []byte) bool {
	var old struct {
		Allowlist any `yaml:"allowlist"`
		Actions   []struct {
			UseAllowlist any `yaml:"use_allowlist"`
		} `yaml:"actions"`
	}
	if yaml.Unmarshal(data, &old) != nil {
		return false
	}
	if old.Allowlist != nil {
		return true
	}
	for _, a := range old.Actions {
		if a.UseAllowlist != nil {
			return true
		}
	}
	return false
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

// ids detects the exclude lists, sources, actions and rules defined twice, possibly in
// different files, and tells where.
type ids map[string]map[string]string // kind -> id -> file

func newIDs() ids {
	return ids{"exclude list": {}, "source": {}, "action": {}, "rule": {}}
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
	for _, l := range cfg.ExcludeLists {
		if err := check("exclude list", l.ID); err != nil {
			return err
		}
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
