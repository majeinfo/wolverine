package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/event"
	"wolverine/internal/source/syslog"
	"wolverine/internal/state"
	"wolverine/internal/stats"
)

// The shipped configuration, with its source pointed at a test file, must
// parse syslog lines, enrich sshd events and raise the brute-force alert.
func TestRunShippedConfig(t *testing.T) {
	var log strings.Builder
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&log, "Nov  8 10:0%d:00 myhost sshd[%d]: Failed password for root from 203.0.113.7 port 4%d ssh2\n", i, i, i)
		fmt.Fprintf(&log, "Nov  8 10:0%d:00 myhost sshd[%d]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root\n", i, i)
	}
	log.WriteString("garbage line\n")
	// The source reads the files of a directory whose names match its
	// filename_regexp: "messages" does, "boot.log" does not.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "messages"), []byte(log.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "boot.log"), []byte("Nov  8 10:00:00 myhost kernel: ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load("../../config/wolverine.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Only the log file source: the others (journal) depend on the machine
	// and may follow forever.
	var messages config.Source
	for _, src := range cfg.Sources {
		if src.ID == "messages" {
			messages = src
		}
	}
	if messages.Directory == "" || messages.FilenameRegexp == "" {
		t.Fatalf("the messages source should use directory and filename_regexp: %+v", messages)
	}
	messages.Directory, messages.Follow, messages.StartAt, messages.Disabled = dir, false, "", false
	cfg.Sources = []config.Source{messages}
	cfg.StateFile = ""
	cfg.LogTTL = oldLogs // logs of a fixed date

	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out, events bytes.Buffer
	eng.Alerts = &out
	eng.AlertEvents = AllAlertEvents // -detailed-events
	eng.Events = &events
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	var alerts []event.Alert
	dec := json.NewDecoder(&out)
	for dec.More() {
		var a event.Alert
		if err := dec.Decode(&a); err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, a)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1:\n%s", len(alerts), out.String())
	}
	a := alerts[0]
	// The rule matches every authentication event: the pam_unix lines are
	// counted along with the "Failed password" ones, so the third event
	// (Failed, pam, Failed) fires it; suppress keeps it to one alert.
	if a.RuleID != "ssh-failed-logins-per-ip" || len(a.Events) != 3 || a.Metadata["value"] != "203.0.113.7" {
		t.Errorf("unexpected alert: %+v", a)
	}
	if !strings.HasPrefix(a.Events[1].Message, "pam_unix(sshd:auth)") {
		t.Errorf("second event of the alert: %q, want the pam_unix line", a.Events[1].Message)
	}
	ev := a.Events[0]
	if ev.Source != "messages" || ev.Hostname != "myhost" || ev.Service != "sshd" || ev.Username != "root" || ev.Category != "authentication" {
		t.Errorf("unexpected event: %+v", ev)
	}

	var nEvents, nUnparsed int
	dec = json.NewDecoder(&events)
	for dec.More() {
		var ev event.Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		nEvents++
		if ev.Fields["parse_error"] != nil {
			nUnparsed++
		}
	}
	if nEvents != 13 || nUnparsed != 1 {
		t.Errorf("printed %d events (%d unparsed), want 13 (1 unparsed)", nEvents, nUnparsed)
	}

	if in := eng.inputs[0]; in.lines.Load() != 13 || in.unparsed.Load() != 1 {
		t.Errorf("lines=%d unparsed=%d, want 13 and 1", in.lines.Load(), in.unparsed.Load())
	}
}

// Each rule ignores the events whose source IP is in one of its exclude
// lists, possibly through a list included in another; other rules still see
// them.
func TestRunExcludeLists(t *testing.T) {
	dir := t.TempDir()
	var log strings.Builder
	for _, ip := range []string{"10.1.1.1", "10.1.1.1", "10.1.1.1", "192.0.2.9", "192.0.2.9", "192.0.2.9", "203.0.113.7", "203.0.113.7", "203.0.113.7"} {
		fmt.Fprintf(&log, "Failed password for root from %s port 22 ssh2\n", ip)
	}
	path := filepath.Join(dir, "secure")
	os.WriteFile(path, []byte(log.String()), 0o644)

	src := logfile(path)
	src.Regexp = `^Failed password for \S+ from (?P<source_ip>\S+) .*$`
	src.Category = "authentication"
	rule := func(id string, exclude ...string) config.Rule {
		return config.Rule{ID: id, Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour, Exclude: exclude,
			Match: config.Match{Category: "authentication"}}
	}
	cfg := &config.Config{
		ExcludeLists: []config.ExcludeList{
			{ID: "trusted", Entries: []string{"admins", "192.0.2.9"}},
			{ID: "admins", Entries: []string{"10.0.0.0/8"}},
			{ID: "unused", Entries: []string{"203.0.113.0/24"}},
		},
		Sources: []config.Source{src},
		Rules:   []config.Rule{rule("strict", "trusted"), rule("lenient", "admins"), rule("all")},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out, events bytes.Buffer
	eng.Alerts, eng.Events = &out, &events
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	var got []string
	dec := json.NewDecoder(&out)
	for dec.More() {
		var a event.Alert
		if err := dec.Decode(&a); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprint(a.RuleID, " ", a.Metadata["value"]))
	}
	want := "all 10.1.1.1,lenient 192.0.2.9,all 192.0.2.9,strict 203.0.113.7,lenient 203.0.113.7,all 203.0.113.7"
	if strings.Join(got, ",") != want {
		t.Errorf("alerts:\n%s\nwant:\n%s", strings.Join(got, ","), want)
	}
	// The events tell which lists they are in; the lists no rule uses are
	// not checked.
	if s := events.String(); !strings.Contains(s, `"ExcludedBy":["trusted","admins"]`) || !strings.Contains(s, `"ExcludedBy":["trusted"]`) || strings.Contains(s, "unused") {
		t.Errorf("events:\n%s", s)
	}
}

// A source's exclude lists drop its events before any rule sees them.
func TestRunSourceExcludeLists(t *testing.T) {
	dir := t.TempDir()
	var log strings.Builder
	for _, ip := range []string{"192.0.2.1", "203.0.113.7", "192.0.2.2", "203.0.113.7", "192.0.2.3", "203.0.113.7"} {
		fmt.Fprintf(&log, "Failed password for root from %s port 22 ssh2\n", ip)
	}
	path := filepath.Join(dir, "secure")
	os.WriteFile(path, []byte(log.String()), 0o644)

	src := logfile(path)
	src.Regexp = `^Failed password for \S+ from (?P<source_ip>\S+) .*$`
	src.Exclude = []string{"scanners"}
	cfg := &config.Config{
		ExcludeLists: []config.ExcludeList{{ID: "scanners", Entries: []string{"192.0.2.0/24"}}},
		Sources:      []config.Source{src},
		Rules:        []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 1, Window: time.Hour}},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out, events bytes.Buffer
	eng.Alerts, eng.Events = &out, &events
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); strings.Contains(s, "192.0.2.") || !strings.Contains(s, "203.0.113.7") {
		t.Errorf("alerts:\n%s", s)
	}
	if s := events.String(); strings.Contains(s, "192.0.2.") || strings.Count(s, "\n") != 3 {
		t.Errorf("events:\n%s", s)
	}
	if in := eng.inputs[0]; in.lines.Load() != 6 || in.excluded.Load() != 3 {
		t.Errorf("lines=%d excluded=%d, want 6 and 3", in.lines.Load(), in.excluded.Load())
	}
}

// A source's exclude_if drops the events for which it is true, alongside
// its exclude lists.
func TestRunSourceExcludeIf(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`192.0.2.1 "GET /login" 401 "Mozilla/5.0"`,     // scanners list
		`203.0.113.7 "GET /login" 401 "curl/8.5"`,      // user agent
		`203.0.113.7 "GET /health" 401 "Mozilla/5.0"`,  // path
		`203.0.113.7 "GET /login" 401 "Mozilla/5.0"`,   // kept
		`198.51.100.4 "POST /login" 401 "Mozilla/5.0"`, // kept
	}
	path := filepath.Join(dir, "access.log")
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)

	src := logfile(path)
	src.Regexp = `^(?P<source_ip>\S+) "(?P<method>\S+) (?P<path>\S+)" (?P<status>\d+) "(?P<user_agent>[^"]*)"$`
	src.ExcludeIf = `in_list(source_ip, "scanners") || user_agent.matches("(?i)curl|bot") || path == "/health"`
	cfg := &config.Config{
		ExcludeLists: []config.ExcludeList{{ID: "scanners", Entries: []string{"192.0.2.0/24"}}},
		Sources:      []config.Source{src},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var events bytes.Buffer
	eng.Events = &events
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	var kept []string
	dec := json.NewDecoder(&events)
	for dec.More() {
		var ev event.Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, ev.Raw)
	}
	if want := lines[3] + "," + lines[4]; strings.Join(kept, ",") != want {
		t.Errorf("kept %q, want %q", kept, want)
	}
	if n := eng.inputs[0].excluded.Load(); n != 3 {
		t.Errorf("%d excluded, want 3", n)
	}
}

// A rule's exclude_if only makes that rule ignore the events; it can use
// the regexp groups of every source.
func TestRunRuleExcludeIf(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "access.log")
	os.WriteFile(web, []byte(strings.Repeat(`203.0.113.7 401 "curl/8.5"`+"\n", 3)+strings.Repeat(`198.51.100.4 401 "Mozilla/5.0"`+"\n", 3)), 0o644)
	ssh := filepath.Join(dir, "secure")
	os.WriteFile(ssh, []byte(strings.Repeat("Failed password for deploy from 192.0.2.9\n", 3)), 0o644)

	webSrc := logfile(web)
	webSrc.ID = "web"
	webSrc.Regexp = `^(?P<source_ip>\S+) (?P<status>\d+) "(?P<user_agent>[^"]*)"$`
	sshSrc := logfile(ssh)
	sshSrc.ID = "ssh"
	sshSrc.Regexp = `^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	rule := func(id, excludeIf string) config.Rule {
		return config.Rule{ID: id, Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour, ExcludeIf: excludeIf}
	}
	cfg := &config.Config{
		ExcludeLists: []config.ExcludeList{{ID: "lab", Entries: []string{"192.0.2.0/24"}}},
		Sources:      []config.Source{webSrc, sshSrc},
		Rules: []config.Rule{
			// user_agent comes from the web source; it is "" for the ssh
			// events.
			rule("filtered", `user_agent.startsWith("curl") || (username == "deploy" && in_list(source_ip, "lab"))`),
			rule("all", ""),
		},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng.Alerts = &out
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Without -detailed-events, the alerts do not embed the log lines.
	if text := out.String(); strings.Contains(text, `"Events"`) || !strings.Contains(text, `"count":3`) {
		t.Errorf("alerts should only give the count of their events:\n%s", text)
	}
	var got []string
	dec := json.NewDecoder(&out)
	for dec.More() {
		var a event.Alert
		if err := dec.Decode(&a); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprint(a.RuleID, " ", a.Metadata["value"]))
	}
	sort.Strings(got)
	want := "all 192.0.2.9,all 198.51.100.4,all 203.0.113.7,filtered 198.51.100.4"
	if strings.Join(got, ",") != want {
		t.Errorf("alerts %s, want %s", strings.Join(got, ","), want)
	}
}

// A rule's match_if keeps only the events for which it is true: here the
// requests that took more than 2 seconds. A value it cannot evaluate ("-")
// does not match.
func TestRunRuleMatchIf(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "access.log")
	os.WriteFile(web, []byte(strings.Join([]string{
		"203.0.113.7 200 2.5", "203.0.113.7 200 3.1", "203.0.113.7 500 10",
		"198.51.100.4 200 0.2", "198.51.100.4 200 2.0", "198.51.100.4 200 5.0",
		"192.0.2.9 200 -", "192.0.2.9 200 -", "192.0.2.9 200 -",
	}, "\n")+"\n"), 0o644)
	src := logfile(web)
	src.ID = "web"
	src.Regexp = `^(?P<source_ip>\S+) (?P<status>\d+) (?P<request_time>\S+)$`
	cfg := &config.Config{
		Sources: []config.Source{src},
		Rules: []config.Rule{{ID: "slow", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour,
			Match: config.Match{MatchIf: `double(request_time) > 2.0`}}},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng.Alerts = &out
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "\n"); n != 1 || !strings.Contains(out.String(), `"value":"203.0.113.7"`) {
		t.Errorf("alerts:\n%s", out.String())
	}
	if m := eng.stats.Total().Rules["slow"].Matches; m != 4 {
		t.Errorf("%d matches, want 4 (3 + 5.0)", m)
	}
}

// A simple rule raises an alert for every event that matches, next to a
// threshold rule that counts them.
func TestRunSimpleRule(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "access.log")
	os.WriteFile(web, []byte(strings.Join([]string{
		"203.0.113.7 200 2.5", "203.0.113.7 200 0.1", "198.51.100.4 500 3.0", "192.0.2.9 200 -",
	}, "\n")+"\n"), 0o644)
	src := logfile(web)
	src.ID = "web"
	src.Regexp = `^(?P<source_ip>\S+) (?P<status>\d+) (?P<request_time>\S+)$`
	cfg := &config.Config{
		Sources: []config.Source{src},
		Rules: []config.Rule{
			{ID: "slow", Type: "simple", Description: "Slow request", Severity: "medium",
				Match: config.Match{MatchIf: `request_time != "-" && double(request_time) > 2.0`}},
			{ID: "errors", Type: "simple", Match: config.Match{Status: "500"}},
			{ID: "count", Type: "threshold", GroupBy: "SourceIP", Count: 2, Window: time.Hour},
		},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng.Alerts = &out
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	dec := json.NewDecoder(&out)
	for dec.More() {
		var a event.Alert
		if err := dec.Decode(&a); err != nil {
			t.Fatal(err)
		}
		if a.RuleID == "count" { // the lines have no time: "within" varies
			a.Message = fmt.Sprint(a.Metadata["value"])
		}
		got = append(got, a.RuleID+" "+a.Message)
	}
	sort.Strings(got)
	want := "count 203.0.113.7|errors 198.51.100.4 500 3.0|slow Slow request: 198.51.100.4 500 3.0|slow Slow request: 203.0.113.7 200 2.5"
	if strings.Join(got, "|") != want {
		t.Errorf("alerts:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
	if r := eng.stats.Total().Rules; r["slow"].Matches != 2 || r["slow"].Alerts != 2 || r["errors"].Alerts != 1 {
		t.Errorf("stats: slow %+v, errors %+v", r["slow"], r["errors"])
	}
}

func TestBuildExcludeErrors(t *testing.T) {
	cfg := &config.Config{
		Sources:      []config.Source{logfile("/var/log/messages")},
		ExcludeLists: []config.ExcludeList{{ID: "a", Entries: []string{"b"}}},
	}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), `exclude list "a": "b"`) {
		t.Errorf("unknown list in a list: got %v", err)
	}
	cfg.ExcludeLists = []config.ExcludeList{{ID: "a"}}
	cfg.Rules = []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 1, Window: time.Minute, Exclude: []string{"nope"}}}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), `rule "r": exclude: unknown exclude list "nope"`) {
		t.Errorf("unknown list in a rule: got %v", err)
	}
	cfg.Rules = nil
	cfg.Sources[0].Exclude = []string{"nope"}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), `source "messages": exclude: unknown exclude list "nope"`) {
		t.Errorf("unknown list in a source: got %v", err)
	}
	cfg.Sources[0].Exclude = nil
	cfg.Rules = []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 1, Window: time.Minute, ExcludeIf: `nope == ""`}}
	if _, err := New(cfg); err == nil || !strings.HasPrefix(err.Error(), `rule "r": exclude_if: `) || !strings.Contains(err.Error(), "undeclared reference to 'nope'") {
		t.Errorf("rule exclude_if: got %v", err)
	}
	// The groups are strings: a number is compared after double().
	cfg.Rules = []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 1, Window: time.Minute, Match: config.Match{MatchIf: `status > 2`}}}
	if _, err := New(cfg); err == nil || !strings.HasPrefix(err.Error(), `rule "r": match_if: `) || !strings.Contains(err.Error(), "no matching overload") {
		t.Errorf("rule match_if: got %v", err)
	}
	cfg.Rules = nil
	for expr, want := range map[string]string{
		`user_agent == "x"`:       "undeclared reference to 'user_agent'",
		`in_list(source_ip, "b")`: `unknown exclude list "b"`,
		`message`:                 "must be true or false",
	} {
		cfg.Sources[0].ExcludeIf = expr
		if _, err := New(cfg); err == nil || !strings.HasPrefix(err.Error(), `source "messages": exclude_if: `) || !strings.Contains(err.Error(), want) {
			t.Errorf("exclude_if %s: got %v", expr, err)
		}
	}
}

func TestRunMissingFile(t *testing.T) {
	eng, err := New(&config.Config{Sources: []config.Source{logfile(filepath.Join(t.TempDir(), "nope"))}})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("got %v, want a missing file error", err)
	}
}

func logfile(path string) config.Source {
	return config.Source{ID: "messages", Type: "logfile", Path: path, Regexp: `^(?P<message>.*)$`}
}

func TestBuildSourcesErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*config.Source)
		want string
	}{
		{"missing id", func(c *config.Source) { c.ID = "" }, "missing id"},
		{"missing type", func(c *config.Source) { c.Type = "" }, "missing type"},
		{"unknown type", func(c *config.Source) { c.Type = "kafka" }, "unknown type"},
		{"no path", func(c *config.Source) { c.Path = "" }, "path is required"},
		{"no regexp", func(c *config.Source) { c.Regexp = "" }, "regexp is required"},
		{"bad regexp", func(c *config.Source) { c.Regexp = "(?P<x" }, "regexp:"},
		{"empty timestamp format", func(c *config.Source) { c.TimestampFormats = []string{""} }, "timestamp_formats"},
		{"bad timezone", func(c *config.Source) { c.Timezone = "Mars/Olympus" }, "timezone"},
		{"macro in the directory", func(c *config.Source) { c.Path = "/var/log/${year}/app.log" }, "only allowed in the file name"},
		{"bad macro", func(c *config.Source) { c.Path = "/var/log/app.${week}" }, `path: macro ${week}: unknown variable "week"`},
		{"unclosed macro", func(c *config.Source) { c.Path = "/var/log/app.${day" }, "unclosed macro"},
		{"bad start_at", func(c *config.Source) { c.StartAt = "middle" }, "start_at"},
		{"negative skip_lines", func(c *config.Source) { c.SkipLines = -1 }, "skip_lines: -1"},
		{"end without follow", func(c *config.Source) { c.StartAt = "end" }, "requires follow"},
		{"all disabled", func(c *config.Source) { c.Disabled = true }, "no source enabled"},
	}
	for _, tt := range tests {
		c := logfile("/var/log/messages")
		tt.mod(&c)
		if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}
	c := logfile("/var/log/messages")
	if _, err := buildSources([]config.Source{c, c}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate ids: got %v", err)
	}
}

func TestRunResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "messages")
	os.WriteFile(path, []byte("one\ntwo\n"), 0o644)
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "lib", "state.json"),
		Sources:   []config.Source{logfile(path)},
	}
	run := func() int64 {
		t.Helper()
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := eng.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return eng.inputs[0].lines.Load()
	}

	if n := run(); n != 2 {
		t.Fatalf("first run: %d lines, want 2", n)
	}
	if n := run(); n != 0 {
		t.Fatalf("second run: %d lines, want 0", n)
	}
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString("three\n")
	f.Close()
	if n := run(); n != 1 {
		t.Fatalf("after appending a line: %d lines, want 1", n)
	}

	b, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"type": "logfile"`) || !strings.Contains(string(b), `"offset": 14`) {
		t.Errorf("unexpected state file:\n%s", b)
	}
}

func TestBuildLogfileDirectory(t *testing.T) {
	c := config.Source{ID: "web", Type: "logfile", Directory: "/var/log/nginx", FilenameRegexp: `access\.log$`, Regexp: `^(?P<message>.*)$`}
	inputs, err := buildSources([]config.Source{c})
	if err != nil {
		t.Fatal(err)
	}
	f := inputs[0].source.(*syslog.Files)
	if f.Dir != "/var/log/nginx" || f.Pattern.String() != `access\.log$` || f.Path != "" {
		t.Errorf("unexpected source: %+v", f)
	}

	tests := []struct {
		mod  func(*config.Source)
		want string
	}{
		{func(c *config.Source) { c.Path = "/var/log/messages" }, "either path, or directory"},
		{func(c *config.Source) { c.FilenameRegexp = "" }, "directory requires filename_regexp"},
		{func(c *config.Source) { c.Directory = "" }, "filename_regexp requires directory"},
		{func(c *config.Source) { c.FilenameRegexp = "(" }, "filename_regexp:"},
	}
	for _, tt := range tests {
		c := c
		tt.mod(&c)
		if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("got error %v, want it to contain %q", err, tt.want)
		}
	}
}

// Two files of a directory, then a third one appearing between two runs.
func TestRunDirectory(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.Mkdir(logs, 0o755)
	os.WriteFile(filepath.Join(logs, "a.log"), []byte("a1\na2\n"), 0o644)
	os.WriteFile(filepath.Join(logs, "b.log"), []byte("b1\n"), 0o644)
	os.WriteFile(filepath.Join(logs, "notes.txt"), []byte("x\n"), 0o644)
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "state.json"),
		Sources: []config.Source{{ID: "app", Type: "logfile", Directory: logs, FilenameRegexp: `\.log$`,
			Regexp: `^(?P<message>.*)$`}},
	}
	run := func() (int64, string) {
		t.Helper()
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var events bytes.Buffer
		eng.Events = &events
		if err := eng.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return eng.inputs[0].lines.Load(), events.String()
	}

	n, events := run()
	if n != 3 || !strings.Contains(events, `"file":"`+filepath.Join(logs, "a.log")+`"`) {
		t.Fatalf("first run: %d lines, want 3; events:\n%s", n, events)
	}
	os.WriteFile(filepath.Join(logs, "c.log"), []byte("c1\n"), 0o644)
	if n, _ := run(); n != 1 {
		t.Fatalf("second run: %d lines, want 1 (c.log)", n)
	}
	if n, _ := run(); n != 0 {
		t.Fatalf("third run: %d lines, want 0", n)
	}
}

func TestAlertEvents(t *testing.T) {
	a := &event.Alert{RuleID: "r", Events: []*event.Event{{Raw: "one"}, {Raw: "two"}, {Raw: "three"}}}
	for mode, want := range map[AlertEvents]string{
		NoAlertEvents:  "",
		LastAlertEvent: "three",
		AllAlertEvents: "one,two,three",
	} {
		var raws []string
		for _, ev := range mode.apply(a).Events {
			raws = append(raws, ev.Raw)
		}
		if got := strings.Join(raws, ","); got != want {
			t.Errorf("mode %d: events %q, want %q", mode, got, want)
		}
	}
	// The alert given to the actions is not modified.
	if len(a.Events) != 3 {
		t.Errorf("alert modified: %d events", len(a.Events))
	}
}

func TestMaxLifetime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	// 4 failures from .1 (one alert), 2 from .2 (memorized, no alert).
	os.WriteFile(path, []byte(strings.Repeat("Failed password for root from 192.0.2.1\n", 4)+
		strings.Repeat("Failed password for root from 192.0.2.2\n", 2)), 0o644)
	src := logfile(path)
	src.Regexp = `^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	cfg := &config.Config{
		Sources: []config.Source{src},
		Rules:   []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour, Suppress: time.Hour}},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if eng.MaxLifetime != config.DefaultMaxLifetime {
		t.Errorf("lifetime %s, want the default", eng.MaxLifetime)
	}
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The alert is memorized with all its events.
	alerts := eng.RecentAlerts()
	if len(alerts) != 1 || alerts[0].RuleID != "r" || len(alerts[0].Events) != 3 {
		t.Fatalf("recent alerts: %+v", alerts)
	}

	// Nothing was memorized an hour ago.
	eng.expire(time.Now().Add(-time.Hour))
	if len(eng.RecentAlerts()) != 1 || eng.detector.Expire(time.Now().Add(-time.Hour)) != 0 {
		t.Fatal("data expired too early")
	}
	// Everything was memorized before now + 1s: the alert, and in the rule
	// the 4th event of .1, the 2 events of .2 and the suppression of .1.
	eng.expire(time.Now().Add(time.Second))
	if n := len(eng.RecentAlerts()); n != 0 {
		t.Errorf("%d alerts left", n)
	}
	if n := eng.detector.Expire(time.Now().Add(time.Second)); n != 0 {
		t.Errorf("%d rule data left", n)
	}
}

func TestCheckLifetime(t *testing.T) {
	rule := func(window, suppress time.Duration) config.Rule {
		return config.Rule{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: window, Suppress: suppress}
	}
	for _, tt := range []struct {
		lifetime time.Duration
		rule     config.Rule
		want     string
	}{
		{time.Hour, rule(time.Hour, time.Hour), ""},
		{time.Hour, rule(2*time.Hour, 0), `rule "r": window 2h0m0s exceeds the maximum lifetime 1h0m0s`},
		{time.Hour, rule(time.Minute, 2*time.Hour), `rule "r": suppress 2h0m0s exceeds the maximum lifetime 1h0m0s`},
		{-time.Hour, rule(time.Minute, 0), "max_lifetime must be a positive duration"},
	} {
		err := checkLifetime([]config.Rule{tt.rule}, tt.lifetime)
		if (err == nil) != (tt.want == "") || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s %+v: got %v, want %q", tt.lifetime, tt.rule, err, tt.want)
		}
	}
	// A disabled rule is not checked.
	r := rule(48*time.Hour, 0)
	r.Disabled = true
	if err := checkLifetime([]config.Rule{r}, time.Hour); err != nil {
		t.Error(err)
	}
	// New applies max_lifetime.
	cfg := &config.Config{
		Sources:     []config.Source{logfile("/var/log/messages")},
		Rules:       []config.Rule{rule(2*time.Hour, 0)},
		MaxLifetime: time.Hour,
	}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "exceeds the maximum lifetime") {
		t.Errorf("New: got %v", err)
	}
}

// log_ttl and memory_limit: defaults, checks, and Info.
func TestLogTTLAndMemoryLimit(t *testing.T) {
	pct := func(n int) *int { return &n }
	for _, tt := range []struct {
		ttl     time.Duration
		limit   *int
		want    string // error
		info    string // LogTTL
		hasMem  bool
		memInfo string // prefix of MemoryLimit
	}{
		{0, nil, "", "1h0m0s", true, "60% ("},
		{30 * time.Minute, pct(25), "", "30m0s", true, "25% ("},
		{0, pct(0), "", "1h0m0s", false, ""},
		{-time.Minute, nil, "log_ttl must be a positive duration", "", false, ""},
		{0, pct(101), "memory_limit: 101: a percentage", "", false, ""},
		{0, pct(-1), "memory_limit: -1: a percentage", "", false, ""},
	} {
		cfg := &config.Config{Sources: []config.Source{logfile("/var/log/messages")}, LogTTL: tt.ttl, MemoryLimit: tt.limit}
		eng, err := New(cfg)
		if tt.want != "" {
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%+v: got %v, want %q", tt, err, tt.want)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		info := eng.Info()
		if info.LogTTL != tt.info || (eng.memory != nil) != tt.hasMem || !strings.HasPrefix(info.MemoryLimit, tt.memInfo) || (tt.memInfo == "") != (info.MemoryLimit == "") {
			t.Errorf("%+v: info %+v, memory %v", tt, info, eng.memory)
		}
	}
}

func TestExpireInterval(t *testing.T) {
	for lifetime, want := range map[time.Duration]time.Duration{
		5 * time.Second: time.Second,
		time.Minute:     6 * time.Second,
		24 * time.Hour:  time.Minute,
	} {
		if got := expireInterval(lifetime); got != want {
			t.Errorf("%s: %s, want %s", lifetime, got, want)
		}
	}
}

// oldLogs is a log TTL for the tests whose logs have a fixed date.
const oldLogs = 100 * 365 * 24 * time.Hour

// The lines older than log_ttl, by their time in the log, are discarded
// when read: not counted by the rules, nor written as events.
func TestRunDiscardsOldLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	now := time.Now()
	var b strings.Builder
	line := func(age time.Duration, ip string) {
		fmt.Fprintf(&b, "%s Failed password for root from %s\n", now.Add(-age).Format(time.RFC3339), ip)
	}
	// Two old ones and a recent one: no alert, as the old ones are not
	// counted.
	line(3*time.Hour, "192.0.2.1")
	line(2*time.Hour, "192.0.2.1")
	line(10*time.Minute, "192.0.2.1")
	// Three recent ones: an alert, even after old lines.
	line(5*time.Minute, "192.0.2.2")
	line(90*time.Minute, "192.0.2.2")
	line(4*time.Minute, "192.0.2.2")
	line(3*time.Minute, "192.0.2.2")
	os.WriteFile(path, []byte(b.String()), 0o644)
	src := logfile(path)
	src.Regexp = `^(?P<timestamp>\S+) Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	src.TimestampFormats = []string{"rfc3339"}
	cfg := &config.Config{
		Sources: []config.Source{src},
		Rules:   []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: 24 * time.Hour}},
		LogTTL:  time.Hour,
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var alerts, events bytes.Buffer
	eng.Alerts, eng.Events = &alerts, &events
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(alerts.String(), "\n"); n != 1 || !strings.Contains(alerts.String(), "192.0.2.2") {
		t.Errorf("alerts:\n%s", alerts.String())
	}
	if n := strings.Count(events.String(), "\n"); n != 4 {
		t.Errorf("%d events written, want 4", n)
	}
	if n := eng.inputs[0].old.Load(); n != 3 {
		t.Errorf("%d old lines, want 3", n)
	}
	if c := eng.stats.Total().Totals; c.Old != 3 || c.Lines != 7 {
		t.Errorf("stats: %+v", c)
	}
}

func TestRunSavesAlerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	os.WriteFile(path, []byte(strings.Repeat("Failed password for root from 192.0.2.1\n", 3)), 0o644)
	src := logfile(path)
	src.Regexp = `^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "state.json"),
		Sources:   []config.Source{src},
		Rules:     []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour}},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(eng.RecentAlerts()) != 1 {
		t.Fatalf("%d alerts", len(eng.RecentAlerts()))
	}

	// A restart gets the alert back, with its events, though no line is
	// read again.
	eng, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	alerts := eng.RecentAlerts()
	if len(alerts) != 1 || alerts[0].RuleID != "r" || len(alerts[0].Events) != 3 || alerts[0].Events[2].SourceIP != "192.0.2.1" {
		t.Fatalf("restored alerts: %+v", alerts)
	}

	// An alert memorized before the lifetime is not restored, and is
	// removed from the file at the next save.
	cfg.MaxLifetime = time.Hour
	b, _ := os.ReadFile(cfg.StateFile)
	old := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	b = regexp.MustCompile(`"memorized_at": "[^"]*"`).ReplaceAll(b, []byte(`"memorized_at": "`+old+`"`))
	os.WriteFile(cfg.StateFile, b, 0o600)
	eng, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(eng.RecentAlerts()); n != 0 {
		t.Fatalf("%d expired alerts restored", n)
	}
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg.StateFile); strings.Contains(string(b), `"alerts"`) {
		t.Errorf("expired alert still saved:\n%s", b)
	}
}

func TestRunSavesRuleData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	line := "Failed password for root from 192.0.2.1\n"
	os.WriteFile(path, []byte(strings.Repeat(line, 2)), 0o644)
	src := logfile(path)
	src.Regexp = `^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "state.json"),
		Sources:   []config.Source{src},
		Rules:     []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour}},
	}
	run := func(appended int) int {
		t.Helper()
		if appended > 0 {
			f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			f.WriteString(strings.Repeat(line, appended))
			f.Close()
		}
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		eng.Alerts = &out
		if err := eng.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return strings.Count(out.String(), "\n")
	}
	// 2 events, then a third after a restart: they add up.
	if n := run(0); n != 0 {
		t.Fatalf("first run: %d alerts", n)
	}
	if n := run(1); n != 1 {
		t.Fatalf("after a restart: %d alerts, want 1", n)
	}

	// A rule that counts other events does not get the data.
	cfg.Rules[0].GroupBy = "Username"
	run(2)
	cfg.Rules[0].GroupBy = "SourceIP"
	if n := run(1); n != 0 {
		t.Fatalf("data of the changed rule restored: %d alerts", n)
	}

	// A removed rule's data is forgotten.
	cfg.Rules[0].ID = "renamed"
	run(0)
	if b, _ := os.ReadFile(cfg.StateFile); strings.Contains(string(b), `"r":`) {
		t.Errorf("data of a removed rule still saved:\n%s", b)
	}
}

func TestRunUndo(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		call := r.URL.Path
		if strings.Contains(string(b), `"undo_of":"block"`) {
			call += " (undo of block)"
		}
		calls = append(calls, call)
	}))
	defer srv.Close()
	called := func() string {
		mu.Lock()
		defer mu.Unlock()
		s := strings.Join(calls, ",")
		calls = nil
		return s
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	os.WriteFile(path, []byte(strings.Repeat("Failed password for root from 192.0.2.1\n", 3)), 0o644)
	src := logfile(path)
	src.Regexp = `^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	cfg := &config.Config{
		StateFile: filepath.Join(dir, "state.json"),
		Sources:   []config.Source{src},
		Rules:     []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour, Actions: []string{"block"}}},
		Actions: []config.Action{
			{ID: "block", Type: "webhook", Webhook: config.Webhook{URL: srv.URL + "/block"},
				Undo: &config.Undo{After: time.Hour, Actions: []string{"unblock"}}},
			{ID: "unblock", Type: "webhook", Webhook: config.Webhook{URL: srv.URL + "/unblock"}},
		},
	}
	var raised time.Time
	// run runs wolverine and returns the action log of the alert, and the
	// notices watched.
	run := func() (string, string) {
		t.Helper()
		eng, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		notices, cancel := eng.Watch()
		defer cancel()
		if err := eng.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		var watched []string
		for n := range notices {
			if n.Action == nil {
				watched = append(watched, "alert "+n.Alert.ID)
			} else {
				watched = append(watched, n.Action.Action+" "+n.Action.Status)
			}
		}
		records := eng.AlertRecords()
		if len(records) != 1 {
			t.Fatalf("%d alerts", len(records))
		}
		// Raised when first read, kept across restarts.
		if raised == (time.Time{}) {
			raised = records[0].Raised
		}
		if !records[0].Raised.Equal(raised) || raised.IsZero() {
			t.Errorf("raised at %s, want %s", records[0].Raised, raised)
		}
		// The pending undo is that of the alert kept.
		for _, p := range eng.PendingUndos() {
			if p.Alert.ID != records[0].Alert.ID {
				t.Errorf("pending undo for alert %s, kept %s", p.Alert.ID, records[0].Alert.ID)
			}
		}
		var log []string
		for _, r := range records[0].Actions {
			line := r.Action + " " + r.Status
			if r.UndoOf != "" {
				line = r.Action + "<" + r.UndoOf + " " + r.Status
			}
			if r.Time.IsZero() {
				line += " (no time)"
			}
			log = append(log, line)
		}
		return strings.Join(log, ", "), strings.Join(watched, ", ")
	}
	savedUndos := func() []state.Undo {
		t.Helper()
		st, err := state.Open(cfg.StateFile)
		if err != nil {
			t.Fatal(err)
		}
		return st.Undos()
	}

	log, watched := run()
	if got := called(); got != "/block" {
		t.Fatalf("first run: %q", got)
	}
	id := ""
	if records := (func() []state.Alert { st, _ := state.Open(cfg.StateFile); return st.Alerts() })(); len(records) == 1 {
		id = records[0].Alert.ID
	}
	if log != "block ok, unblock<block planned" || watched != "alert "+id+", block ok, unblock planned" {
		t.Errorf("first run: log %q, watched %q", log, watched)
	}
	undos := savedUndos()
	if len(undos) != 1 || undos[0].Action != "block" || time.Until(undos[0].Due) < 59*time.Minute {
		t.Fatalf("saved undos: %+v", undos)
	}

	// Not due yet: still pending after a restart.
	// The action log is kept in the state file.
	if log, watched := run(); log != "block ok, unblock<block planned" || watched != "" {
		t.Errorf("second run: log %q, watched %q", log, watched)
	}
	if eng, err := New(cfg); err != nil || len(eng.PendingUndos()) != 1 {
		t.Errorf("pending undos after a restart: %v", err)
	}
	if got := called(); got != "" || len(savedUndos()) != 1 {
		t.Fatalf("second run: %q, %+v", got, savedUndos())
	}

	// Due while wolverine was stopped: run at the next start.
	b, _ := os.ReadFile(cfg.StateFile)
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	b = regexp.MustCompile(`"due": "[^"]*"`).ReplaceAll(b, []byte(`"due": "`+past+`"`))
	os.WriteFile(cfg.StateFile, b, 0o600)
	if log, _ := run(); log != "block ok, unblock<block planned, unblock<block ok" {
		t.Errorf("third run: log %q", log)
	}
	if got := called(); got != "/unblock (undo of block)" || len(savedUndos()) != 0 {
		t.Fatalf("third run: %q, %+v", got, savedUndos())
	}
}

func TestRunStatsAndWatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secure")
	os.WriteFile(path, []byte("Failed password for root from 192.0.2.1\n"+
		"garbage\n"+
		"Failed password for root from 10.0.0.1\n"+ // excluded
		"\n"+ // empty: a line, but not an event
		strings.Repeat("Failed password for root from 192.0.2.1\n", 2)), 0o644)
	src := logfile(path)
	src.ID = "ssh"
	src.Regexp = `^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$`
	src.Exclude = []string{"lan"}
	cfg := &config.Config{
		ExcludeLists: []config.ExcludeList{{ID: "lan", Entries: []string{"10.0.0.0/8"}}},
		Sources:      []config.Source{src},
		Rules: []config.Rule{
			{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour},
			{ID: "idle", Type: "threshold", GroupBy: "SourceIP", Count: 3, Window: time.Hour, Match: config.Match{Category: "none"}},
		},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	info := eng.Info()
	if len(info.Sources) != 1 || info.Sources[0].Type != "logfile" || len(info.Rules) != 2 {
		t.Errorf("info: %+v", info)
	}
	alerts, cancel := eng.Watch()
	defer cancel()
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, ok := <-alerts
	if !ok || n.Alert.RuleID != "r" || n.Action != nil {
		t.Fatalf("watched: %+v %v", n, ok)
	}
	if _, ok := <-alerts; ok {
		t.Error("the channel should be closed when Run returns")
	}
	tot := eng.Stats().Total()
	fi, _ := os.Stat(path) // every line ends with a newline: the bytes are the file size
	if tot.Totals != (stats.Totals{Source: stats.Source{Lines: 6, Events: 4, Unparsed: 1, Excluded: 1, Bytes: fi.Size()}, Rule: stats.Rule{Matches: 3, Alerts: 1}}) {
		t.Errorf("totals: %+v", tot.Totals)
	}
	if *tot.Rules["idle"] != (stats.Rule{}) || tot.Rules["r"].Matches != 3 {
		t.Errorf("rules: %+v %+v", tot.Rules["idle"], tot.Rules["r"])
	}
	// A watcher after the end gets a closed channel.
	if ch, _ := eng.Watch(); func() bool { _, ok := <-ch; return ok }() {
		t.Error("watch after Run")
	}
}

// The header lines given by skip_lines are not parsed: neither events nor
// unparsed lines.
func TestRunSkipLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.csv")
	os.WriteFile(path, []byte("ip,user\n192.0.2.1,root\n192.0.2.1,admin\n"), 0o644)
	src := logfile(path)
	src.Regexp = `^(?P<source_ip>[\d.]+),(?P<username>\w+)$`
	src.SkipLines = 1
	cfg := &config.Config{
		Sources: []config.Source{src},
		Rules:   []config.Rule{{ID: "r", Type: "threshold", GroupBy: "SourceIP", Count: 2, Window: time.Hour}},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tot := eng.Stats().Total().Totals; tot.Lines != 2 || tot.Events != 2 || tot.Unparsed != 0 || tot.Alerts != 1 {
		t.Errorf("totals: %+v", tot)
	}
}
