package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/event"
	"wolverine/internal/source/syslog"
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
