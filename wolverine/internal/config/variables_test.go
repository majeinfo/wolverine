package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVariables(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"wolverine.yaml": `
variables:
  logdir: /var/log/app
  ssh_regexp: '^Failed password for (?P<username>\S+) from (?P<source_ip>\S+)$'
  threshold: 5
  window: 10m
  admins: [192.0.2.10, 192.0.2.11]
  waf_aws:
    region: eu-west-3
    profile: wolverine
  description: more than ${threshold} failures   # a variable using another
sources:
  - id: app
    type: logfile
    # The date macros are not variables: left for the path expansion.
    path: ${logdir}/app.log.${year}-${month}-${day-1}
    regexp: ${ssh_regexp}
    category: "$${not_a_variable}"
exclude_lists:
  - id: admins
    entries: ${admins}
actions:
  - id: waf-block
    type: aws-waf-ipset
    ipset: {name: blocklist}
    aws: ${waf_aws}
rules:
  - id: main
    count: ${threshold}
    window: ${window}
    description: ${description} in ${window}
    suppress: "${threshold}0m"
`,
		"rules.d/10-web.yaml": `
variables:
  web_threshold: ${threshold}0   # local to this file, may use the main file's
rules:
  - id: web
    count: ${web_threshold}
    window: ${window}
`,
	})
	cfg, err := Load(filepath.Join(dir, "wolverine.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	src := cfg.Sources[0]
	if src.Path != "/var/log/app/app.log.${year}-${month}-${day-1}" || !strings.HasPrefix(src.Regexp, "^Failed password for (?P<username>") || src.Category != "${not_a_variable}" {
		t.Errorf("source: %+v", src)
	}
	if !slices.Equal(cfg.ExcludeLists[0].Entries, []string{"192.0.2.10", "192.0.2.11"}) {
		t.Errorf("list variable: %v", cfg.ExcludeLists[0].Entries)
	}
	if a := cfg.Actions[0].AWS; a.Region != "eu-west-3" || a.Profile != "wolverine" {
		t.Errorf("mapping variable: %+v", a)
	}
	r := cfg.Rules[0]
	if r.Count != 5 || r.Window != 10*time.Minute || r.Description != "more than 5 failures in 10m" || r.Suppress != 50*time.Minute {
		t.Errorf("rule: %+v", r)
	}
	if w := cfg.Rules[1]; w.Count != 50 || w.Window != 10*time.Minute {
		t.Errorf("included rule: %+v", w)
	}
}

func TestVariablesErrors(t *testing.T) {
	tests := []struct {
		name, main, part, want string
	}{
		{"undefined", "rules: [{id: r, description: '${nope}'}]\n", "", `wolverine.yaml: line 1: undefined variable ${nope}`},
		{"undefined in an included file", "", "\nrules: [{id: r, count: '${n}'}]\n", `10-part.yaml: line 2: undefined variable ${n}`},
		{"cycle", "variables: {a: '${b}', b: 'x${a}'}\nrules: [{id: '${a}'}]\n", "", "refers to itself"},
		{"list inside text", "variables: {l: [a]}\nrules: [{id: 'r-${l}'}]\n", "", "variable l is a list or a mapping"},
		{"wrong type", "variables: {n: many}\nrules: [{id: r, count: '${n}'}]\n", "", "cannot unmarshal !!str `many` into int"},
		{"reserved name", "variables: {day: 1}\n", "", `variable "day": reserved for the date macros`},
		{"bad name", "variables: {1st: x}\n", "", `variable "1st": a name is made of letters`},
		{"not a mapping", "variables: [a, b]\n", "", "variables: a mapping of names to values"},
		{"redefined in an included file", "variables: {n: 1}\n", "variables: {n: 2}\n", `10-part.yaml: line 1: variable "n" is already defined in the main configuration file`},
		{"unknown key still detected", "variables: {n: 1}\n\nrules:\n  - id: r\n    cuont: ${n}\n", "", "wolverine.yaml: line 5: field cuont not found in type config.Rule"},
	}
	for _, tt := range tests {
		dir := t.TempDir()
		write(t, dir, map[string]string{"wolverine.yaml": tt.main, "rules.d/10-part.yaml": tt.part})
		_, err := Load(filepath.Join(dir, "wolverine.yaml"))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.name, err, tt.want)
		}
	}

	// The variables of an included file are not visible in the others.
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"wolverine.yaml":       "",
		"rules.d/10-a.yaml":    "variables: {n: 1}\nrules: [{id: a, count: '${n}'}]\n",
		"rules.d/20-b.yaml":    "rules: [{id: b, count: '${n}'}]\n",
		"rules.d/30-c.yaml":    "variables: {n: 3}\nrules: [{id: c, count: '${n}'}]\n", // its own n
		"rules.d/40-none.yaml": "variables:\n",
	})
	if _, err := Load(filepath.Join(dir, "wolverine.yaml")); err == nil || !strings.Contains(err.Error(), "20-b.yaml: line 1: undefined variable ${n}") {
		t.Errorf("variable of another included file: got %v", err)
	}
	write(t, dir, map[string]string{"rules.d/20-b.yaml": ""})
	cfg, err := Load(filepath.Join(dir, "wolverine.yaml"))
	if err != nil || cfg.Rules[0].Count != 1 || cfg.Rules[1].Count != 3 {
		t.Errorf("local variables: %v, %+v", err, cfg)
	}
}
