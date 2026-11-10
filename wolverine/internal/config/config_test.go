package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write creates the files (name -> content) under dir.
func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func ruleIDs(cfg *Config) string {
	var ids []string
	for _, r := range cfg.Rules {
		ids = append(ids, r.ID)
	}
	return strings.Join(ids, ",")
}

func TestLoadIncludeDir(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"wolverine.yaml": "allowlist: [127.0.0.1]\nstate_file: /tmp/s.json\nrules:\n  - id: main\n",
		// Read in lexical order, whatever the extension.
		"rules.d/20-web.yml":    "rules:\n  - id: web\n",
		"rules.d/10-ssh.yaml":   "allowlist: [10.0.0.0/8]\nactions:\n  - id: mail\nrules:\n  - id: ssh\n",
		"rules.d/30-empty.yaml": "",
		// Ignored: other extensions, hidden files, subdirectories.
		"rules.d/40-old.yaml.bak": "rules: [{id: bak}]\n",
		"rules.d/README":          "not yaml",
		"rules.d/.50-hidden.yaml": "rules: [{id: hidden}]\n",
		"rules.d/sub/60-sub.yaml": "rules: [{id: sub}]\n",
		"rules.d/dir.yaml/x.yaml": "rules: [{id: dir}]\n",
	})
	os.Symlink(filepath.Join(dir, "rules.d/10-ssh.yaml"), filepath.Join(dir, "rules.d/15-link.yaml.disabled"))
	os.Symlink(filepath.Join(dir, "other.yaml"), filepath.Join(dir, "rules.d/25-link.yaml"))
	write(t, dir, map[string]string{"other.yaml": "rules: [{id: linked}]\n"})

	cfg, err := Load(filepath.Join(dir, "wolverine.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleIDs(cfg); got != "main,ssh,web,linked" {
		t.Errorf("rules %s, want main,ssh,web,linked", got)
	}
	if len(cfg.Actions) != 1 || strings.Join(cfg.Allowlist, ",") != "127.0.0.1,10.0.0.0/8" || cfg.StateFile != "/tmp/s.json" {
		t.Errorf("unexpected configuration: %+v", cfg)
	}
	var names []string
	for _, f := range cfg.Files {
		names = append(names, filepath.Base(f))
	}
	if got := strings.Join(names, ","); got != "wolverine.yaml,10-ssh.yaml,20-web.yml,25-link.yaml,30-empty.yaml" {
		t.Errorf("files %s", got)
	}
}

func TestLoadIncludeDirSetting(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"conf.d/a.yaml":  "rules: [{id: a}]\n",
		"abs/b.yaml":     "rules: [{id: b}]\n",
		"rules.d/c.yaml": "rules: [{id: c}]\n",
		"relative.yaml":  "include_dir: conf.d\n",
		"absolute.yaml":  "include_dir: " + filepath.Join(dir, "abs") + "\n",
		"disabled.yaml":  "include_dir: \"\"\n",
		"missing.yaml":   "include_dir: nope.d\n",
		"default.yaml":   "rules: [{id: main}]\n",
		"sub/main.yaml":  "rules: [{id: main}]\n", // no sub/rules.d: fine
	})
	for _, tt := range []struct{ file, want string }{
		{"relative.yaml", "a"},
		{"absolute.yaml", "b"},
		{"disabled.yaml", ""},
		{"default.yaml", "main,c"},
		{"sub/main.yaml", "main"},
	} {
		cfg, err := Load(filepath.Join(dir, tt.file))
		if err != nil {
			t.Errorf("%s: %v", tt.file, err)
			continue
		}
		if got := ruleIDs(cfg); got != tt.want {
			t.Errorf("%s: rules %q, want %q", tt.file, got, tt.want)
		}
	}
	// An include_dir that is set must exist (a typo must not go unnoticed).
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil || !strings.Contains(err.Error(), "include_dir") {
		t.Errorf("missing include_dir: got %v", err)
	}
}

func TestLoadIncludeErrors(t *testing.T) {
	tests := []struct {
		name, main, part, want string
	}{
		{"state_file in an included file", "", "state_file: /x\n", "only allowed in the main configuration file"},
		{"include_dir in an included file", "", "include_dir: x\n", "only allowed in the main configuration file"},
		{"unknown key", "", "rulez: []\n", "10-part.yaml"},
		{"duplicate rule across files", "rules: [{id: r}]\n", "rules: [{id: r}]\n", `rule "r" is already defined in`},
		{"duplicate action across files", "actions: [{id: a}]\n", "actions: [{id: a}]\n", `action "a" is already defined in`},
		{"duplicate source in one file", "", "sources: [{id: s}, {id: s}]\n", `source "s" is defined twice`},
	}
	for _, tt := range tests {
		dir := t.TempDir()
		write(t, dir, map[string]string{"wolverine.yaml": tt.main, "rules.d/10-part.yaml": tt.part})
		_, err := Load(filepath.Join(dir, "wolverine.yaml"))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.name, err, tt.want)
		}
	}
}
