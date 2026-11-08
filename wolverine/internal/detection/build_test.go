package detection

import (
	"strings"
	"testing"
	"time"

	"wolverine/internal/config"
)

// The shipped configuration must load and produce the SSH rule.
func TestBuildRulesFromShippedConfig(t *testing.T) {
	cfg, err := config.Load("../../config/wolverine.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := BuildRules(cfg.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r, ok := rules[0].(*ThresholdRule)
	if !ok {
		t.Fatalf("got %T, want *ThresholdRule", rules[0])
	}
	if r.ID() != "ssh-failed-logins-per-ip" || r.GroupBy != "SourceIP" || r.Count != 5 || r.Window != 5*time.Minute || r.Suppress != time.Hour {
		t.Errorf("unexpected rule: %+v", r)
	}
	if len(r.Match.HasFields) != 1 || r.Match.HasFields[0] != "auth_method" {
		t.Errorf("unexpected match: %+v", r.Match)
	}
}

func TestBuildRulesErrors(t *testing.T) {
	ok := config.Rule{ID: "a", Type: "threshold", GroupBy: "SourceIP", Count: 1, Window: time.Minute}
	tests := []struct {
		name string
		mod  func(*config.Rule)
		want string
	}{
		{"missing id", func(r *config.Rule) { r.ID = "" }, "missing id"},
		{"missing type", func(r *config.Rule) { r.Type = "" }, "missing type"},
		{"unknown type", func(r *config.Rule) { r.Type = "foo" }, "unknown type"},
		{"no group_by", func(r *config.Rule) { r.GroupBy = "" }, "group_by"},
		{"zero count", func(r *config.Rule) { r.Count = 0 }, "count"},
		{"zero window", func(r *config.Rule) { r.Window = 0 }, "window"},
		{"negative suppress", func(r *config.Rule) { r.Suppress = -time.Minute }, "suppress"},
	}
	for _, tt := range tests {
		r := ok
		tt.mod(&r)
		if _, err := BuildRules([]config.Rule{r}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}

	if _, err := BuildRules([]config.Rule{ok, ok}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate ids: got %v", err)
	}

	disabled := ok
	disabled.Disabled = true
	if rules, err := BuildRules([]config.Rule{disabled}); err != nil || len(rules) != 0 {
		t.Errorf("disabled rule: got %v, %v", rules, err)
	}
}
