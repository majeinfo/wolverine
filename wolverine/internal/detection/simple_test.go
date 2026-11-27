package detection

import (
	"strings"
	"testing"
	"time"

	"wolverine/internal/config"
)

// A simple rule raises an alert for every event that matches.
func TestSimpleRule(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r := &SimpleRule{RuleID: "root-login", Description: "Root login", Severity: "high",
		Match: Match{Category: "authentication", Status: "failure"}}
	for i := range 3 {
		ev := failed("10.0.0.1", t0.Add(time.Duration(i)*time.Second))
		ev.Message = "Failed password for root"
		matched, alerts := r.Process(ev)
		if !matched || len(alerts) != 1 {
			t.Fatalf("event %d: matched %v, %d alerts", i, matched, len(alerts))
		}
		a := alerts[0]
		if a.RuleID != "root-login" || a.Severity != "high" || a.Message != "Root login: Failed password for root" ||
			!a.Timestamp.Equal(ev.Timestamp) || !a.Start.Equal(ev.Timestamp) || !a.End.Equal(ev.Timestamp) ||
			len(a.Events) != 1 || a.Events[0] != ev || a.Count() != 1 {
			t.Errorf("alert: %+v", a)
		}
		if _, hasValue := a.Metadata["value"]; hasValue {
			t.Error("a simple alert has no group_by value")
		}
	}
	other := failed("10.0.0.1", t0)
	other.Status = "success"
	if matched, alerts := r.Process(other); matched || alerts != nil {
		t.Errorf("not matching: %v %v", matched, alerts)
	}

	// Without description nor message: the raw line.
	r.Description = ""
	ev := failed("10.0.0.1", t0)
	ev.Raw = "raw line"
	if _, a := r.Process(ev); a[0].Message != "raw line" {
		t.Errorf("message: %q", a[0].Message)
	}

	// Nothing memorized; the data of a former threshold rule of the same id
	// is ignored, then cleared.
	if r.Expire(t0.Add(time.Hour)) != 0 || r.Trim(t0.Add(time.Hour)) != 0 {
		t.Error("expire or trim")
	}
	if data, changed, err := r.Save(); data != nil || changed || err != nil {
		t.Errorf("save: %s %v %v", data, changed, err)
	}
	if n, err := r.Restore([]byte(`{"signature":"x"}`), t0); n != 0 || err != ErrRuleChanged {
		t.Errorf("restore: %d %v", n, err)
	}
	if data, changed, _ := r.Save(); data != nil || !changed {
		t.Error("the old data must be cleared")
	}
	if _, changed, _ := r.Save(); changed {
		t.Error("cleared twice")
	}
	if n, err := r.Restore([]byte(`null`), t0); n != 0 || err != nil {
		t.Errorf("restore null: %d %v", n, err)
	}
}

func TestBuildSimpleRule(t *testing.T) {
	ok := config.Rule{ID: "s", Type: "simple", Description: "d", Severity: "low", Match: config.Match{Service: "sshd"}}
	rules, err := BuildRules([]config.Rule{ok}, nil)
	if err != nil || len(rules) != 1 {
		t.Fatal(rules, err)
	}
	if r, isSimple := rules[0].(*SimpleRule); !isSimple || r.Match.Service != "sshd" || r.Severity != "low" {
		t.Errorf("rule: %+v", rules[0])
	}
	for name, mod := range map[string]func(*config.Rule){
		"group_by": func(r *config.Rule) { r.GroupBy = "SourceIP" },
		"count":    func(r *config.Rule) { r.Count = 3 },
		"window":   func(r *config.Rule) { r.Window = time.Minute },
		"suppress": func(r *config.Rule) { r.Suppress = time.Minute },
	} {
		r := ok
		mod(&r)
		if _, err := BuildRules([]config.Rule{r}, nil); err == nil || !strings.Contains(err.Error(), name+": not used by a simple rule") {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := BuildRules([]config.Rule{{ID: "x", Type: "simpel"}}, nil); err == nil || !strings.Contains(err.Error(), "threshold or simple") {
		t.Errorf("unknown type: %v", err)
	}
}
