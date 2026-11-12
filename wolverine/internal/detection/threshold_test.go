package detection

import (
	"testing"
	"time"

	"wolverine/internal/event"
)

func failed(ip string, at time.Time) *event.Event {
	return &event.Event{
		Timestamp: at,
		Category:  "authentication",
		Action:    "login",
		Status:    "failure",
		SourceIP:  ip,
		Fields:    map[string]any{"auth_method": "password"},
	}
}

func sshFailedLoginsPerIP(count int, window time.Duration) *ThresholdRule {
	return &ThresholdRule{
		RuleID: "ssh-failed-logins-per-ip",
		Match: Match{
			Category:  "authentication",
			Action:    "login",
			Status:    "failure",
			HasFields: []string{"auth_method"},
		},
		GroupBy: "SourceIP",
		Count:   count,
		Window:  window,
	}
}

func TestSSHFailedLoginsPerIP(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r := sshFailedLoginsPerIP(3, time.Minute)

	// Two failures, then a third outside the window: no alert.
	for _, d := range []time.Duration{0, 10 * time.Second, 80 * time.Second} {
		if a := r.Evaluate(failed("10.0.0.1", t0.Add(d))); a != nil {
			t.Fatalf("unexpected alert at +%s", d)
		}
	}
	// Another IP interleaved does not count for 10.0.0.1.
	if a := r.Evaluate(failed("10.0.0.2", t0.Add(85*time.Second))); a != nil {
		t.Fatal("unexpected alert for 10.0.0.2")
	}
	// PAM duplicate (no auth_method) is ignored.
	pam := failed("10.0.0.1", t0.Add(86*time.Second))
	delete(pam.Fields, "auth_method")
	if a := r.Evaluate(pam); a != nil {
		t.Fatal("PAM duplicate should not be counted")
	}
	// +80s and +90s are within a minute of +100s: third failure fires.
	r.Evaluate(failed("10.0.0.1", t0.Add(90*time.Second)))
	alerts := r.Evaluate(failed("10.0.0.1", t0.Add(100*time.Second)))
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "ssh-failed-logins-per-ip" || len(a.Events) != 3 || a.Metadata["value"] != "10.0.0.1" {
		t.Errorf("unexpected alert: %+v", a)
	}

	// Counter is reset after firing.
	if a := r.Evaluate(failed("10.0.0.1", t0.Add(101*time.Second))); a != nil {
		t.Fatal("counter should be reset after an alert")
	}
}

func TestSuppress(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r := sshFailedLoginsPerIP(2, time.Minute)
	r.Suppress = 10 * time.Minute

	count := func(from, to time.Duration) (n int) {
		for d := from; d < to; d += 10 * time.Second {
			n += len(r.Evaluate(failed("10.0.0.1", t0.Add(d))))
		}
		return n
	}
	// 2 failures every 20s for 9 minutes: only the first alert is sent.
	if n := count(0, 9*time.Minute); n != 1 {
		t.Fatalf("got %d alerts during suppression, want 1", n)
	}
	// After the suppression period, the next threshold crossing alerts again.
	if n := count(10*time.Minute, 10*time.Minute+20*time.Second); n != 1 {
		t.Fatalf("got %d alerts after suppression, want 1", n)
	}
	// Another IP is not suppressed.
	r.Evaluate(failed("10.0.0.2", t0.Add(11*time.Minute)))
	if a := r.Evaluate(failed("10.0.0.2", t0.Add(11*time.Minute))); len(a) != 1 {
		t.Fatal("10.0.0.2 should not be suppressed")
	}
}

func TestSweepForgetsOldGroups(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r := sshFailedLoginsPerIP(5, time.Minute)
	r.Evaluate(failed("10.0.0.1", t0))
	r.Evaluate(failed("10.0.0.2", t0.Add(2*time.Minute)))
	if _, ok := r.groups["10.0.0.1"]; ok || len(r.groups) != 1 {
		t.Errorf("stale group not swept: %v", r.groups)
	}
}

func TestExclude(t *testing.T) {
	r := sshFailedLoginsPerIP(2, time.Minute)
	r.Match.Exclude = []string{"admins"}
	now := time.Now()
	ev := func(by ...string) *event.Event {
		e := failed("10.0.0.1", now)
		e.ExcludedBy = by
		return e
	}

	// Events excluded by one of the rule's lists are not counted.
	for range 3 {
		if alerts := r.Evaluate(ev("localhost", "admins")); len(alerts) != 0 {
			t.Fatalf("excluded events raised %d alerts", len(alerts))
		}
	}
	// Those of other lists are.
	r.Evaluate(ev("localhost"))
	if alerts := r.Evaluate(ev()); len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
}
