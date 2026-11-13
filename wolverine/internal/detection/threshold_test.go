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

func TestExcludeIf(t *testing.T) {
	r := sshFailedLoginsPerIP(2, time.Minute)
	calls := 0
	r.Match.ExcludeIf = func(ev *event.Event) bool {
		calls++
		return ev.Username == "deploy"
	}
	now := time.Now()
	ev := func(user string) *event.Event {
		e := failed("10.0.0.1", now)
		e.Username = user
		return e
	}
	for range 3 {
		if alerts := r.Evaluate(ev("deploy")); len(alerts) != 0 {
			t.Fatalf("excluded events raised %d alerts", len(alerts))
		}
	}
	// Only called for the events the rule matches otherwise.
	other := ev("root")
	other.Category = "system"
	r.Evaluate(other)
	if calls != 3 {
		t.Errorf("called %d times, want 3", calls)
	}
	r.Evaluate(ev("root"))
	if alerts := r.Evaluate(ev("root")); len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
}

func TestExpire(t *testing.T) {
	// Event times far apart from the wall clock: replayed old logs.
	t0 := time.Date(2020, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	r := sshFailedLoginsPerIP(3, time.Hour)
	r.Suppress = time.Hour
	r.Now = func() time.Time { return clock }

	// Two events for .1 memorized at 10:00 and 10:05, one for .2 at 10:05.
	r.Evaluate(failed("10.0.0.1", t0))
	clock = clock.Add(5 * time.Minute)
	r.Evaluate(failed("10.0.0.1", t0.Add(time.Second)))
	r.Evaluate(failed("10.0.0.2", t0.Add(time.Second)))

	// Only the first event was memorized before 10:01.
	if n := r.Expire(clock.Add(-4 * time.Minute)); n != 1 {
		t.Fatalf("expired %d, want 1", n)
	}
	if len(r.groups["10.0.0.1"]) != 1 || len(r.groups["10.0.0.2"]) != 1 {
		t.Fatalf("groups after expiry: %v", r.groups)
	}
	// The expired event no longer counts: 2 more are needed.
	if a := r.Evaluate(failed("10.0.0.1", t0.Add(2*time.Second))); a != nil {
		t.Fatal("an expired event was counted")
	}
	if a := r.Evaluate(failed("10.0.0.1", t0.Add(3*time.Second))); len(a) != 1 {
		t.Fatal("no alert")
	}
	if len(r.fired) != 1 {
		t.Fatalf("suppressions: %v", r.fired)
	}

	// Everything memorized up to now expires: the group of .2 and the
	// suppression of .1, which no longer prevents an alert.
	clock = clock.Add(time.Minute)
	if n := r.Expire(clock); n != 2 {
		t.Fatalf("expired %d, want 2", n)
	}
	if len(r.groups) != 0 || len(r.fired) != 0 {
		t.Fatalf("left: %v %v", r.groups, r.fired)
	}
	for i := range 3 {
		if a := r.Evaluate(failed("10.0.0.1", t0.Add(time.Duration(4+i)*time.Second))); (len(a) == 1) != (i == 2) {
			t.Fatalf("event %d: %d alerts", i, len(a))
		}
	}
}
