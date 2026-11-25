package detection

import (
	"strings"
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

func TestSaveRestore(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	clock := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	newRule := func() *ThresholdRule {
		r := sshFailedLoginsPerIP(3, time.Hour)
		r.Suppress = time.Hour
		r.Signature = "sig"
		r.Now = func() time.Time { return clock }
		return r
	}
	r := newRule()
	if _, changed, _ := r.Save(); changed {
		t.Fatal("a new rule has nothing to save")
	}
	// .1 raises an alert (suppression), .2 has 2 events: one memorized an
	// hour before the other.
	for i := range 3 {
		r.Evaluate(failed("10.0.0.1", t0.Add(time.Duration(i)*time.Second)))
	}
	r.Evaluate(failed("10.0.0.2", t0))
	clock = clock.Add(time.Hour)
	r.Evaluate(failed("10.0.0.2", t0.Add(time.Second)))
	data, changed, err := r.Save()
	if err != nil || !changed {
		t.Fatalf("save: %v %v", changed, err)
	}
	if _, changed, _ := r.Save(); changed {
		t.Error("nothing changed since the last save")
	}

	// Everything restored.
	r2 := newRule()
	if n, err := r2.Restore(data, clock.Add(-2*time.Hour)); n != 3 || err != nil {
		t.Fatalf("restored %d (%v), want 3", n, err)
	}
	if a := r2.Evaluate(failed("10.0.0.2", t0.Add(2*time.Second))); len(a) != 1 || len(a[0].Events) != 3 {
		t.Fatal("the restored events of .2 do not count")
	}
	for i := range 3 {
		if a := r2.Evaluate(failed("10.0.0.1", t0.Add(time.Duration(10+i)*time.Second))); a != nil {
			t.Fatal("the restored suppression of .1 does not apply")
		}
	}

	// The event of .2 and the suppression memorized at the first clock
	// time are expired.
	r3 := newRule()
	if n, _ := r3.Restore(data, clock.Add(-time.Minute)); n != 1 || len(r3.groups["10.0.0.2"]) != 1 || len(r3.fired) != 0 {
		t.Fatalf("restored %d: %v %v", n, r3.groups, r3.fired)
	}
	if _, changed, _ := r3.Save(); !changed {
		t.Error("the expired data must be removed from the file")
	}

	// Another rule, or invalid data: nothing restored.
	r4 := newRule()
	r4.Signature = "other"
	if n, err := r4.Restore(data, time.Time{}); n != 0 || err != ErrRuleChanged {
		t.Errorf("other signature: %d %v", n, err)
	}
	if n, err := newRule().Restore([]byte("{"), time.Time{}); n != 0 || err == nil {
		t.Errorf("invalid data: %d %v", n, err)
	}
}

// Trim forgets the log lines memorized before the cutoff, but the rule still
// counts their events; the alert has only the events kept.
func TestTrim(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	clock := t0
	r := sshFailedLoginsPerIP(4, time.Hour)
	r.Now = func() time.Time { return clock }

	for i := range 3 { // memorized at t0, +1m, +2m
		clock = t0.Add(time.Duration(i) * time.Minute)
		r.Evaluate(failed("10.0.0.1", t0.Add(time.Duration(i)*time.Minute)))
	}
	if n := r.Trim(t0.Add(90 * time.Second)); n != 2 {
		t.Fatalf("trimmed %d log lines, want 2", n)
	}
	if n := r.Trim(t0.Add(90 * time.Second)); n != 0 {
		t.Errorf("trimmed again: %d", n)
	}

	// Saved and restored: the trimmed events keep their time.
	data, changed, err := r.Save()
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	if strings.Count(string(data), `"event"`) != 1 || strings.Count(string(data), `"time"`) != 2 {
		t.Errorf("saved: %s", data)
	}
	r2 := sshFailedLoginsPerIP(4, time.Hour)
	r2.Now = r.Now
	if n, err := r2.Restore(data, t0.Add(-time.Hour)); n != 3 || err != nil {
		t.Fatalf("restored %d, %v", n, err)
	}

	for _, rule := range []*ThresholdRule{r, r2} {
		clock = t0.Add(3 * time.Minute)
		alerts := rule.Evaluate(failed("10.0.0.1", t0.Add(3*time.Minute)))
		if len(alerts) != 1 {
			t.Fatalf("got %d alerts, want 1: the trimmed events count", len(alerts))
		}
		a := alerts[0]
		if len(a.Events) != 2 || a.Count() != 4 || !a.Events[0].Timestamp.Equal(t0.Add(2*time.Minute)) ||
			!strings.Contains(a.Message, "4 events for SourceIP=10.0.0.1 within 3m0s") {
			t.Errorf("alert: %d events, count %d, %q", len(a.Events), a.Count(), a.Message)
		}
	}
}

// Trim goes by the time of the events in the log, not when they were read:
// events read late, out of order, are trimmed by their own time.
func TestTrimByLogTime(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r := sshFailedLoginsPerIP(10, 24*time.Hour)
	r.Now = func() time.Time { return t0.Add(5 * time.Hour) } // all read now
	r.Evaluate(failed("10.0.0.1", t0.Add(4*time.Hour)))
	r.Evaluate(failed("10.0.0.1", t0)) // older, read after
	r.Evaluate(failed("10.0.0.1", t0.Add(3*time.Hour)))
	if n := r.Trim(t0.Add(2 * time.Hour)); n != 1 {
		t.Fatalf("trimmed %d log lines, want 1", n)
	}
	for _, m := range r.groups["10.0.0.1"] {
		if (m.ev == nil) != m.ts.Equal(t0) {
			t.Errorf("event of %s: trimmed %v", m.ts.Format("15:04"), m.ev == nil)
		}
	}
}

// Events out of order (several files or S3 objects): the time between the
// first and the last is never negative, and the window ends at the newest.
func TestOutOfOrder(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	r := sshFailedLoginsPerIP(3, 10*time.Minute)
	r.Evaluate(failed("10.0.0.1", t0.Add(5*time.Minute)))
	r.Evaluate(failed("10.0.0.1", t0.Add(8*time.Minute)))
	alerts := r.Evaluate(failed("10.0.0.1", t0.Add(time.Minute))) // older
	if len(alerts) != 1 || !strings.HasSuffix(alerts[0].Message, "3 events for SourceIP=10.0.0.1 within 7m0s") {
		t.Fatalf("alerts: %+v", alerts)
	}
	// The time range of the events, whatever their order.
	if a := alerts[0]; !a.Start.Equal(t0.Add(time.Minute)) || !a.End.Equal(t0.Add(8*time.Minute)) || !a.Timestamp.Equal(t0.Add(time.Minute)) {
		t.Errorf("range: %s - %s, timestamp %s", a.Start, a.End, a.Timestamp)
	}

	// An event older than the window of the newest is not counted, and an
	// older one memorized first is dropped by a newer one.
	r.Evaluate(failed("10.0.0.2", t0.Add(time.Minute)))
	r.Evaluate(failed("10.0.0.2", t0.Add(30*time.Minute))) // drops +1m
	if a := r.Evaluate(failed("10.0.0.2", t0.Add(2*time.Minute))); a != nil {
		t.Errorf("an event older than the window counted: %+v", a)
	}
	r.Evaluate(failed("10.0.0.2", t0.Add(25*time.Minute)))
	if a := r.Evaluate(failed("10.0.0.2", t0.Add(21*time.Minute))); len(a) != 1 || !strings.HasSuffix(a[0].Message, "within 9m0s") {
		t.Errorf("within the window: %+v", a)
	}
}
