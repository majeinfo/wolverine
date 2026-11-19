package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wolverine/internal/event"
)

func alertWith(id string, n int) *event.Alert {
	a := &event.Alert{ID: id, RuleID: "r", Metadata: map[string]any{"count": n}}
	for i := range n {
		a.Events = append(a.Events, &event.Event{Raw: id + "-" + string(rune('a'+i))})
	}
	return a
}

// The alerts raised before the cutoff keep only their last event; the
// alert itself is not modified (it may be in use), but replaced.
func TestHistoryTrim(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	var h history
	old, recent := alertWith("old", 3), alertWith("recent", 3)
	h.add(old, t0)
	h.add(recent, t0.Add(time.Hour))
	h.saved()

	if n := h.trim(t0.Add(time.Minute)); n != 2 {
		t.Fatalf("trimmed %d events, want 2", n)
	}
	if _, changed := h.saved(); !changed {
		t.Error("the state file must be saved again")
	}
	if n := h.trim(t0.Add(time.Minute)); n != 0 {
		t.Errorf("trimmed again: %d", n)
	}
	recs := h.records()
	if a := recs[0].Alert; len(a.Events) != 1 || a.Events[0].Raw != "old-c" || a.Count() != 3 || a.ID != "old" {
		t.Errorf("trimmed alert: %+v", a)
	}
	if len(old.Events) != 3 {
		t.Error("the original alert was modified")
	}
	if len(recs[1].Alert.Events) != 3 {
		t.Error("the recent alert was trimmed")
	}
	if h.byID["old"].alert != recs[0].Alert {
		t.Error("byID not updated")
	}
}

// The guard frees the oldest log lines first, then the oldest data, until
// the memory used is under the target.
func TestMemoryGuard(t *testing.T) {
	t0 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	var calls []string
	used := uint64(0)
	g := &memoryGuard{
		quota:    1000,
		ttl:      time.Hour,
		lifetime: 24 * time.Hour,
		now:      func() time.Time { return t0 },
		used:     func() uint64 { return used },
		release:  func() {},
	}
	// Each step frees 100 bytes.
	g.trim = func(cutoff time.Time) int {
		calls = append(calls, "trim "+t0.Sub(cutoff).String())
		used -= 100
		return 10
	}
	g.expire = func(cutoff time.Time) int {
		calls = append(calls, "expire "+t0.Sub(cutoff).String())
		used -= 100
		return 1
	}

	used = 1000 // at the quota: nothing to do
	g.check()
	if len(calls) != 0 {
		t.Errorf("under the quota: %v", calls)
	}

	used = 1001 // over: down to 80% of the quota
	g.check()
	if want := "trim 30m0s,trim 15m0s,trim 7m30s"; strings.Join(calls, ",") != want {
		t.Errorf("calls: %v, want %s", calls, want)
	}

	// The log lines are not enough: then the events and alerts, the oldest
	// first.
	calls, used = nil, 1650
	g.check()
	want := "trim 30m0s,trim 15m0s,trim 7m30s,trim 3m45s,trim 56.25s,trim 0s,expire 12h0m0s,expire 6h0m0s,expire 3h0m0s"
	if strings.Join(calls, ",") != want {
		t.Errorf("calls: %v\nwant %s", calls, want)
	}
	if g.freed != 30+60+3 {
		t.Errorf("freed: %d", g.freed)
	}

	// Nothing more to free: everything is tried, then given up.
	calls, used = nil, 1e6
	g.check()
	if len(calls) != 12 {
		t.Errorf("calls: %v", calls)
	}
}

func TestTotalMemory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mi := write("meminfo", "MemTotal:       16303528 kB\nMemFree:  1 kB\n")
	if n, err := memInfoTotal(mi); err != nil || n != 16303528*1024 {
		t.Errorf("MemTotal: %d, %v", n, err)
	}
	if _, err := memInfoTotal(write("bad", "MemFree: 1 kB\n")); err == nil {
		t.Error("no MemTotal: no error")
	}

	// cgroup v2: the lowest limit from the cgroup up to the root.
	self := write("self", "0::/user.slice/app.service\n")
	root := filepath.Join(dir, "cg")
	write("cg/user.slice/app.service/memory.max", "max\n")
	if _, ok := cgroupLimit(self, root); ok {
		t.Error("max: no limit")
	}
	write("cg/user.slice/memory.max", "2147483648\n")
	if n, ok := cgroupLimit(self, root); !ok || n != 2<<30 {
		t.Errorf("parent limit: %d %v", n, ok)
	}
	write("cg/user.slice/app.service/memory.max", "1073741824\n")
	if n, ok := cgroupLimit(self, root); !ok || n != 1<<30 {
		t.Errorf("own limit: %d %v", n, ok)
	}
	// In a container: its cgroup is the root.
	write("cg/memory.max", "536870912\n")
	if n, ok := cgroupLimit(write("self2", "0::/\n"), root); !ok || n != 512<<20 {
		t.Errorf("container: %d %v", n, ok)
	}

	// cgroup v1, without a limit (a huge number).
	v1 := write("self3", "12:cpu,cpuacct:/\n4:memory:/\n")
	write("cg/memory/memory.limit_in_bytes", "9223372036854771712\n")
	if _, ok := cgroupLimit(v1, root); ok {
		t.Error("v1 without a limit")
	}
	write("cg/memory/memory.limit_in_bytes", "268435456\n")
	if n, ok := cgroupLimit(v1, root); !ok || n != 256<<20 {
		t.Errorf("v1: %d %v", n, ok)
	}

	// The real machine.
	if n, err := totalMemory(); err != nil || n == 0 {
		t.Errorf("totalMemory: %d, %v", n, err)
	}
	if s := formatBytes(1536 << 20); s != "1.5 GiB" {
		t.Errorf("formatBytes: %s", s)
	}
}
