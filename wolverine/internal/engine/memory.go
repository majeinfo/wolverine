package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"time"

	"wolverine/internal/verbose"
)

// The memory limit: when wolverine uses more than its quota (a percentage
// of the memory of the machine, or of its cgroup if lower), the oldest data
// is forgotten until it uses less than freeTarget of the quota: the log
// lines first (from the oldest to the most recent, by their time in the log,
// as Trim does), then, if that is not enough, the events counted by the rules
// and the alerts (as Expire does). The quota is also given to the Go runtime
// as its soft memory limit, so that the garbage collector works harder as
// it gets closer.

// memoryCheckInterval is how often the memory used is checked.
const memoryCheckInterval = time.Second

// freeTarget is the fraction of the quota to get under when freeing memory,
// so that it is not freed again right away.
const freeTarget = 0.8

// freeSteps are the fractions of the log TTL (then of the maximum lifetime)
// whose data is forgotten in turn, the oldest first: what was memorized
// more than TTL/2 ago, then TTL/4... then everything.
var freeSteps = []float64{1. / 2, 1. / 4, 1. / 8, 1. / 16, 1. / 64, 0}

// memoryGuard keeps the memory used under a quota.
type memoryGuard struct {
	quota uint64 // bytes
	// used returns the memory used (memoryUsed).
	used func() uint64
	// release returns the memory freed to the system (debug.FreeOSMemory).
	release func()
	// trim forgets the log lines, expire the data, memorized before
	// cutoff; they return how many items were forgotten.
	trim, expire     func(cutoff time.Time) int
	ttl, lifetime    time.Duration
	now              func() time.Time
	lastWarn         time.Time
	freed, freeCalls int // for the tests
}

// newMemoryGuard returns the guard of a quota of percent % of the total
// memory, or nil if there is no limit.
func newMemoryGuard(percent int) (*memoryGuard, error) {
	if percent <= 0 {
		return nil, nil
	}
	total, err := totalMemory()
	if err != nil {
		return nil, err
	}
	quota := uint64(float64(total) * float64(percent) / 100)
	return &memoryGuard{quota: quota, used: memoryUsed, release: debug.FreeOSMemory, now: time.Now}, nil
}

// run checks the memory used every memoryCheckInterval until ctx is done.
func (g *memoryGuard) run(ctx context.Context) {
	t := time.NewTicker(memoryCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.check()
		}
	}
}

// check frees memory if the quota is exceeded.
func (g *memoryGuard) check() {
	used := g.used()
	if used <= g.quota {
		return
	}
	g.freeCalls++
	target := uint64(float64(g.quota) * freeTarget)
	now := g.now()
	lines, data := 0, 0
	done := func() bool {
		g.release()
		used = g.used()
		return used <= target
	}
	// The garbage collector may be enough.
	ok := done()
	for _, f := range freeSteps {
		if ok {
			break
		}
		lines += g.trim(now.Add(-time.Duration(float64(g.ttl) * f)))
		ok = done()
	}
	for _, f := range freeSteps {
		if ok {
			break
		}
		data += g.expire(now.Add(-time.Duration(float64(g.lifetime) * f)))
		ok = done()
	}
	g.freed += lines + data
	msg := fmt.Sprintf("memory limit of %s reached: %d log lines and %d events or alerts forgotten, %s used", formatBytes(g.quota), lines, data, formatBytes(used))
	switch {
	case !ok:
		log.Printf("warning: %s: still above %d%% of the limit", msg, int(freeTarget*100))
	case data > 0 || now.Sub(g.lastWarn) >= time.Minute:
		// Forgetting events changes what the rules count: always said.
		log.Print(msg)
		g.lastWarn = now
	default:
		verbose.Infof("%s", msg)
	}
}

// memoryUsed returns the memory used by the Go runtime, but what it has
// released to the system: about the resident memory of the process.
func memoryUsed() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

// totalMemory returns the memory of the machine, or the memory limit of the
// cgroup of the process if lower.
func totalMemory() (uint64, error) {
	total, err := memInfoTotal("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("total memory: %w", err)
	}
	if limit, ok := cgroupLimit("/proc/self/cgroup", "/sys/fs/cgroup"); ok && limit < total {
		verbose.Infof("memory: limit of the cgroup: %s (machine: %s)", formatBytes(limit), formatBytes(total))
		total = limit
	}
	return total, nil
}

// memInfoTotal reads MemTotal in /proc/meminfo.
func memInfoTotal(file string) (uint64, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// MemTotal:       16303528 kB
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			fields := strings.Fields(rest)
			if len(fields) == 2 && fields[1] == "kB" {
				if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					return n * 1024, nil
				}
			}
			return 0, fmt.Errorf("%s: unexpected MemTotal: %q", file, rest)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New(file + ": no MemTotal")
}

// cgroupLimit returns the lowest memory limit of the cgroup of the process
// and of its parents (cgroup v2, or v1), if any.
func cgroupLimit(selfCgroup, root string) (uint64, bool) {
	b, err := os.ReadFile(selfCgroup)
	if err != nil {
		return 0, false
	}
	limit, found := uint64(math.MaxUint64), false
	read := func(file string) {
		b, err := os.ReadFile(file)
		if err != nil {
			return
		}
		s := strings.TrimSpace(string(b))
		if n, err := strconv.ParseUint(s, 10, 64); err == nil && n < limit {
			limit, found = n, true // "max" (v2) is no limit
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		// v2: "0::/user.slice/...". v1: "4:memory:/user.slice".
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		var dir, file string
		switch {
		case parts[0] == "0" && parts[1] == "":
			dir, file = root, "memory.max"
		case slices.Contains(strings.Split(parts[1], ","), "memory"):
			dir, file = path.Join(root, "memory"), "memory.limit_in_bytes"
		default:
			continue
		}
		// From the cgroup of the process up to the root: a parent may have
		// a lower limit. In a container, the path may not exist: its own
		// cgroup is the root.
		for p := path.Clean("/" + parts[2]); ; p = path.Dir(p) {
			read(path.Join(dir, p, file))
			if p == "/" {
				break
			}
		}
	}
	// cgroup v1 gives a huge number when there is no limit.
	if !found || limit >= 1<<62 {
		return 0, false
	}
	return limit, true
}

// formatBytes gives a size with a binary unit: 1.5 GiB.
func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
