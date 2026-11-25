package stats

import (
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	t0 := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	clock := t0
	s := New([]string{"ssh", "web"}, []string{"brute", "idle"})
	s.Now = func() time.Time { return clock }
	at := func(d time.Duration) { clock = t0.Add(d) }

	// 10:00:10: 3 lines of ssh, one unparsed; a match.
	at(10 * time.Second)
	s.Line("ssh", 10, true, false)
	s.Line("ssh", 10, true, false)
	s.Line("ssh", 10, false, true)
	s.Matched([]string{"brute"}, nil)
	// 10:02:30: a line of web, excluded; a line of ssh: match and alert.
	at(150 * time.Second)
	s.Line("web", 10, true, false)
	s.Excluded("web")
	s.Old("ssh")
	s.Line("ssh", 10, true, false)
	s.Matched([]string{"brute"}, []string{"brute"})
	s.Matched(nil, nil)

	tot := s.Total()
	if tot.Totals != (Totals{Source{5, 4, 1, 1, 1, 50}, Rule{2, 1}}) {
		t.Errorf("totals: %+v", tot.Totals)
	}
	if *tot.Sources["ssh"] != (Source{4, 3, 1, 0, 1, 40}) || *tot.Sources["web"] != (Source{1, 1, 0, 1, 0, 10}) {
		t.Errorf("sources: %+v %+v", tot.Sources["ssh"], tot.Sources["web"])
	}
	if *tot.Rules["brute"] != (Rule{2, 1}) || *tot.Rules["idle"] != (Rule{}) {
		t.Errorf("rules: %+v %+v", tot.Rules["brute"], tot.Rules["idle"])
	}

	// An interval: the buckets that start in it, at a minute's resolution.
	if c := s.Interval(t0.Add(time.Minute), t0.Add(time.Hour)); c.Totals.Lines != 2 || c.Totals.Alerts != 1 || c.Sources["ssh"].Lines != 1 {
		t.Errorf("interval from 10:01: %+v", c.Totals)
	}
	if c := s.Interval(t0.Add(30*time.Second), t0.Add(time.Minute)); c.Totals.Lines != 3 {
		t.Errorf("interval 10:00:30-10:01 (from rounded down): %+v", c.Totals)
	}
	if c := s.Interval(t0.Add(time.Hour), t0.Add(2*time.Hour)); c.Totals != (Totals{}) || c.Rules["idle"] == nil {
		t.Errorf("empty interval: %+v", c)
	}

	// A series by 2 minutes, from 9:59: buckets 9:58, 10:00, 10:02.
	series := s.Series(t0.Add(-time.Minute), t0.Add(3*time.Minute), 2*time.Minute)
	if len(series) != 3 || !series[0].Start.Equal(t0.Add(-2*time.Minute)) {
		t.Fatalf("series: %+v", series)
	}
	for i, want := range []int64{0, 3, 2} {
		if series[i].Totals.Lines != want {
			t.Errorf("bucket %s: %d lines, want %d", series[i].Start.Format("15:04"), series[i].Totals.Lines, want)
		}
	}
	if series[2].Rules["brute"].Alerts != 1 || series[0].Sources["web"] == nil {
		t.Errorf("bucket 10:02: %+v", series[2].Counts)
	}
	// The step is at least the resolution.
	if n := len(s.Series(t0, t0.Add(3*time.Minute), time.Second)); n != 3 {
		t.Errorf("%d buckets by 1s, want 3 (by minute)", n)
	}

	// Expire drops the buckets that ended before the cutoff, not the
	// totals.
	if n := s.Expire(t0.Add(90 * time.Second)); n != 1 || !s.Oldest().Equal(t0.Add(2*time.Minute)) {
		t.Errorf("expired %d, oldest %s", n, s.Oldest())
	}
	if c := s.Interval(t0, t0.Add(time.Hour)); c.Totals.Lines != 2 {
		t.Errorf("after expiry: %+v", c.Totals)
	}
	if s.Total().Totals.Lines != 5 {
		t.Error("totals changed by Expire")
	}
}
