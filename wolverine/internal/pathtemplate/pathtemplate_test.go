package pathtemplate

import (
	"strings"
	"testing"
	"time"
)

func TestExpand(t *testing.T) {
	at := func(s string) time.Time {
		d, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	tests := []struct {
		tmpl, now, want string
	}{
		{"/var/log/file.log.${year}-${month}-${day}", "2026-11-10 08:30:00", "/var/log/file.log.2026-11-10"},
		{"/var/log/file.log.${year}-${month}-${day-1}", "2026-11-10 08:30:00", "/var/log/file.log.2026-11-09"},
		// Shifts move the whole date.
		{"/var/log/file.log.${year}-${month}-${day-1}", "2026-03-01 00:10:00", "/var/log/file.log.2026-02-28"},
		{"/var/log/file.log.${year}-${month}-${day-1}", "2026-01-01 00:10:00", "/var/log/file.log.2025-12-31"},
		{"/x/${year}${month}${day}${hour - 1}", "2026-01-01 00:10:00", "/x/2025123123"},
		{"/x/${year}${month+1}", "2026-12-15 00:00:00", "/x/202701"},
		{"/x/${year}-${month-1}-${day}", "2026-03-31 00:00:00", "/x/2026-02-28"},
		{"/x/${year}${month}${day}T${hour}${minute}${second+30}", "2026-11-10 23:59:45", "/x/20261111T000015"},
		// Shifts apply even to the macros written before them.
		{"/x/${month}/${day+1}", "2026-11-30 12:00:00", "/x/12/01"},
		// The same shift twice is fine.
		{"/x/${day-1}/${day-1}", "2026-11-10 12:00:00", "/x/09/09"},
		// Other expressions: computed from the shifted date, rounded down.
		{"/x/${year%100}${month}", "2026-11-10 12:00:00", "/x/2611"},
		// The arithmetic is done on floats: only the result is rounded down.
		{"/x/${hour/6*6}", "2026-11-10 13:00:00", "/x/13"},
		{"/x/${hour - hour%6}", "2026-11-10 13:00:00", "/x/12"},
		{"/x/${hour/6}", "2026-11-10 13:00:00", "/x/02"},
		{"/x/${year%100}-${day-1}", "2027-01-01 12:00:00", "/x/26-31"},
		{"/x/${day > 15 ? 2 : 1}", "2026-11-20 12:00:00", "/x/02"},
		{"/plain/path.log", "2026-11-10 12:00:00", "/plain/path.log"},
		{"/x/$HOME/${day}", "2026-11-10 12:00:00", "/x/$HOME/10"},
	}
	for _, tt := range tests {
		tmpl, err := Parse(tt.tmpl)
		if err != nil {
			t.Errorf("%s: %v", tt.tmpl, err)
			continue
		}
		got, err := tmpl.Expand(at(tt.now))
		if err != nil {
			t.Errorf("%s at %s: %v", tt.tmpl, tt.now, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s at %s: got %s, want %s", tt.tmpl, tt.now, got, tt.want)
		}
	}
}

func TestExpandLocation(t *testing.T) {
	tmpl, _ := Parse("${year}-${month}-${day}T${hour}")
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip(err)
	}
	now := time.Date(2026, 11, 10, 23, 30, 0, 0, time.UTC)
	if got, _ := tmpl.Expand(now.In(paris)); got != "2026-11-11T00" {
		t.Errorf("got %s, want the date in Paris", got)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ tmpl, want string }{
		{"/x/${day", "unclosed"},
		{"/x/${}", "empty"},
		{"/x/${week}", `unknown variable "week"`},
		{"/x/${day +}", "macro ${day +}"},
		{"/x/${day-1}${day-2}", "shifted by -1 elsewhere"},
		{"/x/${day > 3}", "not a number"},
		{"/x/${'abc'}", "not a number"},
	}
	for _, tt := range tests {
		if _, err := Parse(tt.tmpl); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.tmpl, err, tt.want)
		}
	}
}
