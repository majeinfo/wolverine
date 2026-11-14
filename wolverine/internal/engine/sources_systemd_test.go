//go:build !nosystemd

package engine

import (
	"strings"
	"testing"

	"wolverine/internal/config"
	"wolverine/internal/source/systemd"
)

func systemdService(unit string) config.Source {
	return config.Source{ID: "sshd-journal", Type: "systemd-service", Unit: unit}
}

func TestBuildSystemdService(t *testing.T) {
	c := systemdService("sshd")
	c.Follow, c.StartAt, c.Regexp = true, "end", `^Failed (?P<auth_method>\S+)`
	inputs, err := buildSources([]config.Source{c})
	if err != nil {
		t.Fatal(err)
	}
	j := inputs[0].source.(*systemd.Journal)
	if j.Unit != "sshd.service" || !j.Follow || !j.StartAtEnd {
		t.Errorf("unexpected source: %+v", j)
	}
	p := inputs[0].parser.(*systemd.Parser)
	if p.Regexp == nil || p.Category != "system" {
		t.Errorf("unexpected parser: %+v", p)
	}

	// The suffix is kept when given, and the regexp is optional.
	inputs, err = buildSources([]config.Source{systemdService("cron.timer")})
	if err != nil {
		t.Fatal(err)
	}
	if u := inputs[0].source.(*systemd.Journal).Unit; u != "cron.timer" {
		t.Errorf("unit %q, want cron.timer", u)
	}
}

func TestBuildSystemdServiceErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*config.Source)
		want string
	}{
		{"no unit", func(c *config.Source) { c.Unit = "" }, "unit is required"},
		{"match injection", func(c *config.Source) { c.Unit = "x _UID=0" }, "invalid unit name"},
		{"path", func(c *config.Source) { c.Path = "/var/log/messages" }, "path, directory and filename_regexp do not apply"},
		{"timestamp_formats", func(c *config.Source) { c.TimestampFormats = []string{"rfc3164"} }, "timestamp_formats does not apply"},
		{"timezone", func(c *config.Source) { c.Timezone = "UTC" }, "timezone does not apply"},
		{"skip_lines", func(c *config.Source) { c.SkipLines = 1 }, "skip_lines does not apply"},
		{"end without follow", func(c *config.Source) { c.StartAt = "end" }, "requires follow"},
		{"bad regexp", func(c *config.Source) { c.Regexp = "(" }, "regexp:"},
	}
	for _, tt := range tests {
		c := systemdService("sshd")
		tt.mod(&c)
		if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}

	c := logfile("/var/log/messages")
	c.Unit = "sshd"
	if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), "unit does not apply") {
		t.Errorf("logfile with a unit: got %v", err)
	}

}
