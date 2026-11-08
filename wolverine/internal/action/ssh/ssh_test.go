package ssh

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wolverine/internal/event"
)

func alert(ip, user string) *event.Alert {
	return &event.Alert{
		ID:       "a1",
		RuleID:   "ssh-failed-logins-per-ip",
		Severity: "high",
		Metadata: map[string]any{"value": ip},
		Events:   []*event.Event{{SourceIP: ip, Username: user, Hostname: "web01"}},
	}
}

func newSSH(t *testing.T, command string) *SSH {
	t.Helper()
	tmpl, err := ParseCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	return &SSH{ID: "block", Host: "fw.example.com", Command: tmpl}
}

func TestRender(t *testing.T) {
	s := newSSH(t, "ipset add blocklist {{.SourceIP}} -exist # {{.RuleID}} {{.Username}}@{{.Hostname}}")
	got, err := s.render(alert("203.0.113.7", "root"))
	if err != nil {
		t.Fatal(err)
	}
	want := "ipset add blocklist '203.0.113.7' -exist # 'ssh-failed-logins-per-ip' 'root'@'web01'"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// Values come from logs: they must never escape their quotes.
func TestRenderInjection(t *testing.T) {
	s := newSSH(t, "logger blocked {{.Username}}")
	got, err := s.render(alert("1.2.3.4", `x'; rm -rf / #`))
	if err != nil {
		t.Fatal(err)
	}
	want := `logger blocked 'x'\''; rm -rf / #'`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRenderEmptyValue(t *testing.T) {
	s := newSSH(t, "ipset add blocklist {{.SourceIP}}")
	if _, err := s.render(alert("", "root")); err == nil {
		t.Fatal("expected an error for an empty SourceIP")
	}
}

func TestParseCommandUnknownVariable(t *testing.T) {
	if _, err := ParseCommand("echo {{.Nope}}"); err == nil {
		t.Fatal("expected an error")
	}
}

// fakeSSH writes a script that records its arguments, one per line.
func fakeSSH(t *testing.T, exitCode string) (bin, argsFile string) {
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "ssh")
	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > " + argsFile + "\necho remote output\nexit " + exitCode + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestExecute(t *testing.T) {
	bin, argsFile := fakeSSH(t, "0")
	s := newSSH(t, "ipset add blocklist {{.SourceIP}} -exist")
	s.Binary, s.Port, s.User, s.IdentityFile = bin, 2222, "wolverine", "/etc/wolverine/id_ed25519"

	if err := s.Execute(context.Background(), alert("203.0.113.7", "root")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(argsFile)
	want := strings.Join([]string{
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
		"-p", "2222", "-l", "wolverine",
		"-i", "/etc/wolverine/id_ed25519", "-o", "IdentitiesOnly=yes",
		"--", "fw.example.com", "ipset add blocklist '203.0.113.7' -exist",
	}, "\n") + "\n"
	if string(got) != want {
		t.Errorf("ssh args:\n%s\nwant:\n%s", got, want)
	}
}

func TestExecuteFailure(t *testing.T) {
	bin, _ := fakeSSH(t, "1")
	s := newSSH(t, "false")
	s.Binary = bin
	err := s.Execute(context.Background(), alert("203.0.113.7", "root"))
	if err == nil || !strings.Contains(err.Error(), "remote output") {
		t.Fatalf("got %v, want an error with the command output", err)
	}
}

func TestAllowlist(t *testing.T) {
	bin, argsFile := fakeSSH(t, "0")
	s := newSSH(t, "ipset add blocklist {{.SourceIP}} -exist")
	s.Binary = bin
	s.Allowlist = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}

	for _, ip := range []string{"10.1.2.3", "::ffff:10.1.2.3", "2001:db8::1"} {
		if err := s.Execute(context.Background(), alert(ip, "root")); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(argsFile); err == nil {
			t.Fatalf("%s is allowlisted, ssh must not run", ip)
		}
	}

	if err := s.Execute(context.Background(), alert("203.0.113.7", "root")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(argsFile); err != nil {
		t.Fatal("203.0.113.7 is not allowlisted, ssh must run")
	}
}
