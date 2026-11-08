package enrichment

import (
	"context"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"wolverine/internal/event"
)

// sshdRule maps an sshd message pattern to an action and status. Patterns use
// the named groups "user", "ip", "port" and "method", all optional.
type sshdRule struct {
	re          *regexp.Regexp
	action      string
	status      string
	invalidUser bool
}

const (
	ipPort = `(?P<ip>[0-9A-Fa-f.:]+) port (?P<port>\d+)`
	user   = `(?P<user>\S*)`
)

var sshdRules = []sshdRule{
	{re: regexp.MustCompile(`^Accepted (?P<method>\S+) for ` + user + ` from ` + ipPort), action: "login", status: "success"},
	{re: regexp.MustCompile(`^Failed (?P<method>\S+) for invalid user ` + user + ` from ` + ipPort), action: "login", status: "failure", invalidUser: true},
	{re: regexp.MustCompile(`^Failed (?P<method>\S+) for ` + user + ` from ` + ipPort), action: "login", status: "failure"},
	{re: regexp.MustCompile(`^Invalid user ` + user + ` from ` + ipPort), action: "login", status: "failure", invalidUser: true},
	{re: regexp.MustCompile(`^error: maximum authentication attempts exceeded for invalid user ` + user + ` from ` + ipPort), action: "login", status: "failure", invalidUser: true},
	{re: regexp.MustCompile(`^error: maximum authentication attempts exceeded for ` + user + ` from ` + ipPort), action: "login", status: "failure"},
	{re: regexp.MustCompile(`^User ` + user + ` from (?P<ip>[0-9A-Fa-f.:]+) not allowed`), action: "login", status: "denied"},
	{re: regexp.MustCompile(`^pam_unix\(sshd:session\): session opened for user ` + `(?P<user>[^\s(]+)`), action: "session_open", status: "success"},
	{re: regexp.MustCompile(`^pam_unix\(sshd:session\): session closed for user ` + `(?P<user>[^\s(]+)`), action: "session_close", status: "success"},
	{re: regexp.MustCompile(`^pam_unix\(sshd:auth\): authentication failure;.* rhost=(?P<ip>[0-9A-Fa-f.:]+)(?:\s+user=` + user + `)?`), action: "login", status: "failure"},
	{re: regexp.MustCompile(`^Disconnected from invalid user ` + user + ` ` + ipPort), action: "disconnect", status: "success", invalidUser: true},
	{re: regexp.MustCompile(`^Disconnected from (?:authenticating )?user ` + user + ` ` + ipPort), action: "disconnect", status: "success"},
	{re: regexp.MustCompile(`^Connection closed by invalid user ` + user + ` ` + ipPort), action: "disconnect", status: "failure", invalidUser: true},
	{re: regexp.MustCompile(`^Connection closed by (?:authenticating user ` + user + ` )?` + ipPort), action: "disconnect", status: "failure"},
	{re: regexp.MustCompile(`^Received disconnect from ` + ipPort), action: "disconnect", status: "success"},
	{re: regexp.MustCompile(`^Connection reset by (?:authenticating user ` + user + ` )?` + ipPort), action: "disconnect", status: "failure"},
	{re: regexp.MustCompile(`^Did not receive identification string from ` + ipPort), action: "connect", status: "failure"},
	{re: regexp.MustCompile(`^Unable to negotiate with ` + ipPort), action: "connect", status: "failure"},
	{re: regexp.MustCompile(`^banner exchange: Connection from ` + ipPort), action: "connect", status: "failure"},
}

// SSHD extracts the user, source IP, action and status from OpenSSH messages.
// Events from other services are returned unchanged.
type SSHD struct{}

func (SSHD) Name() string { return "sshd" }

func (SSHD) Process(_ context.Context, ev *event.Event) (*event.Event, error) {
	// OpenSSH >= 9.8 logs from "sshd-session" (and "sshd-auth" in 10.x).
	if ev.Service != "sshd" && !strings.HasPrefix(ev.Service, "sshd-") {
		return ev, nil
	}

	for _, r := range sshdRules {
		m := r.re.FindStringSubmatch(ev.Message)
		if m == nil {
			continue
		}

		ev.Category = "authentication"
		ev.Action = r.action
		ev.Status = r.status
		if ev.Fields == nil {
			ev.Fields = map[string]any{}
		}
		if r.invalidUser {
			ev.Fields["invalid_user"] = true
		}

		for i, name := range r.re.SubexpNames() {
			v := m[i]
			if v == "" {
				continue
			}
			switch name {
			case "user":
				ev.Username = v
			case "ip":
				if addr, err := netip.ParseAddr(v); err == nil {
					ev.SourceIP = addr.String()
				}
			case "port":
				if port, err := strconv.Atoi(v); err == nil {
					ev.Fields["source_port"] = port
				}
			case "method":
				ev.Fields["auth_method"] = v
			}
		}
		break
	}

	return ev, nil
}
