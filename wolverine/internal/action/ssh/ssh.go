// Package ssh runs a command on a remote host over SSH when an alert fires,
// e.g. to block an IP address on a firewall.
package ssh

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
	"time"

	"wolverine/internal/event"
)

const (
	defaultTimeout = 30 * time.Second
	maxOutput      = 1024
)

// Variables usable in the command template.
var Variables = []string{"AlertID", "RuleID", "Severity", "Value", "SourceIP", "Username", "Hostname"}

// SSH runs Command on Host with the system ssh client, so that the usual
// keys, ssh_config and known_hosts apply. BatchMode is forced: ssh fails
// instead of prompting for a password or an unknown host key.
//
// Command is a text/template. Every value is shell-quoted before being
// inserted, because it comes from log content that an attacker controls:
// placeholders must therefore be used outside of quotes, e.g.
//
//	ipset add blocklist {{.SourceIP}} -exist
//
// A placeholder whose value is empty for an alert makes the action fail
// rather than run the command with an empty argument.
type SSH struct {
	ID           string
	Host         string
	Port         int
	User         string
	IdentityFile string
	Command      *template.Template
	Timeout      time.Duration
	// Binary is the ssh client to run (default "ssh").
	Binary string
}

// ParseCommand parses a command template and checks that it only uses
// known variables.
func ParseCommand(text string) (*template.Template, error) {
	t, err := template.New("command").Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, err
	}
	sample := map[string]string{}
	for _, v := range Variables {
		sample[v] = "x"
	}
	if err := t.Execute(&bytes.Buffer{}, sample); err != nil {
		return nil, fmt.Errorf("%w (available: %s)", err, strings.Join(Variables, ", "))
	}
	return t, nil
}

func (s *SSH) Name() string { return s.ID }

func (s *SSH) Execute(ctx context.Context, alert *event.Alert) error {
	cmd, err := s.render(alert)
	if err != nil {
		return err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, s.binary(), s.args(cmd)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s on %s: %w: %s", cmd, s.Host, err, truncate(out))
	}
	log.Printf("action %s: ran %s on %s for alert %s", s.ID, cmd, s.Host, alert.ID)
	return nil
}

func (s *SSH) binary() string {
	if s.Binary != "" {
		return s.Binary
	}
	return "ssh"
}

func (s *SSH) args(cmd string) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	if s.Port != 0 {
		args = append(args, "-p", strconv.Itoa(s.Port))
	}
	if s.User != "" {
		args = append(args, "-l", s.User)
	}
	if s.IdentityFile != "" {
		args = append(args, "-i", s.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	return append(args, "--", s.Host, cmd)
}

// render expands the command template with the alert's values, each one
// shell-quoted. Empty values are left out so that using them is an error.
func (s *SSH) render(a *event.Alert) (string, error) {
	vars := map[string]string{
		"AlertID":  a.ID,
		"RuleID":   a.RuleID,
		"Severity": a.Severity,
	}
	if v, ok := a.Metadata["value"]; ok {
		vars["Value"] = fmt.Sprint(v)
	}
	if n := len(a.Events); n > 0 {
		ev := a.Events[n-1]
		vars["SourceIP"] = ev.SourceIP
		vars["Username"] = ev.Username
		vars["Hostname"] = ev.Hostname
	}
	for k, v := range vars {
		if v == "" {
			delete(vars, k)
		} else {
			vars[k] = shellQuote(v)
		}
	}

	var b strings.Builder
	if err := s.Command.Execute(&b, vars); err != nil {
		return "", fmt.Errorf("command: %w", err)
	}
	return b.String(), nil
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncate(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > maxOutput {
		s = s[:maxOutput] + "..."
	}
	return s
}
