package email

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"wolverine/internal/event"
)

// fakeSMTP accepts one connection, speaks just enough SMTP for net/smtp
// (without STARTTLS) and returns the commands and the DATA it received.
func fakeSMTP(t *testing.T) (port int, result <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- "accept: " + err.Error()
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		reply := func(s string) { conn.Write([]byte(s + "\r\n")) }

		var log strings.Builder
		reply("220 fake ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				ch <- log.String()
				return
			}
			cmd := strings.TrimRight(line, "\r\n")
			log.WriteString(cmd + "\n")
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				reply("250-fake")
				reply("250 8BITMIME")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				reply("250 ok")
			case cmd == "DATA":
				reply("354 go ahead")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					log.WriteString(l)
				}
				reply("250 queued")
			case cmd == "QUIT":
				reply("221 bye")
				ch <- log.String()
				return
			default:
				reply("502 unsupported")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

func testAlert() *event.Alert {
	return &event.Alert{
		ID:        "abc123",
		RuleID:    "ssh-failed-logins-per-ip",
		Timestamp: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC),
		Severity:  "high",
		Message:   "Repeated failed SSH logins: 5 events for SourceIP=203.0.113.7",
		Events: []*event.Event{
			{Raw: "Nov  8 10:00:00 h sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2"},
			{Raw: "Nov  8 10:00:01 h sshd[1]: Failed password for root from 203.0.113.7 port 2 ssh2"},
			{Raw: "."},
		},
		Metadata: map[string]any{"value": "203.0.113.7", "count": 5},
	}
}

func TestExecute(t *testing.T) {
	port, result := fakeSMTP(t)
	e := &Email{
		ID: "email-admin", Host: "127.0.0.1", Port: port,
		From: "wolverine@example.com", To: []string{"a@example.com", "b@example.com"},
		MaxEvents: 2, Timeout: 5 * time.Second,
	}
	if err := e.Execute(context.Background(), testAlert()); err != nil {
		t.Fatal(err)
	}
	got := <-result

	for _, want := range []string{
		"MAIL FROM:<wolverine@example.com>",
		"RCPT TO:<a@example.com>",
		"RCPT TO:<b@example.com>",
		"From: wolverine@example.com\r\n",
		"To: a@example.com, b@example.com\r\n",
		"Subject: [wolverine] [HIGH] Repeated failed SSH logins: 5 events for SourceIP=203.0.113.7\r\n",
		"Message-ID: <abc123@wolverine>\r\n",
		"Rule:     ssh-failed-logins-per-ip\r\n",
		"  count: 5\r\n  value: 203.0.113.7\r\n",
		"Events (3):\r\n  Nov  8 10:00:00 h sshd[1]",
		"  ... 1 more\r\n",
		"QUIT",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestMessageNoHeaderInjection(t *testing.T) {
	a := testAlert()
	a.Message = "evil\r\nBcc: victim@example.com"
	msg := string((&Email{From: "w@example.com", To: []string{"a@example.com"}}).message(a, time.Now()))
	headers, _, _ := strings.Cut(msg, "\n\n")
	if strings.Contains(headers, "\nBcc:") {
		t.Errorf("header injected:\n%s", headers)
	}
}

func TestExecuteConnectionError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	e := &Email{Host: "127.0.0.1", Port: port, From: "w@example.com", To: []string{"a@example.com"}}
	if err := e.Execute(context.Background(), testAlert()); err == nil {
		t.Fatal("expected an error")
	}
}
