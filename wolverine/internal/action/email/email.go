// Package email sends alerts by email over SMTP.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"wolverine/internal/event"
)

const defaultTimeout = 30 * time.Second

// Email is an action that mails the alert to a list of recipients.
//
// STARTTLS is used whenever the server offers it. Authentication (PLAIN) is
// done when Username is set; net/smtp refuses to send the password over an
// unencrypted connection unless the server is localhost.
type Email struct {
	ID       string
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	Timeout  time.Duration
	// MaxEvents limits the number of log lines included in the body.
	MaxEvents int
}

func (e *Email) Name() string { return e.ID }

func (e *Email) Execute(ctx context.Context, alert *event.Alert) error {
	return e.send(ctx, e.message(alert, time.Now()))
}

func (e *Email) send(ctx context.Context, msg []byte) error {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(e.Host, strconv.Itoa(e.Port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		return err
	}
	defer c.Close()

	if name, err := os.Hostname(); err == nil {
		if err := c.Hello(name); err != nil {
			return fmt.Errorf("ehlo: %w", err)
		}
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: e.Host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(e.From); err != nil {
		return fmt.Errorf("mail from %s: %w", e.From, err)
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("rcpt to %s: %w", to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("data: %w", err)
	}
	return c.Quit()
}

// message builds the mail. Lines end with "\n": the SMTP data writer turns
// them into CRLF and escapes lines starting with a dot.
func (e *Email) message(a *event.Alert, now time.Time) []byte {
	var b bytes.Buffer

	subject := fmt.Sprintf("[wolverine] [%s] %s", strings.ToUpper(a.Severity), a.Message)
	fmt.Fprintf(&b, "From: %s\n", e.From)
	fmt.Fprintf(&b, "To: %s\n", strings.Join(e.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\n", mime.QEncoding.Encode("utf-8", oneLine(subject)))
	fmt.Fprintf(&b, "Date: %s\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@wolverine>\n", a.ID)
	b.WriteString("MIME-Version: 1.0\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\n")
	b.WriteString("\n")

	fmt.Fprintf(&b, "Rule:     %s\n", a.RuleID)
	fmt.Fprintf(&b, "Severity: %s\n", a.Severity)
	fmt.Fprintf(&b, "Time:     %s\n", a.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Message:  %s\n", oneLine(a.Message))

	if len(a.Metadata) > 0 {
		b.WriteString("\nDetails:\n")
		keys := make([]string, 0, len(a.Metadata))
		for k := range a.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %s\n", k, oneLine(fmt.Sprint(a.Metadata[k])))
		}
	}

	if len(a.Events) > 0 {
		if n := a.Count(); n > len(a.Events) {
			fmt.Fprintf(&b, "\nEvents (%d, the last %d kept):\n", n, len(a.Events))
		} else {
			fmt.Fprintf(&b, "\nEvents (%d):\n", len(a.Events))
		}
		for i, ev := range a.Events {
			if e.MaxEvents > 0 && i == e.MaxEvents {
				fmt.Fprintf(&b, "  ... %d more\n", len(a.Events)-i)
				break
			}
			line := ev.Raw
			if line == "" {
				line = ev.Message
			}
			fmt.Fprintf(&b, "  %s\n", oneLine(line))
		}
	}
	return b.Bytes()
}

// oneLine strips line breaks, which could otherwise inject mail headers or
// break the body layout (log content is attacker-controlled).
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}
