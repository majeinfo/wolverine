package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"wolverine/internal/event"
)

const slackTemplate = `{
  "text": ":rotating_light: *[{{.SeverityUpper}}] {{.Message}}*\nRule: ` + "`{{.RuleID}}`" + ` on {{.Hostname}}\n` +
	"```{{range .Events}}{{.}}\\n{{end}}{{if .MoreEvents}}... {{.MoreEvents}} more{{end}}```" + `"
}`

func bodyAlert(user string) *event.Alert {
	return &event.Alert{
		ID: "a1", RuleID: "ssh-failed-logins-per-ip", Severity: "high",
		Timestamp: time.Date(2026, 11, 8, 10, 5, 0, 0, time.UTC),
		Message:   "Repeated failed SSH logins: SourceIP=203.0.113.7",
		Metadata:  map[string]any{"value": "203.0.113.7"},
		Events: []*event.Event{
			{Raw: "Failed password for root from 203.0.113.7", Hostname: "web01"},
			{Raw: "Failed password for " + user + " from 203.0.113.7", Hostname: "web01", Username: user, SourceIP: "203.0.113.7"},
			{Raw: "Failed password for admin from 203.0.113.7", Hostname: "web01", SourceIP: "203.0.113.7"},
		},
	}
}

func render(t *testing.T, tmpl, escape string, a *event.Alert, maxEvents int) map[string]any {
	t.Helper()
	b, err := ParseBody(tmpl, escape)
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.Render(a, maxEvents)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return m
}

func TestSlackBody(t *testing.T) {
	m := render(t, slackTemplate, "slack", bodyAlert("jd"), 2)
	want := ":rotating_light: *[HIGH] Repeated failed SSH logins: SourceIP=203.0.113.7*\n" +
		"Rule: `ssh-failed-logins-per-ip` on web01\n" +
		"```Failed password for root from 203.0.113.7\nFailed password for jd from 203.0.113.7\n... 1 more```"
	if m["text"] != want {
		t.Errorf("got:\n%s\nwant:\n%s", m["text"], want)
	}
}

// Log content must not be able to break the JSON nor trigger Slack mentions.
func TestBodyEscaping(t *testing.T) {
	evil := `x", "channel": "#general", "y": "<!channel> & \ ` + "\n"
	a := bodyAlert("u")
	a.Message = evil

	m := render(t, `{"text": "{{.Message}}"}`, "slack", a, 0)
	if len(m) != 1 {
		t.Fatalf("keys injected: %v", m)
	}
	if got := m["text"].(string); strings.Contains(got, "<!channel>") || !strings.Contains(got, "&lt;!channel&gt; &amp;") {
		t.Errorf("slack escaping missing: %q", got)
	}

	m = render(t, `{"text": "{{.Message}}"}`, "json", a, 0)
	if len(m) != 1 || m["text"] != evil {
		t.Errorf("json escaping: got %v", m)
	}
}

func TestParseBodyErrors(t *testing.T) {
	for tmpl, want := range map[string]string{
		`{"text": "{{.SourceIP"}`: "template: body",
		`{"text": "{{.Nope}}"}`:   "available:",
		`{"text": {{.Message}}}`:  "not valid JSON",
		`{"count": {{.Count}}}`:   "",
		`{"text": "{{.Message}}"`: "not valid JSON",
	} {
		_, err := ParseBody(tmpl, "")
		if want == "" {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tmpl, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", tmpl, err, want)
		}
	}
}

func TestExecuteWithBody(t *testing.T) {
	srv, _, _, bodies := server(t, 200)
	b, err := ParseBody(`{"text": "{{.RuleID}} {{.SourceIP}}"}`, "slack")
	if err != nil {
		t.Fatal(err)
	}
	w := &Webhook{URL: srv.URL, Body: b}
	if err := w.Execute(context.Background(), bodyAlert("jd")); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(<-bodies, &m)
	if m["text"] != "ssh-failed-logins-per-ip 203.0.113.7" {
		t.Errorf("got %v", m)
	}
}

// The URL path of Slack/Teams webhooks is a secret: errors must not show it.
func TestErrorsRedactURL(t *testing.T) {
	srv, _, _, _ := server(t, 404)
	w := &Webhook{URL: srv.URL + "/services/T000/B000/SECRET"}
	err := w.Execute(context.Background(), bodyAlert("jd"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("got %v, want an error without the URL path", err)
	}

	w = &Webhook{URL: "http://127.0.0.1:1/services/T000/B000/SECRET", Timeout: time.Second}
	err = w.Execute(context.Background(), bodyAlert("jd"))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("got %v, want a connection error without the URL path", err)
	}
}
