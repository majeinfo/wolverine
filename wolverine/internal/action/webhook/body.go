package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"wolverine/internal/event"
)

// Template variables. Strings are escaped for use inside a JSON string, so
// placeholders go between quotes: "text": "Alert from {{.SourceIP}}".
//
//	AlertID, RuleID, Severity, SeverityUpper, Message, Time (RFC 3339),
//	Value (the rule's group value), SourceIP, Username, Hostname (from the
//	last event), Count (number of events), Events (raw log lines, at most
//	max_events), MoreEvents (number of events left out).
var bodyVariables = []string{
	"AlertID", "RuleID", "Severity", "SeverityUpper", "Message", "Time",
	"Value", "SourceIP", "Username", "Hostname", "Count", "Events", "MoreEvents",
}

// Body renders a custom JSON request body from a text/template.
type Body struct {
	tmpl  *template.Template
	slack bool
}

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// ParseBody parses a body template. escape is "json" (default) or "slack":
// Slack also interprets &, < and > (links, @channel mentions), which are
// then escaped as well. The template is rendered with sample values to check
// that it only uses known variables and produces valid JSON.
func ParseBody(text, escape string) (*Body, error) {
	b := &Body{}
	switch escape {
	case "", "json":
	case "slack":
		b.slack = true
	default:
		return nil, fmt.Errorf("unknown escape %q (json or slack)", escape)
	}

	var err error
	b.tmpl, err = template.New("body").Option("missingkey=error").Parse(text)
	if err != nil {
		return nil, err
	}

	sample := &event.Alert{
		ID: "id", RuleID: "rule", Severity: "high", Message: `a "quoted" <message>`,
		Metadata: map[string]any{"value": "203.0.113.7"},
		Events:   []*event.Event{{Raw: `line with "quotes"`, SourceIP: "203.0.113.7"}, {Raw: "line 2"}},
	}
	out, err := b.Render(sample, 1)
	if err != nil {
		return nil, fmt.Errorf("%w (available: %s)", err, strings.Join(bodyVariables, ", "))
	}
	if !json.Valid(out) {
		return nil, fmt.Errorf("the body is not valid JSON once rendered (placeholders must be inside quotes):\n%s", out)
	}
	return b, nil
}

// Render expands the template for an alert, with at most maxEvents events
// (0 = all).
func (b *Body) Render(a *event.Alert, maxEvents int) ([]byte, error) {
	data := map[string]any{
		"AlertID":       b.escape(a.ID),
		"RuleID":        b.escape(a.RuleID),
		"Severity":      b.escape(a.Severity),
		"SeverityUpper": b.escape(strings.ToUpper(a.Severity)),
		"Message":       b.escape(a.Message),
		"Time":          b.escape(a.Timestamp.Format(time.RFC3339)),
		"Value":         "",
		"SourceIP":      "",
		"Username":      "",
		"Hostname":      "",
		"Count":         len(a.Events),
		"MoreEvents":    0,
	}
	if v, ok := a.Metadata["value"]; ok {
		data["Value"] = b.escape(fmt.Sprint(v))
	}
	if n := len(a.Events); n > 0 {
		last := a.Events[n-1]
		data["SourceIP"] = b.escape(last.SourceIP)
		data["Username"] = b.escape(last.Username)
		data["Hostname"] = b.escape(last.Hostname)
	}

	evs := a.Events
	if maxEvents > 0 && len(evs) > maxEvents {
		data["MoreEvents"] = len(evs) - maxEvents
		evs = evs[:maxEvents]
	}
	lines := make([]string, len(evs))
	for i, ev := range evs {
		line := ev.Raw
		if line == "" {
			line = ev.Message
		}
		lines[i] = b.escape(line)
	}
	data["Events"] = lines

	var out bytes.Buffer
	if err := b.tmpl.Execute(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// escape returns s encoded as the content of a JSON string (without the
// quotes), plus Slack's own escaping if enabled.
func (b *Body) escape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(s) // cannot fail for a string
	out := strings.TrimSuffix(buf.String(), "\n")
	out = out[1 : len(out)-1]
	if b.slack {
		out = slackEscaper.Replace(out)
	}
	return out
}
