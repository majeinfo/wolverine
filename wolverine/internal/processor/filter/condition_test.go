package filter

import (
	"context"
	"strings"
	"testing"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/event"
)

func testLists(t *testing.T) map[string]*List {
	t.Helper()
	lists, err := BuildLists([]config.ExcludeList{
		{ID: "scanners", Entries: []string{"192.0.2.0/24"}},
		{ID: "admins", Entries: []string{"10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return lists
}

func TestCondition(t *testing.T) {
	lists := testLists(t)
	groups := []string{"source_ip", "method", "path", "user_agent", "status", "in", "bad-name"}
	ev := func(ip, ua string) *event.Event {
		e := &event.Event{
			Source: "nginx", SourceIP: ip, Status: "200", Hostname: "web1",
			Timestamp: time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC),
			Fields:    map[string]any{"method": "GET", "path": "/health", "source_port": 4242, "in": "x"},
		}
		if ua != "" {
			e.Fields["user_agent"] = ua
		}
		return e
	}
	tests := []struct {
		expr string
		ev   *event.Event
		want bool
	}{
		// The example of the README.
		{`in_list(source_ip, "scanners") || user_agent.matches("(?i)(curl|python-requests|bot)")`, ev("192.0.2.7", "Mozilla/5.0"), true},
		{`in_list(source_ip, "scanners") || user_agent.matches("(?i)(curl|python-requests|bot)")`, ev("203.0.113.1", "curl/8.5"), true},
		{`in_list(source_ip, "scanners") || user_agent.matches("(?i)(curl|python-requests|bot)")`, ev("203.0.113.1", "Mozilla/5.0"), false},
		// A group that did not match is "".
		{`user_agent == ""`, ev("203.0.113.1", ""), true},
		// Common fields, groups, extension functions.
		{`hostname == "web1" && status == "200" && path.startsWith("/health") && method in ["GET", "HEAD"]`, ev("", ""), true},
		{`source == "nginx" && user_agent.lowerAscii().contains("mozilla")`, ev("", "Mozilla/5.0"), true},
		// Other fields, through fields; non-string values keep their type.
		{`fields.source_port == 4242 && fields["in"] == "x"`, ev("", ""), true},
		{`has(fields.auth_method)`, ev("", ""), false},
		{`fields.?auth_method.orValue("none") == "none"`, ev("", ""), true},
		// A group that is not a valid name is only in fields.
		{`!("bad-name" in fields)`, ev("", ""), true},
		{`timestamp.getHours() < 6`, ev("", ""), true},
		{`in_list(source_ip, "admins")`, ev("not an IP", ""), false},
		{`in_list(source_ip, "admins")`, ev("::ffff:10.1.2.3", ""), true},
	}
	for _, tt := range tests {
		c, err := CompileCondition(tt.expr, groups, lists)
		if err != nil {
			t.Errorf("%s: %v", tt.expr, err)
			continue
		}
		got, err := c.Match(tt.ev)
		if err != nil || got != tt.want {
			t.Errorf("%s: got %v (%v), want %v", tt.expr, got, err, tt.want)
		}
	}

	// A missing key of fields is an error, reported by Match.
	c, err := CompileCondition(`fields.auth_method == "password"`, nil, lists)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Match(ev("", "")); err == nil || !strings.Contains(err.Error(), "auth_method") {
		t.Errorf("missing key: got %v", err)
	}
}

func TestCompileConditionErrors(t *testing.T) {
	lists := testLists(t)
	for expr, want := range map[string]string{
		`source_ip ==`:                 "Syntax error",
		`source_ip`:                    "must be true or false, not a string",
		`user_agent == "curl"`:         "undeclared reference to 'user_agent'",
		`status == 200`:                "no matching overload",
		`in_list(source_ip, "nope")`:   `unknown exclude list "nope"`,
		`in_list(source_ip, hostname)`: "given by its id in quotes",
		`in_list(source_ip)`:           "found no matching overload for 'in_list'",
		`message.matches("(")`:         "missing closing )",
	} {
		if _, err := CompileCondition(expr, nil, lists); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", expr, err, want)
		}
	}
}

func TestExcludeCondition(t *testing.T) {
	lists := testLists(t)
	c, err := CompileCondition(`in_list(source_ip, "scanners") || fields.user_agent.startsWith("curl")`, nil, lists)
	if err != nil {
		t.Fatal(err)
	}
	x := &Exclude{
		Sources:    map[string][]*List{"web": {lists["admins"]}},
		Conditions: map[string]*Condition{"web": c},
	}
	for _, tt := range []struct {
		ev      event.Event
		dropped bool
	}{
		{event.Event{Source: "web", SourceIP: "10.1.1.1"}, true}, // exclude
		{event.Event{Source: "web", SourceIP: "192.0.2.1"}, true},
		{event.Event{Source: "web", SourceIP: "203.0.113.1", Fields: map[string]any{"user_agent": "curl/8"}}, true},
		{event.Event{Source: "web", SourceIP: "203.0.113.1", Fields: map[string]any{"user_agent": "Mozilla"}}, false},
		// An error (no user_agent) keeps the event.
		{event.Event{Source: "web", SourceIP: "203.0.113.1"}, false},
		// The condition of a source only applies to it.
		{event.Event{Source: "ssh", SourceIP: "192.0.2.1"}, false},
	} {
		ev, err := x.Process(context.Background(), &tt.ev)
		if err != nil || (ev == nil) != tt.dropped {
			t.Errorf("%+v: dropped %v (%v), want %v", tt.ev, ev == nil, err, tt.dropped)
		}
	}
	if n := c.errors.Load(); n != 1 {
		t.Errorf("%d errors counted, want 1", n)
	}
}
