package filter

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"wolverine/internal/config"
	"wolverine/internal/event"
)

func TestBuildLists(t *testing.T) {
	lists, err := BuildLists([]config.ExcludeList{
		// A list may name lists defined after it.
		{ID: "trusted", Entries: []string{"admins", "local", "192.168.1.77/24"}},
		{ID: "local", Entries: []string{"127.0.0.1/8", "::1", "::ffff:172.16.0.1"}},
		{ID: "admins", Entries: []string{"2001:db8::/32", "local"}},
		{ID: "empty"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{
		"local":   "[127.0.0.0/8 ::1/128 172.16.0.1/32]",
		"admins":  "[2001:db8::/32 127.0.0.0/8 ::1/128 172.16.0.1/32]",
		"trusted": "[2001:db8::/32 127.0.0.0/8 ::1/128 172.16.0.1/32 192.168.1.0/24]",
		"empty":   "[]",
	} {
		if got := fmt.Sprint(lists[id].Prefixes); got != want {
			t.Errorf("%s: got %s, want %s", id, got, want)
		}
	}
}

func TestBuildListsErrors(t *testing.T) {
	tests := []struct {
		name  string
		lists []config.ExcludeList
		want  string
	}{
		{"missing id", []config.ExcludeList{{Entries: []string{"10.0.0.1"}}}, "missing id"},
		{"duplicate", []config.ExcludeList{{ID: "a"}, {ID: "a"}}, "duplicate id"},
		{"address id", []config.ExcludeList{{ID: "10.0.0.0/8"}}, "must not be an IP address"},
		{"bad address", []config.ExcludeList{{ID: "a", Entries: []string{"10.0.0"}}}, `"10.0.0": not an IP address or a CIDR range, nor the id of an exclude list`},
		{"bad prefix", []config.ExcludeList{{ID: "a", Entries: []string{"10.0.0.0/33"}}}, "10.0.0.0/33"},
		{"mapped prefix", []config.ExcludeList{{ID: "a", Entries: []string{"::ffff:10.0.0.0/104"}}}, "IPv4 form"},
		{"unknown list", []config.ExcludeList{{ID: "a", Entries: []string{"nope"}}}, `"nope"`},
		{"field spaces", []config.ExcludeList{{ID: "a", Field: " DestIP"}}, "unexpected spaces"},
		{"self", []config.ExcludeList{{ID: "a", Entries: []string{"a"}}}, "a -> a"},
		{"cycle", []config.ExcludeList{
			{ID: "a", Entries: []string{"10.0.0.1", "b"}},
			{ID: "b", Entries: []string{"c"}},
			{ID: "c", Entries: []string{"a"}},
		}, "a -> b -> c -> a"},
	}
	for _, tt := range tests {
		if _, err := BuildLists(tt.lists); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.name, err, tt.want)
		}
	}
}

func TestExclude(t *testing.T) {
	lists, err := BuildLists([]config.ExcludeList{
		{ID: "local", Entries: []string{"10.0.0.0/8"}},
		{ID: "admins", Entries: []string{"2001:db8::1", "local"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	x := &Exclude{Lists: []*List{lists["local"], lists["admins"]}}
	for ip, want := range map[string]string{
		"10.1.2.3":        "local,admins",
		"::ffff:10.1.2.3": "local,admins",
		"2001:db8::1":     "admins",
		"2001:db8::2":     "",
		"203.0.113.7":     "",
		"":                "",
		"not an address":  "",
	} {
		ev, err := x.Process(context.Background(), &event.Event{SourceIP: ip})
		if err != nil || ev == nil {
			t.Fatalf("%q: %v %v", ip, ev, err)
		}
		if got := strings.Join(ev.ExcludedBy, ","); got != want {
			t.Errorf("%q: excluded by %q, want %q", ip, got, want)
		}
	}

	if !lists["admins"].Contains(netip.MustParseAddr("10.9.9.9")) {
		t.Error("admins includes local")
	}
}

func TestExcludeField(t *testing.T) {
	lists, err := BuildLists([]config.ExcludeList{
		{ID: "lan", Entries: []string{"10.0.0.0/8"}},
		// The included list's addresses are checked against this list's
		// field.
		{ID: "lan-dest", Field: "DestIP", Entries: []string{"lan"}},
		{ID: "proxied", Field: "client_ip", Entries: []string{"192.0.2.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if lists["lan"].Field != "SourceIP" || lists["lan-dest"].Field != "DestIP" {
		t.Fatalf("fields %q %q", lists["lan"].Field, lists["lan-dest"].Field)
	}
	x := &Exclude{Lists: []*List{lists["lan"], lists["lan-dest"], lists["proxied"]}}
	for _, tt := range []struct {
		ev   event.Event
		want string
	}{
		{event.Event{SourceIP: "10.1.1.1", DestIP: "203.0.113.1"}, "lan"},
		{event.Event{SourceIP: "203.0.113.1", DestIP: "10.1.1.1"}, "lan-dest"},
		{event.Event{SourceIP: "10.1.1.1", DestIP: "10.2.2.2"}, "lan,lan-dest"},
		{event.Event{SourceIP: "203.0.113.1", Fields: map[string]any{"client_ip": "192.0.2.7"}}, "proxied"},
		{event.Event{Fields: map[string]any{"client_ip": "10.1.1.1"}}, ""},
		{event.Event{Fields: map[string]any{"client_ip": 42}}, ""},
	} {
		ev, _ := x.Process(context.Background(), &tt.ev)
		if got := strings.Join(ev.ExcludedBy, ","); got != tt.want {
			t.Errorf("%+v: excluded by %q, want %q", tt.ev, got, tt.want)
		}
	}
}

func TestExcludeSource(t *testing.T) {
	lists, err := BuildLists([]config.ExcludeList{
		{ID: "scanners", Entries: []string{"192.0.2.0/24"}},
		{ID: "lan-dest", Field: "DestIP", Entries: []string{"10.0.0.0/8"}},
		{ID: "admins", Entries: []string{"192.0.2.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	x := &Exclude{
		Sources: map[string][]*List{"web": {lists["scanners"], lists["lan-dest"]}},
		Lists:   []*List{lists["admins"]},
	}
	for _, tt := range []struct {
		ev   event.Event
		want string // "dropped", or the lists recorded
	}{
		{event.Event{Source: "web", SourceIP: "192.0.2.1"}, "dropped"},
		{event.Event{Source: "web", SourceIP: "203.0.113.1", DestIP: "10.1.1.1"}, "dropped"},
		{event.Event{Source: "web", SourceIP: "203.0.113.1"}, ""},
		// The lists of a source only apply to it.
		{event.Event{Source: "ssh", SourceIP: "192.0.2.1"}, "admins"},
	} {
		ev, err := x.Process(context.Background(), &tt.ev)
		got := "dropped"
		if ev != nil {
			got = strings.Join(ev.ExcludedBy, ",")
		}
		if err != nil || got != tt.want {
			t.Errorf("%+v: got %q (%v), want %q", tt.ev, got, err, tt.want)
		}
	}
}
