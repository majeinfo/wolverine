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
