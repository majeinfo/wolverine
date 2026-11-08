package allowlist

import (
	"fmt"
	"testing"

	"wolverine/internal/event"
)

func TestParse(t *testing.T) {
	got, err := Parse([]string{"10.0.0.1", "192.168.1.77/24", "2001:db8::/32", "::ffff:172.16.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	want := "[10.0.0.1/32 192.168.1.0/24 2001:db8::/32 172.16.0.1/32]"
	if s := fmt.Sprint(got); s != want {
		t.Errorf("got %s, want %s", s, want)
	}

	for _, bad := range []string{"10.0.0", "example.com", "10.0.0.0/33", "::ffff:10.0.0.0/104"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestMatch(t *testing.T) {
	l, err := Parse([]string{"10.0.0.0/8", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	alert := func(ip string) *event.Alert {
		return &event.Alert{Events: []*event.Event{{SourceIP: ip}}, Metadata: map[string]any{}}
	}

	for ip, want := range map[string]bool{
		"10.1.2.3":        true,
		"::ffff:10.1.2.3": true,
		"2001:db8::1":     true,
		"2001:db8::2":     false,
		"203.0.113.7":     false,
		"":                false,
	} {
		if _, got := l.Match(alert(ip)); got != want {
			t.Errorf("%q: got %v, want %v", ip, got, want)
		}
	}

	// The group value is checked too.
	a := alert("")
	a.Metadata["value"] = "10.9.9.9"
	if ip, ok := l.Match(a); !ok || ip.String() != "10.9.9.9" {
		t.Errorf("group value not checked: %v %v", ip, ok)
	}

	if _, ok := List(nil).Match(alert("10.1.2.3")); ok {
		t.Error("an empty list matches nothing")
	}
}
