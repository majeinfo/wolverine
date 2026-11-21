package awswaf

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"wolverine/internal/event"
)

// fakeWAF holds IP sets in memory, by id, with a lock token that changes on
// every update, like AWS WAF.
type fakeWAF struct {
	mu      sync.Mutex
	sets    map[string]*types.IPSet
	tokens  map[string]int
	lists   int // ListIPSets calls
	updates int
	// conflicts makes the next updates fail as if the set changed.
	conflicts int
}

func newFake() *fakeWAF {
	f := &fakeWAF{sets: map[string]*types.IPSet{}, tokens: map[string]int{}}
	f.sets["id-v4"] = &types.IPSet{Id: aws.String("id-v4"), Name: aws.String("blocklist"), Description: aws.String("by wolverine"),
		IPAddressVersion: types.IPAddressVersionIpv4, Addresses: []string{"198.51.100.0/24"}}
	// AWS returns an empty description for an IP set without one.
	f.sets["id-v6"] = &types.IPSet{Id: aws.String("id-v6"), Name: aws.String("blocklist6"), Description: aws.String(""),
		IPAddressVersion: types.IPAddressVersionIpv6, Addresses: []string{}}
	return f
}

func (f *fakeWAF) ListIPSets(_ context.Context, in *wafv2.ListIPSetsInput, _ ...func(*wafv2.Options)) (*wafv2.ListIPSetsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	// One set per page, to exercise the pagination.
	switch aws.ToString(in.NextMarker) {
	case "":
		return &wafv2.ListIPSetsOutput{IPSets: []types.IPSetSummary{{Name: aws.String("other"), Id: aws.String("id-other")}}, NextMarker: aws.String("p2")}, nil
	case "p2":
		return &wafv2.ListIPSetsOutput{IPSets: []types.IPSetSummary{{Name: aws.String("blocklist6"), Id: aws.String("id-v6")}}, NextMarker: aws.String("p3")}, nil
	default:
		return &wafv2.ListIPSetsOutput{IPSets: []types.IPSetSummary{{Name: aws.String("blocklist"), Id: aws.String("id-v4")}}}, nil
	}
}

func (f *fakeWAF) GetIPSet(_ context.Context, in *wafv2.GetIPSetInput, _ ...func(*wafv2.Options)) (*wafv2.GetIPSetOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sets[aws.ToString(in.Id)]
	if !ok || aws.ToString(s.Name) != aws.ToString(in.Name) {
		return nil, &types.WAFNonexistentItemException{Message: aws.String("not found")}
	}
	c := *s
	c.Addresses = append([]string(nil), s.Addresses...)
	return &wafv2.GetIPSetOutput{IPSet: &c, LockToken: aws.String(token(f.tokens[*s.Id]))}, nil
}

func token(n int) string { return strings.Repeat("t", n+1) }

func (f *fakeWAF) UpdateIPSet(_ context.Context, in *wafv2.UpdateIPSetInput, _ ...func(*wafv2.Options)) (*wafv2.UpdateIPSetOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := aws.ToString(in.Id)
	if f.conflicts > 0 {
		f.conflicts--
		f.tokens[id]++ // someone else updated it
	}
	if in.Description != nil && *in.Description == "" {
		return nil, &types.WAFInvalidParameterException{Message: aws.String("Value '' at 'description' failed to satisfy constraint")}
	}
	if aws.ToString(in.LockToken) != token(f.tokens[id]) {
		return nil, &types.WAFOptimisticLockException{Message: aws.String("stale")}
	}
	f.updates++
	f.tokens[id]++
	s := f.sets[id]
	s.Addresses = in.Addresses
	s.Description = in.Description
	if s.Description == nil {
		s.Description = aws.String("")
	}
	return &wafv2.UpdateIPSetOutput{}, nil
}

func (f *fakeWAF) addresses(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.sets[id].Addresses, ",")
}

func alert(ip string) *event.Alert {
	return &event.Alert{ID: "a1", Events: []*event.Event{{SourceIP: "192.0.2.99"}, {SourceIP: ip, Fields: map[string]any{"client_ip": "203.0.113.5"}}}}
}

func TestAddRemove(t *testing.T) {
	f := newFake()
	block := New("block", f, "blocklist", "", types.ScopeRegional, "SourceIP", false, 0)
	unblock := New("unblock", f, "blocklist", "id-v4", types.ScopeRegional, "SourceIP", true, 0)
	ctx := context.Background()

	// The address of the last event, looked up by name (3 pages).
	if err := block.Execute(ctx, alert("192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	if got := f.addresses("id-v4"); got != "198.51.100.0/24,192.0.2.7/32" {
		t.Errorf("after add: %s", got)
	}
	if f.lists != 3 || aws.ToString(f.sets["id-v4"].Description) != "by wolverine" {
		t.Errorf("%d list calls, description %q", f.lists, aws.ToString(f.sets["id-v4"].Description))
	}
	// Already there: no update. The id is not looked up again.
	f.updates = 0
	if err := block.Execute(ctx, alert("::ffff:192.0.2.7")); err != nil || f.updates != 0 || f.lists != 3 {
		t.Errorf("add again: %v, %d updates, %d list calls", err, f.updates, f.lists)
	}

	if err := unblock.Execute(ctx, alert("192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	if got := f.addresses("id-v4"); got != "198.51.100.0/24" {
		t.Errorf("after remove: %s", got)
	}
	// Not there: nothing to do. An address inside a range of the set is
	// not removed either: only that exact address is.
	f.updates = 0
	if err := unblock.Execute(ctx, alert("198.51.100.1")); err != nil || f.updates != 0 || f.addresses("id-v4") != "198.51.100.0/24" {
		t.Errorf("remove absent: %v, %d updates", err, f.updates)
	}

	// IPv6, in an IPv6 set.
	block6 := New("block6", f, "blocklist6", "id-v6", types.ScopeRegional, "SourceIP", false, 0)
	if err := block6.Execute(ctx, alert("2001:DB8::1")); err != nil || f.addresses("id-v6") != "2001:db8::1/128" {
		t.Errorf("IPv6: %v, %s", err, f.addresses("id-v6"))
	}

	// Another field.
	byField := New("proxied", f, "blocklist", "id-v4", types.ScopeRegional, "client_ip", false, 0)
	if err := byField.Execute(ctx, alert("192.0.2.8")); err != nil || !strings.HasSuffix(f.addresses("id-v4"), "203.0.113.5/32") {
		t.Errorf("client_ip: %v, %s", err, f.addresses("id-v4"))
	}
}

// With an IPv6 IP set, each address goes to the IP set of its version.
func TestIPv4AndIPv6Sets(t *testing.T) {
	f := newFake()
	ctx := context.Background()
	block := New("block", f, "blocklist", "", types.ScopeRegional, "SourceIP", false, 0).WithIPv6("blocklist6", "")
	unblock := New("unblock", f, "blocklist", "id-v4", types.ScopeRegional, "SourceIP", true, 0).WithIPv6("blocklist6", "id-v6")

	if err := block.Execute(ctx, alert("2001:db8::7")); err != nil {
		t.Fatal(err)
	}
	if err := block.Execute(ctx, alert("192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	if f.addresses("id-v6") != "2001:db8::7/128" || f.addresses("id-v4") != "198.51.100.0/24,192.0.2.7/32" {
		t.Errorf("after add: v6 %s, v4 %s", f.addresses("id-v6"), f.addresses("id-v4"))
	}
	// Each id is looked up once (the list has 3 pages, v6 on the second).
	lists := f.lists
	block.Execute(ctx, alert("2001:db8::8"))
	block.Execute(ctx, alert("192.0.2.8"))
	if f.lists != lists {
		t.Errorf("looked up again: %d list calls, then %d", lists, f.lists)
	}
	// An IPv4-mapped IPv6 address is an IPv4 one.
	if err := unblock.Execute(ctx, alert("::ffff:192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	if err := unblock.Execute(ctx, alert("2001:DB8::7")); err != nil {
		t.Fatal(err)
	}
	if f.addresses("id-v6") != "2001:db8::8/128" || f.addresses("id-v4") != "198.51.100.0/24,192.0.2.8/32" {
		t.Errorf("after remove: v6 %s, v4 %s", f.addresses("id-v6"), f.addresses("id-v4"))
	}

	// The IP sets swapped: the error says what to fix.
	swapped := New("block", f, "blocklist6", "id-v6", types.ScopeRegional, "SourceIP", false, 0).WithIPv6("blocklist", "id-v4")
	if err := swapped.Execute(ctx, alert("2001:db8::9")); err == nil || !strings.Contains(err.Error(), "ipset.ipv6_name must be an IPv6 IP set") {
		t.Errorf("swapped, IPv6: %v", err)
	}
	if err := swapped.Execute(ctx, alert("192.0.2.9")); err == nil || !strings.Contains(err.Error(), "ipset.name must be an IPv4 IP set") {
		t.Errorf("swapped, IPv4: %v", err)
	}
}

func TestConflicts(t *testing.T) {
	f := newFake()
	block := New("block", f, "blocklist", "id-v4", types.ScopeRegional, "SourceIP", false, 0)
	// The set changes meanwhile: read again and retry.
	f.conflicts = maxAttempts - 1
	if err := block.Execute(context.Background(), alert("192.0.2.7")); err != nil || !strings.Contains(f.addresses("id-v4"), "192.0.2.7/32") {
		t.Fatalf("after %d conflicts: %v", maxAttempts-1, err)
	}
	// Given up after maxAttempts.
	f.conflicts = maxAttempts
	err := block.Execute(context.Background(), alert("192.0.2.8"))
	var lock *types.WAFOptimisticLockException
	if !errors.As(err, &lock) {
		t.Errorf("after %d conflicts: %v", maxAttempts, err)
	}
}

func TestErrors(t *testing.T) {
	f := newFake()
	full := newFake()
	for i := 0; i < maxAddresses; i++ {
		full.sets["id-v4"].Addresses = append(full.sets["id-v4"].Addresses, "x")
	}
	for _, tt := range []struct {
		name  string
		f     *fakeWAF
		set   string
		id    string
		alert *event.Alert
		want  string
	}{
		{"no event", f, "blocklist", "id-v4", &event.Alert{}, "no event"},
		{"no address", f, "blocklist", "id-v4", alert(""), "SourceIP: no address"},
		{"not an address", f, "blocklist", "id-v4", alert("nope; rm -rf /"), "not an IP address"},
		{"IPv6 in an IPv4 set", f, "blocklist", "id-v4", alert("2001:db8::1"), "does not fit in an IPV4 IP set: give an IPv6 IP set for them in ipset.ipv6_name"},
		{"IPv4 in an IPv6 set", f, "blocklist6", "id-v6", alert("192.0.2.1"), "does not fit in an IPV6 IP set"},
		{"unknown name", f, "nope", "", alert("192.0.2.1"), "no IP set of this name"},
		{"wrong id", f, "blocklist", "id-v6", alert("192.0.2.1"), "not found"},
		{"full", full, "blocklist", "id-v4", alert("192.0.2.1"), "full"},
	} {
		a := New("block", tt.f, tt.set, tt.id, types.ScopeRegional, "SourceIP", false, 0)
		if err := a.Execute(context.Background(), tt.alert); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want %q", tt.name, err, tt.want)
		}
	}
}
