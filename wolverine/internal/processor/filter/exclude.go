// Package filter holds the exclude lists: named sets of IP addresses and
// CIDR ranges that rules ignore. A list may include other lists by name.
//
// Each list checks one event field (default SourceIP). The Exclude
// processor runs after parsing and enrichment: it records in each event the
// lists whose field holds an address of the list (Event.ExcludedBy). Each
// rule then skips the events excluded by one of its own lists.
package filter

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"wolverine/internal/config"
	"wolverine/internal/detection"
	"wolverine/internal/event"
	"wolverine/internal/verbose"
)

// DefaultField is the event field a list checks when it does not set one.
const DefaultField = "SourceIP"

// List is an exclude list, with the lists it includes resolved.
type List struct {
	ID string
	// Field is the event field checked (see detection.FieldValue).
	Field    string
	Prefixes []netip.Prefix
}

// Contains reports whether addr is in the list.
func (l *List) Contains(addr netip.Addr) bool {
	addr = addr.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
	for _, p := range l.Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// BuildLists resolves the exclude lists of the configuration. An entry is an
// IP address ("10.0.0.1", "2001:db8::1"), a CIDR range ("10.0.0.0/8") or the
// id of another list, whose addresses are added: they are checked against
// the field of the including list, not that of the included one.
func BuildLists(cfgs []config.ExcludeList) (map[string]*List, error) {
	defs := map[string]config.ExcludeList{}
	for i, c := range cfgs {
		if c.ID == "" {
			return nil, fmt.Errorf("exclude list #%d: missing id", i+1)
		}
		if _, err := parseAddress(c.ID); err == nil {
			return nil, fmt.Errorf("exclude list %q: the id must not be an IP address", c.ID)
		}
		if _, dup := defs[c.ID]; dup {
			return nil, fmt.Errorf("exclude list %q: duplicate id", c.ID)
		}
		if strings.TrimSpace(c.Field) != c.Field {
			return nil, fmt.Errorf("exclude list %q: field %q: unexpected spaces", c.ID, c.Field)
		}
		defs[c.ID] = c
	}

	lists := map[string]*List{}
	var resolve func(id string, path []string) (*List, error)
	resolve = func(id string, path []string) (*List, error) {
		if l, ok := lists[id]; ok {
			return l, nil
		}
		if i := slices.Index(path, id); i >= 0 {
			return nil, fmt.Errorf("exclude list %q: includes itself: %s", id, strings.Join(append(path[i:], id), " -> "))
		}
		path = append(path, id)
		l := &List{ID: id, Field: defs[id].Field}
		if l.Field == "" {
			l.Field = DefaultField
		}
		seen := map[netip.Prefix]bool{}
		add := func(p netip.Prefix) {
			if !seen[p] {
				seen[p] = true
				l.Prefixes = append(l.Prefixes, p)
			}
		}
		for _, e := range defs[id].Entries {
			if p, err := parseAddress(e); err == nil {
				add(p)
				continue
			} else if _, isList := defs[e]; !isList {
				return nil, fmt.Errorf("exclude list %q: %q: %v, nor the id of an exclude list", id, e, err)
			}
			sub, err := resolve(e, path)
			if err != nil {
				return nil, err
			}
			for _, p := range sub.Prefixes {
				add(p)
			}
		}
		lists[id] = l
		return l, nil
	}
	for _, c := range cfgs {
		if _, err := resolve(c.ID, nil); err != nil {
			return nil, err
		}
	}
	return lists, nil
}

// parseAddress parses an IP address or a CIDR range.
func parseAddress(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("use the IPv4 form")
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an IP address or a CIDR range")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Exclude records in each event the lists whose field holds one of their
// addresses.
type Exclude struct {
	// Lists are the lists to check: those the rules use.
	Lists []*List
}

func (*Exclude) Name() string { return "exclude" }

func (x *Exclude) Process(_ context.Context, ev *event.Event) (*event.Event, error) {
	if len(x.Lists) == 0 {
		return ev, nil
	}
	// Most lists check the same field: parse each field once.
	addrs := map[string]netip.Addr{}
	for _, l := range x.Lists {
		addr, seen := addrs[l.Field]
		if !seen {
			addr, _ = netip.ParseAddr(detection.FieldValue(ev, l.Field)) // invalid if not an address
			addrs[l.Field] = addr
		}
		if addr.IsValid() && l.Contains(addr) {
			ev.ExcludedBy = append(ev.ExcludedBy, l.ID)
			verbose.Debugf("event from %s: %s %s is in exclude list %s", ev.Source, l.Field, addr, l.ID)
		}
	}
	return ev, nil
}
