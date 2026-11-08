// Package allowlist holds the IP addresses that blocking actions must never
// act on.
package allowlist

import (
	"fmt"
	"net/netip"

	"wolverine/internal/event"
)

type List []netip.Prefix

// Parse parses IP addresses ("10.0.0.1", "2001:db8::1") and CIDR ranges
// ("10.0.0.0/8").
func Parse(entries []string) (List, error) {
	l := make(List, 0, len(entries))
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			if p.Addr().Is4In6() {
				return nil, fmt.Errorf("allowlist: %q: use the IPv4 form", e)
			}
			l = append(l, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("allowlist: %q is not an IP address or a CIDR range", e)
		}
		addr = addr.Unmap()
		l = append(l, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return l, nil
}

// Match reports whether one of the alert's IP addresses (the source IP of its
// events, or its group value) is in the list, and returns it.
func (l List) Match(a *event.Alert) (netip.Addr, bool) {
	if len(l) == 0 {
		return netip.Addr{}, false
	}
	candidates := make([]string, 0, len(a.Events)+1)
	for _, ev := range a.Events {
		candidates = append(candidates, ev.SourceIP)
	}
	if v, ok := a.Metadata["value"]; ok {
		candidates = append(candidates, fmt.Sprint(v))
	}
	for _, c := range candidates {
		addr, err := netip.ParseAddr(c)
		if err != nil {
			continue
		}
		addr = addr.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
		for _, p := range l {
			if p.Contains(addr) {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}
