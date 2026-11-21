// Package awswaf adds an address of an alert to an AWS WAF (v2) IP set, or
// removes it, e.g. to block the source of an attack in front of a load
// balancer or a CloudFront distribution, and to unblock it later (undo).
package awswaf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"wolverine/internal/detection"
	"wolverine/internal/event"
)

const (
	defaultTimeout = 30 * time.Second
	// maxAttempts is how many times an update is tried when the IP set
	// changed meanwhile (another wolverine action, the console...).
	maxAttempts = 5
	// maxAddresses is the number of addresses of an IP set in AWS WAF.
	maxAddresses = 10000
)

// API is the part of the WAF client used: *wafv2.Client.
type API interface {
	ListIPSets(context.Context, *wafv2.ListIPSetsInput, ...func(*wafv2.Options)) (*wafv2.ListIPSetsOutput, error)
	GetIPSet(context.Context, *wafv2.GetIPSetInput, ...func(*wafv2.Options)) (*wafv2.GetIPSetOutput, error)
	UpdateIPSet(context.Context, *wafv2.UpdateIPSetInput, ...func(*wafv2.Options)) (*wafv2.UpdateIPSetOutput, error)
}

// IPSet adds the address in Field of an alert's last event to an IP set
// (Remove false), or removes it (Remove true). An IP set holds one IP
// version: with IPv6SetName, the IPv6 addresses go to that IP set, and the
// IPv4 ones to SetName.
type IPSet struct {
	ID     string // action id
	Client API
	// SetName is the name of the IP set.
	SetName string
	// IPv6SetName is the name of the IP set of the IPv6 addresses (empty:
	// SetName).
	IPv6SetName string
	Scope       types.Scope
	// Field is the event field holding the address (see
	// detection.FieldValue).
	Field   string
	Remove  bool
	Timeout time.Duration

	mu  sync.Mutex
	ids map[string]string // IP set ids by name, looked up if not configured
}

// New creates the action. setID may be empty: it is looked up by name the
// first time the action runs.
func New(id string, client API, name, setID string, scope types.Scope, field string, remove bool, timeout time.Duration) *IPSet {
	s := &IPSet{ID: id, Client: client, SetName: name, Scope: scope, Field: field, Remove: remove, Timeout: timeout, ids: map[string]string{}}
	if setID != "" {
		s.ids[name] = setID
	}
	return s
}

// WithIPv6 sends the IPv6 addresses to the IP set name (id may be empty:
// looked up by name), and returns s.
func (s *IPSet) WithIPv6(name, id string) *IPSet {
	s.IPv6SetName = name
	if id != "" {
		s.ids[name] = id
	}
	return s
}

// setName returns the name of the IP set of an address.
func (s *IPSet) setName(addr netip.Addr) string {
	if addr.Is6() && s.IPv6SetName != "" {
		return s.IPv6SetName
	}
	return s.SetName
}

func (s *IPSet) Name() string { return s.ID }

// Execute adds or removes the address of the alert.
func (s *IPSet) Execute(ctx context.Context, alert *event.Alert) error {
	cidr, err := s.address(alert)
	if err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name := s.setName(cidr.Addr())
	setID, err := s.lookup(ctx, name)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		changed, err := s.update(ctx, name, setID, cidr)
		var lock *types.WAFOptimisticLockException
		if errors.As(err, &lock) && attempt < maxAttempts {
			continue // changed meanwhile: read it again
		}
		if err != nil {
			return fmt.Errorf("WAF IP set %s: %w", name, err)
		}
		what := map[bool]string{false: "added %s to", true: "removed %s from"}[s.Remove]
		if !changed {
			what = map[bool]string{false: "%s already in", true: "%s not in"}[s.Remove]
		}
		log.Printf("action %s: "+what+" WAF IP set %s for alert %s", s.ID, cidr, name, alert.ID)
		return nil
	}
}

// address returns the address of the alert's last event as a CIDR range of
// one address, as WAF IP sets hold them.
func (s *IPSet) address(a *event.Alert) (netip.Prefix, error) {
	if len(a.Events) == 0 {
		return netip.Prefix{}, errors.New("the alert has no event")
	}
	v := detection.FieldValue(a.Events[len(a.Events)-1], s.Field)
	if v == "" {
		return netip.Prefix{}, fmt.Errorf("%s: no address in the last event", s.Field)
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s %q: not an IP address", s.Field, v)
	}
	addr = addr.Unmap().WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// lookup returns the id of an IP set, looked up by name once.
func (s *IPSet) lookup(ctx context.Context, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id := s.ids[name]; id != "" {
		return id, nil
	}
	in := &wafv2.ListIPSetsInput{Scope: s.Scope, Limit: aws.Int32(100)}
	for {
		out, err := s.Client.ListIPSets(ctx, in)
		if err != nil {
			return "", fmt.Errorf("WAF IP set %s: looking up its id: %w", name, err)
		}
		for _, set := range out.IPSets {
			if aws.ToString(set.Name) == name {
				s.ids[name] = aws.ToString(set.Id)
				return s.ids[name], nil
			}
		}
		if aws.ToString(out.NextMarker) == "" || len(out.IPSets) == 0 {
			return "", fmt.Errorf("WAF IP set %s: no IP set of this name in scope %s (and region)", name, s.Scope)
		}
		in.NextMarker = out.NextMarker
	}
}

// update reads the IP set and writes it with the address added or removed,
// and tells whether it changed.
func (s *IPSet) update(ctx context.Context, name, setID string, cidr netip.Prefix) (bool, error) {
	got, err := s.Client.GetIPSet(ctx, &wafv2.GetIPSetInput{Name: aws.String(name), Id: aws.String(setID), Scope: s.Scope})
	if err != nil {
		return false, err
	}
	set := got.IPSet
	if set == nil {
		return false, errors.New("no IP set returned")
	}
	if cidr.Addr().Is4() != (set.IPAddressVersion == types.IPAddressVersionIpv4) {
		hint := ""
		switch {
		case cidr.Addr().Is6() && s.IPv6SetName == "":
			hint = ": give an IPv6 IP set for them in ipset.ipv6_name"
		case cidr.Addr().Is6():
			hint = ": ipset.ipv6_name must be an IPv6 IP set"
		case s.IPv6SetName != "":
			hint = ": with ipset.ipv6_name, ipset.name must be an IPv4 IP set"
		}
		return false, fmt.Errorf("%s does not fit in an %s IP set%s", cidr.Addr(), set.IPAddressVersion, hint)
	}
	i := slices.IndexFunc(set.Addresses, func(a string) bool {
		p, err := netip.ParsePrefix(a)
		return err == nil && p.Masked() == cidr
	})
	addresses := set.Addresses
	switch {
	case !s.Remove && i >= 0, s.Remove && i < 0:
		return false, nil
	case s.Remove:
		addresses = slices.Delete(slices.Clone(addresses), i, i+1)
	default:
		if len(addresses) >= maxAddresses {
			return false, fmt.Errorf("the IP set is full (%d addresses)", len(addresses))
		}
		addresses = append(slices.Clone(addresses), cidr.String())
	}
	// UpdateIPSet replaces the whole IP set: keep its description. An IP
	// set without one comes back with an empty description, which
	// UpdateIPSet rejects (it must be at least 1 character): leave it out.
	var description *string
	if aws.ToString(set.Description) != "" {
		description = set.Description
	}
	_, err = s.Client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Name:        aws.String(name),
		Id:          aws.String(setID),
		Scope:       s.Scope,
		Addresses:   addresses,
		Description: description,
		LockToken:   got.LockToken,
	})
	return err == nil, err
}
