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
// (Remove false), or removes it (Remove true).
type IPSet struct {
	ID     string // action id
	Client API
	// SetName is the name of the IP set.
	SetName string
	Scope   types.Scope
	// Field is the event field holding the address (see
	// detection.FieldValue).
	Field   string
	Remove  bool
	Timeout time.Duration

	mu    sync.Mutex
	setID string // looked up by name if not configured
}

// New creates the action. setID may be empty: it is looked up by name the
// first time the action runs.
func New(id string, client API, name, setID string, scope types.Scope, field string, remove bool, timeout time.Duration) *IPSet {
	return &IPSet{ID: id, Client: client, SetName: name, setID: setID, Scope: scope, Field: field, Remove: remove, Timeout: timeout}
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

	setID, err := s.lookup(ctx)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		changed, err := s.update(ctx, setID, cidr)
		var lock *types.WAFOptimisticLockException
		if errors.As(err, &lock) && attempt < maxAttempts {
			continue // changed meanwhile: read it again
		}
		if err != nil {
			return fmt.Errorf("WAF IP set %s: %w", s.SetName, err)
		}
		what := map[bool]string{false: "added %s to", true: "removed %s from"}[s.Remove]
		if !changed {
			what = map[bool]string{false: "%s already in", true: "%s not in"}[s.Remove]
		}
		log.Printf("action %s: "+what+" WAF IP set %s for alert %s", s.ID, cidr, s.SetName, alert.ID)
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

// lookup returns the id of the IP set, looked up by name once.
func (s *IPSet) lookup(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setID != "" {
		return s.setID, nil
	}
	in := &wafv2.ListIPSetsInput{Scope: s.Scope, Limit: aws.Int32(100)}
	for {
		out, err := s.Client.ListIPSets(ctx, in)
		if err != nil {
			return "", fmt.Errorf("WAF IP set %s: looking up its id: %w", s.SetName, err)
		}
		for _, set := range out.IPSets {
			if aws.ToString(set.Name) == s.SetName {
				s.setID = aws.ToString(set.Id)
				return s.setID, nil
			}
		}
		if aws.ToString(out.NextMarker) == "" || len(out.IPSets) == 0 {
			return "", fmt.Errorf("WAF IP set %s: no IP set of this name in scope %s (and region)", s.SetName, s.Scope)
		}
		in.NextMarker = out.NextMarker
	}
}

// update reads the IP set and writes it with the address added or removed,
// and tells whether it changed.
func (s *IPSet) update(ctx context.Context, setID string, cidr netip.Prefix) (bool, error) {
	got, err := s.Client.GetIPSet(ctx, &wafv2.GetIPSetInput{Name: aws.String(s.SetName), Id: aws.String(setID), Scope: s.Scope})
	if err != nil {
		return false, err
	}
	set := got.IPSet
	if set == nil {
		return false, errors.New("no IP set returned")
	}
	if cidr.Addr().Is4() != (set.IPAddressVersion == types.IPAddressVersionIpv4) {
		return false, fmt.Errorf("%s does not fit in an %s IP set", cidr.Addr(), set.IPAddressVersion)
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
		Name:        aws.String(s.SetName),
		Id:          aws.String(setID),
		Scope:       s.Scope,
		Addresses:   addresses,
		Description: description,
		LockToken:   got.LockToken,
	})
	return err == nil, err
}
