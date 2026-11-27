package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"wolverine/internal/config"
	"wolverine/internal/event"
)

// Conditions are the compiled CEL conditions of a rule.
type Conditions struct {
	MatchIf, ExcludeIf func(*event.Event) bool
}

// BuildRules creates the rules described in the configuration, skipping the
// disabled ones. conds holds the compiled match_if and exclude_if
// conditions, by rule id.
func BuildRules(cfgs []config.Rule, conds map[string]Conditions) ([]Rule, error) {
	var rules []Rule
	seen := map[string]bool{}
	for i, c := range cfgs {
		if c.ID == "" {
			return nil, fmt.Errorf("rule #%d: missing id", i+1)
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("rule %q: duplicate id", c.ID)
		}
		seen[c.ID] = true
		if c.Disabled {
			continue
		}

		r, err := buildRule(c, conds[c.ID])
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", c.ID, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func buildRule(c config.Rule, conds Conditions) (Rule, error) {
	if c.Match.MatchIf != "" && conds.MatchIf == nil {
		return nil, fmt.Errorf("match_if: not compiled")
	}
	match := Match{
		Category:  c.Match.Category,
		Service:   c.Match.Service,
		Action:    c.Match.Action,
		Status:    c.Match.Status,
		HasFields: c.Match.HasFields,
		MatchIf:   conds.MatchIf,
		Exclude:   c.Exclude,
		ExcludeIf: conds.ExcludeIf,
	}

	switch c.Type {
	case "threshold":
		if c.GroupBy == "" {
			return nil, fmt.Errorf("group_by is required")
		}
		if c.Count < 1 {
			return nil, fmt.Errorf("count must be at least 1")
		}
		if c.Window <= 0 {
			return nil, fmt.Errorf("window must be a positive duration (e.g. 5m)")
		}
		if c.Suppress < 0 {
			return nil, fmt.Errorf("suppress must not be negative")
		}
		return &ThresholdRule{
			RuleID:      c.ID,
			Description: c.Description,
			Severity:    c.Severity,
			Match:       match,
			GroupBy:     c.GroupBy,
			Count:       c.Count,
			Window:      c.Window,
			Suppress:    c.Suppress,
			Signature:   Signature(c),
		}, nil
	case "":
		return nil, fmt.Errorf("missing type")
	default:
		return nil, fmt.Errorf("unknown type %q", c.Type)
	}
}

// Signature identifies what a rule counts: its type, match, exclusions and
// group_by. The data a rule saved is only restored if its signature did not
// change; count, window, suppress, actions... may change.
func Signature(c config.Rule) string {
	b, _ := json.Marshal([]any{c.Type, c.Match, c.Exclude, c.ExcludeIf, c.GroupBy})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
