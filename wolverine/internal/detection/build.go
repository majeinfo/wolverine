package detection

import (
	"fmt"

	"wolverine/internal/config"
)

// BuildRules creates the rules described in the configuration, skipping the
// disabled ones.
func BuildRules(cfgs []config.Rule) ([]Rule, error) {
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

		r, err := buildRule(c)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", c.ID, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func buildRule(c config.Rule) (Rule, error) {
	match := Match{
		Category:  c.Match.Category,
		Service:   c.Match.Service,
		Action:    c.Match.Action,
		Status:    c.Match.Status,
		HasFields: c.Match.HasFields,
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
		}, nil
	case "":
		return nil, fmt.Errorf("missing type")
	default:
		return nil, fmt.Errorf("unknown type %q", c.Type)
	}
}
