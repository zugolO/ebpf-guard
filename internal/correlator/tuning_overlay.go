// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// TuningOverlay is a local, operator-owned overlay of rule exceptions merged
// onto the base rule set by rule_id at load time. It is not part of any
// shipped rule set, so it is never overwritten by a rules update — this is
// where an operator suppresses known false positives without editing the
// core rule that would otherwise be clobbered on the next rules refresh.
type TuningOverlay struct {
	Overlays []RuleTuningOverlay `yaml:"overlays"`
}

// RuleTuningOverlay adds exceptions to an existing rule, identified by ID.
type RuleTuningOverlay struct {
	RuleID     string          `yaml:"rule_id"`
	Exceptions []RuleException `yaml:"exceptions"`
}

// LoadTuningOverlay reads and validates a local-tuning YAML file at path.
// A missing file is not an error: the overlay is an optional, opt-in feature,
// so ApplyTuningOverlay is simply a no-op when overlay is nil.
func LoadTuningOverlay(path string) (*TuningOverlay, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("correlator: read tuning overlay %s: %w", path, err)
	}

	var overlay TuningOverlay
	if err := yaml.Unmarshal(data, &overlay); err != nil {
		return nil, fmt.Errorf("correlator: unmarshal tuning overlay %s: %w", path, err)
	}

	for i := range overlay.Overlays {
		o := &overlay.Overlays[i]
		if o.RuleID == "" {
			return nil, fmt.Errorf("correlator: tuning overlay %s: entry %d missing rule_id", path, i)
		}
		if len(o.Exceptions) == 0 {
			return nil, fmt.Errorf("correlator: tuning overlay %s: rule %q has no exceptions", path, o.RuleID)
		}
		for j := range o.Exceptions {
			exc := &o.Exceptions[j]
			if exc.Name == "" {
				return nil, fmt.Errorf("correlator: tuning overlay %s: rule %q exception %d missing name", path, o.RuleID, j)
			}
			if exc.ConditionGroup != nil && len(exc.ConditionGroup.Conditions) == 0 && len(exc.ConditionGroup.SubGroups) == 0 {
				return nil, fmt.Errorf("correlator: tuning overlay %s: rule %q exception %q condition_group has no conditions", path, o.RuleID, exc.Name)
			}
		}
	}

	return &overlay, nil
}

// ApplyTuningOverlay merges overlay exceptions onto rules by rule_id,
// validating each exception's condition/condition_group against the target
// rule's event type (same field-name and operator rules as core conditions).
// rule_id entries that match nothing in rules are returned in unknownRuleIDs
// rather than treated as a hard error — the overlay may reference rules that
// are not part of the currently active rule set (e.g. a disabled ruleset).
func ApplyTuningOverlay(rules []Rule, overlay *TuningOverlay) (unknownRuleIDs []string, err error) {
	if overlay == nil || len(overlay.Overlays) == 0 {
		return nil, nil
	}

	byID := make(map[string]int, len(rules))
	for i := range rules {
		byID[rules[i].ID] = i
	}

	for _, o := range overlay.Overlays {
		idx, ok := byID[o.RuleID]
		if !ok {
			unknownRuleIDs = append(unknownRuleIDs, o.RuleID)
			continue
		}
		rule := &rules[idx]
		for _, exc := range o.Exceptions {
			if exc.ConditionGroup != nil {
				for _, cond := range getConditionsFromGroup(exc.ConditionGroup) {
					if verr := validateCondition(&cond, rule.EventType); verr != nil {
						return nil, fmt.Errorf("tuning overlay: rule %q exception %q: %w", o.RuleID, exc.Name, verr)
					}
				}
			} else if verr := validateCondition(&exc.Condition, rule.EventType); verr != nil {
				return nil, fmt.Errorf("tuning overlay: rule %q exception %q: %w", o.RuleID, exc.Name, verr)
			}
		}
		rule.Exceptions = append(rule.Exceptions, o.Exceptions...)
	}

	return unknownRuleIDs, nil
}
