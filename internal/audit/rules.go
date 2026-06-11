package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// RulesEvent identifies the kind of rule audit record.
type RulesEvent string

const (
	EventRulesLoaded   RulesEvent = "rules_loaded"
	EventRulesReloaded RulesEvent = "rules_reloaded"
	EventConfigReloaded RulesEvent = "config_reloaded"
)

// RulesEntry is one rule-change audit record.
// The JSON field names are stable; consumers may rely on them without schema evolution.
type RulesEntry struct {
	Timestamp       time.Time  `json:"timestamp"`
	Event           RulesEvent `json:"event"`
	Source          string     `json:"source"`           // "startup", "fsnotify", "api"
	RulesFile       string     `json:"rules_file"`
	RulesAdded      int        `json:"rules_added"`
	RulesRemoved    int        `json:"rules_removed"`
	RulesModified   int        `json:"rules_modified"`
	OldRuleIDs      []string   `json:"old_rule_ids,omitempty"`
	NewRuleIDs      []string   `json:"new_rule_ids,omitempty"`
	ChecksumBefore  string     `json:"checksum_before,omitempty"`
	ChecksumAfter   string     `json:"checksum_after"`
	ConfigFile      string     `json:"config_file,omitempty"` // set for config_reloaded
}

// RulesLogger writes rule-change audit entries to the same append-only JSONL
// file as the enforcement Logger. It is safe for concurrent use.
type RulesLogger struct {
	l                *Logger
	includeRuleDiffs bool
}

// NewRulesLogger creates a RulesLogger backed by an append-only JSONL file at
// path. includeRuleDiffs controls whether old_rule_ids and new_rule_ids are
// written; set to false for high-cardinality rule sets to reduce log volume.
func NewRulesLogger(path string, maxSizeMB int, includeRuleDiffs bool) (*RulesLogger, error) {
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = rotateSize
	}
	l, err := newLogger(path, maxBytes)
	if err != nil {
		return nil, err
	}
	return &RulesLogger{l: l, includeRuleDiffs: includeRuleDiffs}, nil
}

// LogRulesLoaded records a startup rule-load event.
// ruleIDs is the complete set of rule IDs in the newly loaded file.
// rulesFile is the path to the rules YAML that was loaded.
func (rl *RulesLogger) LogRulesLoaded(rulesFile string, ruleIDs []string) error {
	e := RulesEntry{
		Timestamp:    time.Now().UTC(),
		Event:        EventRulesLoaded,
		Source:       "startup",
		RulesFile:    rulesFile,
		RulesAdded:   len(ruleIDs),
		ChecksumAfter: checksumIDs(ruleIDs),
	}
	if rl.includeRuleDiffs {
		e.NewRuleIDs = sortedCopy(ruleIDs)
	}
	return rl.write(e)
}

// LogRulesReloaded records a hot-reload event, computing the diff between
// oldIDs and newIDs to populate the added/removed/modified counts.
func (rl *RulesLogger) LogRulesReloaded(source, rulesFile string, oldIDs, newIDs []string) error {
	added, removed, modified := diffRuleIDs(oldIDs, newIDs)
	e := RulesEntry{
		Timestamp:      time.Now().UTC(),
		Event:          EventRulesReloaded,
		Source:         source,
		RulesFile:      rulesFile,
		RulesAdded:     len(added),
		RulesRemoved:   len(removed),
		RulesModified:  len(modified),
		ChecksumBefore: checksumIDs(oldIDs),
		ChecksumAfter:  checksumIDs(newIDs),
	}
	if rl.includeRuleDiffs {
		e.OldRuleIDs = sortedCopy(oldIDs)
		e.NewRuleIDs = sortedCopy(newIDs)
	}
	return rl.write(e)
}

// LogConfigReloaded records a config-file change event.
func (rl *RulesLogger) LogConfigReloaded(configFile string) error {
	e := RulesEntry{
		Timestamp:  time.Now().UTC(),
		Event:      EventConfigReloaded,
		Source:     "fsnotify",
		ConfigFile: configFile,
	}
	return rl.write(e)
}

// Close closes the underlying log file.
func (rl *RulesLogger) Close() error {
	return rl.l.Close()
}

// write serialises the entry as a single JSON line.
func (rl *RulesLogger) write(e RulesEntry) error {
	rl.l.mu.Lock()
	defer rl.l.mu.Unlock()
	if err := rl.l.maybeRotate(); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit rules: marshal: %w", err)
	}
	b = append(b, '\n')
	_, err = rl.l.file.Write(b)
	return err
}

// checksumIDs returns "sha256:<hex>" of the sorted, newline-joined rule IDs.
func checksumIDs(ids []string) string {
	sorted := sortedCopy(ids)
	h := sha256.New()
	for _, id := range sorted {
		h.Write([]byte(id))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// diffRuleIDs computes added, removed, and modified rule IDs between two sets.
// A rule is considered "modified" if it appears in both sets — presence in both
// means it persisted but may have changed; this is a best-effort approximation
// since we only compare IDs, not rule bodies.
func diffRuleIDs(oldIDs, newIDs []string) (added, removed, modified []string) {
	oldSet := make(map[string]struct{}, len(oldIDs))
	for _, id := range oldIDs {
		oldSet[id] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(newIDs))
	for _, id := range newIDs {
		newSet[id] = struct{}{}
	}
	for _, id := range newIDs {
		if _, ok := oldSet[id]; ok {
			modified = append(modified, id)
		} else {
			added = append(added, id)
		}
	}
	for _, id := range oldIDs {
		if _, ok := newSet[id]; !ok {
			removed = append(removed, id)
		}
	}
	return
}

// sortedCopy returns a sorted copy of ids, or nil if ids is empty.
func sortedCopy(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	cp := make([]string, len(ids))
	copy(cp, ids)
	sort.Strings(cp)
	return cp
}
