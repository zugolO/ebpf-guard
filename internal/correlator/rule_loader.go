// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"gopkg.in/yaml.v3"
)

// Valid field names for each event type. These are the single source of truth
// for field name validation — keep in sync with getFieldValue in rules.go.
var (
	validNetworkFields = map[string]bool{
		"dport": true, "sport": true, "daddr": true, "saddr": true, "proto": true, "family": true,
		// proc enrichment: command-line args populated from BPF proc_args_map or /proc fallback
		"proc.args":           true,
		"proc.args_truncated": true,
		// Aliases: dot-prefixed names used in rule YAML files for readability.
		"network.dport": true, "network.sport": true,
		"network.daddr": true, "network.saddr": true, "network.proto": true,
		"proc.comm": true, "uid": true,
	}
	validFileFields = map[string]bool{
		"filename": true, "flags": true, "mode": true, "op": true, "directory": true, "extension": true,
		// fd-enrichment fields (issue #47): available for all file ops; populated via BPF fd→path map.
		"fd.name":           true,
		"fd.name_truncated": true,
		// proc enrichment: command-line args populated from BPF proc_args_map or /proc fallback
		"proc.args":           true,
		"proc.args_truncated": true,
		// Aliases: dot-prefixed names used in rule YAML files for readability.
		"file.path":           true,
		"file.op":             true,
		"file.flags":          true,
		"file.mode":           true,
		"file.directory":      true,
		"file.extension":      true,
		"proc.comm":           true,
		"uid":                 true,
	}
	validSyscallFields = map[string]bool{
		"nr": true, "ret": true,
		// Process identity — available from the base Event struct on all syscalls.
		"uid": true, "comm": true,
		// Raw syscall arguments (arg0 = first argument, arg1 = second, …).
		"arg0": true, "arg1": true, "arg2": true,
		"arg3": true, "arg4": true, "arg5": true,
		// fd-enrichment: resolved path for the fd in arg0 (read/write/close syscalls).
		"fd.name": true,
		// proc enrichment
		"proc.args":           true,
		"proc.args_truncated": true,
		// Aliases: dot-prefixed names used in rule YAML files for readability.
		"syscall.nr":   true,
		"syscall.ret":  true,
		"syscall.arg0": true, "syscall.arg1": true, "syscall.arg2": true,
		"syscall.arg3": true, "syscall.arg4": true, "syscall.arg5": true,
		"proc.comm": true,
	}
	validDNSFields = map[string]bool{
		"qname": true, "qtype": true, "rcode": true, "direction": true,
		// Enriched fields computed on demand from qname
		"qname_length": true, "qname_entropy": true, "qname_dga_score": true,
		"qname_digit_ratio": true, "qname_subdomain_count": true, "qname_is_dga": true,
	}
	validTLSFields = map[string]bool{
		"tls_data": true, "direction": true, "data_len": true,
		// "data" is an alias for "tls_data" accepted in rule YAML for ergonomics.
		"data": true,
		// JA3/JA4 TLS fingerprint fields — computed from ClientHello handshake.
		"ja3":  true,
		"ja4":  true,
		"ja3s": true,
	}
	// caps_gained / caps_dropped use the OpCapsGained / OpCapsDropped operators
	// (not standard value comparison), so their only meaningful field is "caps".
	validPrivescFields = map[string]bool{
		"caps": true, "uid": true, "comm": true,
	}
	validNetCloseFields = map[string]bool{
		"dport": true, "sport": true, "daddr": true, "saddr": true,
		"family": true, "duration_sec": true, "duration_ms": true,
	}
	validGPUFields = map[string]bool{
		"gpu_op":       true, // operation name: alloc, free, memcpy_htod, memcpy_dtoh, memcpy_dtod, kernel_launch
		"gpu_size":     true, // bytes transferred or allocated
		"gpu_dev_ptr":  true, // device memory address (hex string)
		"gpu_host_ptr": true, // host memory address (hex string)
		"comm":         true, // process name (allows filtering by process)
		"uid":          true, // user ID (allows filtering non-root access)
	}
	validCgroupEscFields = map[string]bool{
		"new_cgroup_id": true,
		"old_cgroup_id": true,
		"cgroup_path":   true,
		"comm":          true,
		"uid":           true,
	}
	validKmodFields = map[string]bool{
		"name":        true,
		"filename":    true,
		"comm":        true,
		"uid":         true,
		"fingerprint": true,
	}
	validLSMAuditFields = map[string]bool{
		"hook":     true,
		"comm":     true,
		"uid":      true,
		"decision": true,
	}
	validSequenceFields = map[string]bool{
		"pattern": true,
		"comm":    true,
		"uid":     true,
	}
	validIOUringFields = map[string]bool{
		"op":        true, // "setup" or "enter"
		"flags":     true, // IORING_SETUP_* / IORING_ENTER_* flags as uint32 string
		"fd":        true, // io_uring instance fd
		"to_submit": true, // number of SQEs to submit
		"comm":      true,
		"uid":       true,
	}
	validCloudAuditFields = map[string]bool{
		"cloud.provider":   true, // "aws" | "gcp" | "azure"
		"cloud.service":    true, // "iam" | "ec2" | "gke" | "storage" | …
		"cloud.action":     true, // "AssumeRole" | "GetSecretValue" | "pods/exec" | …
		"cloud.principal":  true, // ARN or service account email
		"cloud.resource":   true, // target resource ARN / name
		"cloud.source_ip":  true, // client IP
		"cloud.user_agent": true, // HTTP user-agent
		"cloud.error_code": true, // non-empty = denied/failed
		"cloud.region":     true, // cloud region
		"cloud.event_id":   true, // provider event ID
	}
	validBpfProgramFields = map[string]bool{
		"cmd":       true, // bpf command: "PROG_LOAD" or "MAP_CREATE"
		"cmd_nr":    true, // numeric bpf command: 5 for PROG_LOAD, 0 for MAP_CREATE
		"prog_type": true, // BPF program type name (e.g. "XDP", "KPROBE", "SCHED_CLS")
		"prog_type_nr": true, // numeric BPF program type
		"ret":       true, // return value: >=0 = fd, <0 = error
		"uid":       true,
		"comm":      true,
	}
)

// Ensure RuleConditionGroup has SubGroups field for recursive validation.
// This is defined in rules.go but we need to reference it here.

// ValidateFull performs full pre-swap validation of a rule set.
// It validates each rule individually (field names, operators, regex/CIDR patterns,
// sample_rate range) and then checks the set as a whole for duplicate rule IDs.
// All errors are collected so the caller sees every problem in one pass.
func ValidateFull(rules []Rule) error {
	var errs []string

	seen := make(map[string]int, len(rules))
	for i := range rules {
		rule := &rules[i]
		if err := validateRule(rule); err != nil {
			errs = append(errs, fmt.Sprintf("rule %d (%s): %v", i, rule.ID, err))
		}
		if rule.ID != "" {
			if prev, dup := seen[rule.ID]; dup {
				errs = append(errs, fmt.Sprintf("duplicate rule ID %q at indices %d and %d", rule.ID, prev, i))
			} else {
				seen[rule.ID] = i
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("correlator: rule set validation failed (%d error(s)): %s",
			len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// LoadRulesFromFile loads rules from a YAML file with full validation.
func LoadRulesFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("correlator: read rules file: %w", err)
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("correlator: unmarshal rules: %w", err)
	}

	if err := ValidateFull(ruleSet.Rules); err != nil {
		return nil, err
	}

	return ruleSet.Rules, nil
}

// LoadRulesFromDir loads all .yaml/.yml files from a directory.
func LoadRulesFromDir(dir string) ([]Rule, error) {
	return LoadRulesFromDirWithChecksums(dir, false, "")
}

// LoadRulesFromEmbedded loads rules from a map of filename → YAML content,
// performing full validation on the combined set. This is used by the
// zero-config mode where rules are embedded in the binary via Go embed.
// Unknown files (without .yaml/.yml extension) are silently skipped.
func LoadRulesFromEmbedded(files map[string][]byte) ([]Rule, error) {
	var allRules []Rule
	for name, data := range files {
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		var ruleSet RuleSet
		if err := yaml.Unmarshal(data, &ruleSet); err != nil {
			return nil, fmt.Errorf("correlator: unmarshal rules from %s: %w", name, err)
		}
		allRules = append(allRules, ruleSet.Rules...)
	}

	if err := ValidateFull(allRules); err != nil {
		return nil, err
	}
	return allRules, nil
}

// LoadRulesFromDirWithChecksums loads all .yaml/.yml rule files from a
// directory, optionally verifying their SHA-256 checksums first.
// When verifyChecksums is true and checksumFile is empty, it defaults to
// <dir>/checksums.sha256. Returns an error if any checksum fails.
func LoadRulesFromDirWithChecksums(dir string, verifyChecksums bool, checksumFile string) ([]Rule, error) {
	if verifyChecksums {
		if err := VerifyRuleChecksums(dir, checksumFile); err != nil {
			return nil, err
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("correlator: read rules directory: %w", err)
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		rules, err := LoadRulesFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("correlator: load rules from %s: %w", path, err)
		}

		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

// validateRule validates a single rule including regex, CIDR, and field names.
func validateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.EventType == 0 {
		return fmt.Errorf("event type is required")
	}
	if rule.Action == "" {
		rule.Action = ActionAlert // Default action
	}
	switch rule.Action {
	case ActionAlert, ActionDrop, ActionBlock, ActionKill, ActionThrottle:
		// valid
	default:
		return fmt.Errorf("unknown action %q, valid: alert, drop, block, kill, throttle", rule.Action)
	}
	if rule.Severity == "" {
		rule.Severity = "warning" // Default severity
	}

	// Reject empty condition_group (Н-4): would silently match every event.
	if rule.ConditionGroup != nil && len(rule.ConditionGroup.Conditions) == 0 && len(rule.ConditionGroup.SubGroups) == 0 {
		return fmt.Errorf("rule %s: condition_group has no conditions or subgroups", rule.ID)
	}

	// Resolve nested sampling block (takes precedence over flat sample_rate/sample_deterministic).
	if rule.Sampling != nil {
		if rule.Sampling.Rate != 0 {
			rule.SampleRate = rule.Sampling.Rate
		}
		switch rule.Sampling.Mode {
		case SamplingModeHashPID:
			rule.SampleDeterministic = true
		case SamplingModeRandom:
			// explicitly set random mode
		case "":
			// Default to deterministic (hash_pid) for reproducible sampling.
			rule.SampleDeterministic = true
		default:
			return fmt.Errorf("rule %s: sampling.mode %q invalid, must be %q or %q",
				rule.ID, rule.Sampling.Mode, SamplingModeRandom, SamplingModeHashPID)
		}
	} else if rule.SampleRate > 0 && rule.SampleRate < 1.0 {
		// Flat sample_rate with deterministic default.
		rule.SampleDeterministic = true
	}

	// Normalise sample_rate: missing (0.0) → 1.0 (evaluate every event).
	if rule.SampleRate == 0 {
		rule.SampleRate = 1.0
	}
	if rule.SampleRate < 0 || rule.SampleRate > 1.0 {
		return fmt.Errorf("rule %s: sample_rate %.4f out of range, must be in (0.0, 1.0]", rule.ID, rule.SampleRate)
	}

	// Validate conditions
	conditions := getAllConditions(rule)
	for _, cond := range conditions {
		if err := validateCondition(&cond, rule.EventType); err != nil {
			return fmt.Errorf("condition validation failed: %w", err)
		}
	}

	return nil
}

// getAllConditions extracts all conditions from a rule, recursively traversing SubGroups.
func getAllConditions(rule *Rule) []RuleCondition {
	if rule.ConditionGroup != nil {
		return getConditionsFromGroup(rule.ConditionGroup)
	}
	return []RuleCondition{rule.Condition}
}

// getConditionsFromGroup recursively extracts conditions from a RuleConditionGroup and its SubGroups.
func getConditionsFromGroup(group *RuleConditionGroup) []RuleCondition {
	if group == nil {
		return nil
	}

	var conditions []RuleCondition

	// Add direct conditions
	conditions = append(conditions, group.Conditions...)

	// Recursively process subgroups
	for i := range group.SubGroups {
		conditions = append(conditions, getConditionsFromGroup(&group.SubGroups[i])...)
	}

	return conditions
}

// validateCondition validates a single condition including regex, CIDR, and field names.
func validateCondition(cond *RuleCondition, eventType types.EventType) error {
	// Validate field name is valid for the event type
	if err := validateFieldName(cond.Field, eventType); err != nil {
		return err
	}

	// Validate operator-specific requirements
	switch cond.Op {
	case OpRegex:
		if err := validateRegexPatterns(cond.Values); err != nil {
			return fmt.Errorf("regex validation failed for field %s: %w", cond.Field, err)
		}
	case OpInCIDR, OpNotInCIDR:
		if err := validateCIDRPatterns(cond.Values); err != nil {
			return fmt.Errorf("CIDR validation failed for field %s: %w", cond.Field, err)
		}
		// CIDR operators are valid for IP address fields.
		validCIDRFields := map[string]bool{
			"daddr":           true,
			"saddr":           true,
			"cloud.source_ip": true,
		}
		if !validCIDRFields[cond.Field] {
			return fmt.Errorf("CIDR operator %s can only be used with daddr/saddr/cloud.source_ip fields, not %s", cond.Op, cond.Field)
		}
	case OpIn, OpNotIn, OpEquals, OpNotEquals, OpPrefix, OpSuffix, OpContains,
		OpGreaterThan, OpLessThan, OpGreaterOrEqual, OpLessOrEqual,
		OpCapsGained, OpCapsDropped:
		// These operators don't need pre-validation
	default:
		return fmt.Errorf("unknown operator: %s", cond.Op)
	}

	return nil
}

// validateFieldName checks if a field name is valid for the given event type.
func validateFieldName(field string, eventType types.EventType) error {
	if field == "" {
		return fmt.Errorf("field name is required")
	}

	var validFields map[string]bool
	switch eventType {
	case types.EventTCPConnect:
		validFields = validNetworkFields
	case types.EventFileAccess:
		validFields = validFileFields
	case types.EventSyscall:
		validFields = validSyscallFields
	case types.EventDNS:
		validFields = validDNSFields
	case types.EventTLS:
		validFields = validTLSFields
	case types.EventPrivesc:
		validFields = validPrivescFields
	case types.EventNetClose:
		validFields = validNetCloseFields
	case types.EventGPU:
		validFields = validGPUFields
	case types.EventCgroupEsc:
		validFields = validCgroupEscFields
	case types.EventKmodLoad:
		validFields = validKmodFields
	case types.EventLSMAudit:
		validFields = validLSMAuditFields
	case types.EventSequence:
		validFields = validSequenceFields
	case types.EventIOUring:
		validFields = validIOUringFields
	case types.EventCloudAudit:
		validFields = validCloudAuditFields
	case types.EventBPFProgram:
		validFields = validBpfProgramFields
	default:
		return fmt.Errorf("unknown event type: %d", eventType)
	}

	if !validFields[field] {
		// Get list of valid fields for error message
		var validList []string
		for f := range validFields {
			validList = append(validList, f)
		}
		return fmt.Errorf("invalid field name %q for event type %d, valid fields: %v", field, eventType, validList)
	}

	return nil
}

// maxRegexPatternLen caps the length of a single regex pattern accepted in a
// rule. Go's regexp package uses RE2 (linear-time matching), so catastrophic
// backtracking cannot occur, but very long patterns still drive up compilation
// time and memory usage. 1 KiB is generous for all legitimate detection rules.
const maxRegexPatternLen = 1024

// validateRegexPatterns compiles and validates all regex patterns.
func validateRegexPatterns(patterns []string) error {
	if len(patterns) == 0 {
		return fmt.Errorf("regex operator requires at least one pattern")
	}
	for _, pattern := range patterns {
		if len(pattern) > maxRegexPatternLen {
			return fmt.Errorf("regex pattern exceeds maximum length of %d bytes (got %d)", maxRegexPatternLen, len(pattern))
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
		}
	}
	return nil
}

// validateCIDRPatterns parses and validates all CIDR ranges.
func validateCIDRPatterns(cidrs []string) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("CIDR operator requires at least one CIDR range")
	}
	for _, cidr := range cidrs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR range %q: %w", cidr, err)
		}
	}
	return nil
}
