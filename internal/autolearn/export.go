package autolearn

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ruleFile is the YAML top-level structure matching correlator.RuleSet.
type ruleFile struct {
	Rules []ruleEntry `yaml:"rules"`
}

type ruleEntry struct {
	ID             string         `yaml:"id"`
	Name           string         `yaml:"name"`
	Description    string         `yaml:"description"`
	EventType      string         `yaml:"event_type"`
	Condition      *ruleCondition `yaml:"condition,omitempty"`
	ConditionGroup *condGroup     `yaml:"condition_group,omitempty"`
	Severity       string         `yaml:"severity"`
	Action         string         `yaml:"action"`
	Tags           []string       `yaml:"tags,omitempty"`
}

type ruleCondition struct {
	Field  string   `yaml:"field"`
	Op     string   `yaml:"op"`
	Values []string `yaml:"values"`
}

type condGroup struct {
	Operator   string          `yaml:"operator"`
	Conditions []ruleCondition `yaml:"conditions"`
}

// seccompProfile is the OCI seccomp profile JSON format.
type seccompProfile struct {
	DefaultAction string          `json:"defaultAction"`
	Architectures []string        `json:"architectures"`
	Syscalls      []seccompSyscall `json:"syscalls"`
}

type seccompSyscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// ExportRules writes a YAML rule file to outputPath that generates alerts for
// any behaviour not observed during the learning session.
func (snap *Snapshot) ExportRules(outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	workloadLabel := snap.workloadLabel()
	now := snap.GeneratedAt.Format(time.RFC3339)

	var rules []ruleEntry

	// --- Syscall allowlist ---
	if len(snap.Syscalls) > 0 {
		sorted := sortedInt64(snap.Syscalls)
		values := make([]string, len(sorted))
		for i, nr := range sorted {
			values[i] = strconv.FormatInt(nr, 10)
		}
		rules = append(rules, ruleEntry{
			ID:          fmt.Sprintf("autoprofile_%s_syscall_allowlist", workloadLabel),
			Name:        fmt.Sprintf("Auto-profile: unexpected syscall in %s", workloadLabel),
			Description: fmt.Sprintf("Syscall not observed during %s learning window (generated %s)", snap.Duration, now),
			EventType:   "syscall",
			Condition: &ruleCondition{
				Field:  "syscall_nr",
				Op:     "not_in",
				Values: values,
			},
			Severity: "warning",
			Action:   "alert",
			Tags:     []string{"auto-profile", "generated"},
		})
	}

	// --- Network destination port allowlist ---
	if len(snap.DestPorts) > 0 {
		sorted := sortedUint16(snap.DestPorts)
		values := make([]string, len(sorted))
		for i, p := range sorted {
			values[i] = strconv.FormatUint(uint64(p), 10)
		}
		rules = append(rules, ruleEntry{
			ID:          fmt.Sprintf("autoprofile_%s_net_dport_allowlist", workloadLabel),
			Name:        fmt.Sprintf("Auto-profile: unexpected destination port in %s", workloadLabel),
			Description: fmt.Sprintf("Destination port not observed during %s learning window (generated %s)", snap.Duration, now),
			EventType:   "network",
			Condition: &ruleCondition{
				Field:  "dport",
				Op:     "not_in",
				Values: values,
			},
			Severity: "warning",
			Action:   "alert",
			Tags:     []string{"auto-profile", "generated", "network"},
		})
	}

	// --- Network destination IP allowlist ---
	if len(snap.DestIPs) > 0 {
		sorted := sortedStrings(snap.DestIPs)
		rules = append(rules, ruleEntry{
			ID:          fmt.Sprintf("autoprofile_%s_net_daddr_allowlist", workloadLabel),
			Name:        fmt.Sprintf("Auto-profile: unexpected destination IP in %s", workloadLabel),
			Description: fmt.Sprintf("Destination IP not observed during %s learning window (generated %s)", snap.Duration, now),
			EventType:   "network",
			Condition: &ruleCondition{
				Field:  "daddr",
				Op:     "not_in",
				Values: sorted,
			},
			Severity: "warning",
			Action:   "alert",
			Tags:     []string{"auto-profile", "generated", "network"},
		})
	}

	// --- File directory allowlist ---
	if len(snap.FileDirs) > 0 {
		sorted := sortedStrings(snap.FileDirs)
		rules = append(rules, ruleEntry{
			ID:          fmt.Sprintf("autoprofile_%s_file_dir_allowlist", workloadLabel),
			Name:        fmt.Sprintf("Auto-profile: unexpected file directory access in %s", workloadLabel),
			Description: fmt.Sprintf("Directory not accessed during %s learning window (generated %s)", snap.Duration, now),
			EventType:   "file",
			Condition: &ruleCondition{
				Field:  "filename",
				Op:     "not_in",
				Values: sorted,
			},
			Severity: "warning",
			Action:   "alert",
			Tags:     []string{"auto-profile", "generated", "file"},
		})
	}

	rf := ruleFile{Rules: rules}
	data, err := marshalYAMLWithHeader(rf, snap)
	if err != nil {
		return fmt.Errorf("marshal rules YAML: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o640); err != nil {
		return fmt.Errorf("write rules file: %w", err)
	}
	return nil
}

// ExportSeccomp writes an OCI-compatible seccomp JSON profile to outputPath.
// The profile allowlists exactly the syscalls observed during the learning session
// and sets SCMP_ACT_ERRNO as the default action for all others.
func (snap *Snapshot) ExportSeccomp(outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	sorted := sortedInt64(snap.Syscalls)
	names := make([]string, 0, len(sorted))
	for _, nr := range sorted {
		names = append(names, SyscallName(nr))
	}

	profile := seccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"},
		Syscalls: []seccompSyscall{
			{
				Names:  names,
				Action: "SCMP_ACT_ALLOW",
			},
		},
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal seccomp JSON: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o640); err != nil {
		return fmt.Errorf("write seccomp file: %w", err)
	}
	return nil
}

// ExportAll writes both the YAML rules and seccomp profile to outputDir.
func (snap *Snapshot) ExportAll(outputDir string) (rulesPath, seccompPath string, err error) {
	label := snap.workloadLabel()
	rulesPath = filepath.Join(outputDir, fmt.Sprintf("autoprofile-%s-rules.yaml", label))
	seccompPath = filepath.Join(outputDir, fmt.Sprintf("autoprofile-%s-seccomp.json", label))

	if err := snap.ExportRules(rulesPath); err != nil {
		return "", "", fmt.Errorf("export rules: %w", err)
	}
	if err := snap.ExportSeccomp(seccompPath); err != nil {
		return "", "", fmt.Errorf("export seccomp: %w", err)
	}
	return rulesPath, seccompPath, nil
}

// Summary returns a human-readable summary of the learned profile.
func (snap *Snapshot) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Auto-Profile Summary\n")
	fmt.Fprintf(&b, "  Generated:    %s\n", snap.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "  Duration:     %s\n", snap.Duration)
	fmt.Fprintf(&b, "  Events:       %d\n", snap.EventCount)
	if snap.Namespace != "" {
		fmt.Fprintf(&b, "  Namespace:    %s\n", snap.Namespace)
	}
	if snap.ContainerID != "" {
		fmt.Fprintf(&b, "  Container:    %s\n", snap.ContainerID)
	}
	fmt.Fprintf(&b, "\n  Observed:\n")
	fmt.Fprintf(&b, "    Syscalls:       %d\n", len(snap.Syscalls))
	fmt.Fprintf(&b, "    Dest ports:     %d\n", len(snap.DestPorts))
	fmt.Fprintf(&b, "    Dest IPs:       %d\n", len(snap.DestIPs))
	fmt.Fprintf(&b, "    File dirs:      %d\n", len(snap.FileDirs))
	fmt.Fprintf(&b, "    Exec paths:     %d\n", len(snap.ExecPaths))
	fmt.Fprintf(&b, "    Processes:      %d\n", len(snap.Comms))

	if len(snap.Syscalls) > 0 {
		sorted := sortedInt64(snap.Syscalls)
		names := make([]string, 0, len(sorted))
		for _, nr := range sorted {
			names = append(names, SyscallName(nr))
		}
		fmt.Fprintf(&b, "\n  Allowed syscalls:\n    %s\n", strings.Join(names, ", "))
	}
	return b.String()
}

// workloadLabel returns a filesystem-safe identifier for this profile.
func (snap *Snapshot) workloadLabel() string {
	if snap.CommFilter != "" {
		return sanitizeLabel(snap.CommFilter)
	}
	if snap.Namespace != "" {
		return sanitizeLabel(snap.Namespace)
	}
	return "default"
}

func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// marshalYAMLWithHeader marshals the rule file and prepends a comment header.
func marshalYAMLWithHeader(rf ruleFile, snap *Snapshot) ([]byte, error) {
	body, err := yaml.Marshal(rf)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf("# Auto-generated by: ebpf-guard learn\n"+
		"# Generated at:     %s\n"+
		"# Learning window:  %s\n"+
		"# Events observed:  %d\n"+
		"# Namespace filter: %s\n"+
		"# Container filter: %s\n"+
		"#\n"+
		"# These rules alert when behaviour deviates from the baseline.\n"+
		"# Review and tune thresholds before enabling in production.\n\n",
		snap.GeneratedAt.Format(time.RFC3339),
		snap.Duration,
		snap.EventCount,
		orDefault(snap.Namespace, "(all)"),
		orDefault(snap.ContainerID, "(all)"),
	)
	return append([]byte(header), body...), nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func sortedInt64(m []int64) []int64 {
	cp := make([]int64, len(m))
	copy(cp, m)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp
}

func sortedUint16(m []uint16) []uint16 {
	cp := make([]uint16, len(m))
	copy(cp, m)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp
}

func sortedStrings(m []string) []string {
	cp := make([]string, len(m))
	copy(cp, m)
	sort.Strings(cp)
	return cp
}
