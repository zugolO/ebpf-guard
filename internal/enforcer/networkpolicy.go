package enforcer

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"gopkg.in/yaml.v3"
)

// NetworkPolicyMode controls how generated NetworkPolicies are handled.
type NetworkPolicyMode string

const (
	// NetworkPolicyModeSuggest generates the policy YAML and sends it via
	// the configured notification channel for human review.
	NetworkPolicyModeSuggest NetworkPolicyMode = "suggest"
	// NetworkPolicyModeApply applies the policy directly via the Kubernetes API.
	// Requires networkpolicies write RBAC permission, validated at startup.
	NetworkPolicyModeApply NetworkPolicyMode = "apply"
)

// PolicyNotifier sends generated NetworkPolicy YAML to operators for review.
type PolicyNotifier interface {
	SendPolicySuggestion(ctx context.Context, alert types.Alert, policyYAML string) error
}

// PolicyApplier applies and removes NetworkPolicies via the Kubernetes API.
type PolicyApplier interface {
	ApplyNetworkPolicy(ctx context.Context, namespace string, policy *networkingv1.NetworkPolicy) error
	DeleteNetworkPolicy(ctx context.Context, namespace, name string) error
}

// NetworkPolicyCfg configures the NetworkPolicyManager within an Enforcer.
type NetworkPolicyCfg struct {
	// Enabled activates the networkpolicy action type.
	Enabled bool
	// Mode is either "suggest" (default) or "apply".
	Mode NetworkPolicyMode
	// EgressBlock adds a deny-all egress rule when true.
	EgressBlock bool
	// Notify sends the generated policy YAML via the notification channel.
	Notify bool
	// AutoCleanupAfter removes applied policies after this TTL. 0 disables auto-cleanup.
	AutoCleanupAfter time.Duration
	// Notifier handles suggest-mode delivery. Nil disables notifications.
	Notifier PolicyNotifier
	// Applier handles apply-mode operations. Nil disables direct apply.
	Applier PolicyApplier
}

// appliedPolicyEntry tracks a NetworkPolicy applied by the manager for TTL cleanup.
type appliedPolicyEntry struct {
	name      string
	namespace string
	appliedAt time.Time
}

// NetworkPolicyManager generates and optionally applies Kubernetes NetworkPolicies
// in response to security alerts.
type NetworkPolicyManager struct {
	mu     sync.Mutex
	logger *slog.Logger
	cfg    NetworkPolicyCfg

	// applied tracks live policies for TTL-based cleanup; key = "namespace/name".
	applied     map[string]appliedPolicyEntry
	stopCleanup context.CancelFunc
}

// NewNetworkPolicyManager creates a NetworkPolicyManager and starts the cleanup goroutine
// when AutoCleanupAfter > 0 and mode is "apply".
func NewNetworkPolicyManager(logger *slog.Logger, cfg NetworkPolicyCfg) *NetworkPolicyManager {
	if cfg.Mode == "" {
		cfg.Mode = NetworkPolicyModeSuggest
	}
	m := &NetworkPolicyManager{
		logger:  logger.With("component", "networkpolicy_manager"),
		cfg:     cfg,
		applied: make(map[string]appliedPolicyEntry),
	}
	if cfg.AutoCleanupAfter > 0 && cfg.Mode == NetworkPolicyModeApply && cfg.Applier != nil {
		ctx, cancel := context.WithCancel(context.Background())
		m.stopCleanup = cancel
		go m.cleanupLoop(ctx)
	}
	return m
}

// Execute generates a NetworkPolicy for the given alert and either suggests or applies it.
func (m *NetworkPolicyManager) Execute(ctx context.Context, alert types.Alert) error {
	policy, policyYAML, err := m.generatePolicy(alert)
	if err != nil {
		return fmt.Errorf("networkpolicy: generate: %w", err)
	}

	m.logger.Info("NetworkPolicy generated",
		slog.String("name", policy.Name),
		slog.String("namespace", policy.Namespace),
		slog.String("rule_id", alert.RuleID),
		slog.String("mode", string(m.cfg.Mode)),
	)

	switch m.cfg.Mode {
	case NetworkPolicyModeApply:
		return m.applyPolicy(ctx, policy, policyYAML, alert)
	default:
		return m.suggestPolicy(ctx, policy, policyYAML, alert)
	}
}

// generatePolicy creates a NetworkPolicy from alert metadata.
// Pod selector labels are taken from alert.Enrichment.Labels when available.
func (m *NetworkPolicyManager) generatePolicy(alert types.Alert) (*networkingv1.NetworkPolicy, string, error) {
	namespace := alert.Enrichment.Namespace
	podName := alert.Enrichment.PodName
	if namespace == "" {
		namespace = "default"
	}

	name := policyName(podName, namespace, alert.ID)

	labels := map[string]string{}
	for k, v := range alert.Enrichment.Labels {
		labels[k] = v
	}
	// If no pod labels available, fall back to matching by pod name.
	if len(labels) == 0 && podName != "" {
		labels["kubernetes.io/pod-name"] = podName
	}

	policyTypes := []networkingv1.PolicyType{}
	if m.cfg.EgressBlock {
		policyTypes = append(policyTypes, networkingv1.PolicyTypeEgress)
	}

	policy := &networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "NetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"ebpf-guard/alert-id": alert.ID,
				"ebpf-guard/rule-id":  alert.RuleID,
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: labels,
			},
			PolicyTypes: policyTypes,
			// Egress left nil/empty to block all egress when EgressBlock=true.
		},
	}

	policyYAML, err := marshalNetworkPolicy(policy)
	if err != nil {
		return nil, "", err
	}
	return policy, policyYAML, nil
}

// applyPolicy applies the policy via the Kubernetes API and registers it for cleanup.
func (m *NetworkPolicyManager) applyPolicy(ctx context.Context, policy *networkingv1.NetworkPolicy, policyYAML string, alert types.Alert) error {
	if m.cfg.Applier == nil {
		m.logger.Warn("networkpolicy apply mode configured but no applier set; falling back to suggest")
		return m.suggestPolicy(ctx, policy, policyYAML, alert)
	}

	if err := m.cfg.Applier.ApplyNetworkPolicy(ctx, policy.Namespace, policy); err != nil {
		return fmt.Errorf("networkpolicy: apply %s/%s: %w", policy.Namespace, policy.Name, err)
	}

	m.mu.Lock()
	m.applied[policyKey(policy.Namespace, policy.Name)] = appliedPolicyEntry{
		name:      policy.Name,
		namespace: policy.Namespace,
		appliedAt: time.Now(),
	}
	m.mu.Unlock()

	m.logger.Info("NetworkPolicy applied",
		slog.String("name", policy.Name),
		slog.String("namespace", policy.Namespace),
	)

	if m.cfg.Notify && m.cfg.Notifier != nil {
		_ = m.cfg.Notifier.SendPolicySuggestion(ctx, alert, policyYAML)
	}
	return nil
}

// suggestPolicy sends the generated policy YAML via the notification channel.
func (m *NetworkPolicyManager) suggestPolicy(ctx context.Context, policy *networkingv1.NetworkPolicy, policyYAML string, alert types.Alert) error {
	if !m.cfg.Notify || m.cfg.Notifier == nil {
		m.logger.Info("NetworkPolicy suggested (no notifier configured; log only)",
			slog.String("policy_yaml", policyYAML),
		)
		return nil
	}
	if err := m.cfg.Notifier.SendPolicySuggestion(ctx, alert, policyYAML); err != nil {
		return fmt.Errorf("networkpolicy: send suggestion: %w", err)
	}
	return nil
}

// cleanupLoop removes applied policies whose TTL has expired.
func (m *NetworkPolicyManager) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.AutoCleanupAfter / 4)
	if m.cfg.AutoCleanupAfter/4 < time.Minute {
		ticker.Reset(time.Minute)
	}
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanupExpired(ctx)
		}
	}
}

// cleanupExpired deletes applied policies older than AutoCleanupAfter.
func (m *NetworkPolicyManager) cleanupExpired(ctx context.Context) {
	now := time.Now()
	m.mu.Lock()
	var toDelete []appliedPolicyEntry
	for k, entry := range m.applied {
		if now.Sub(entry.appliedAt) >= m.cfg.AutoCleanupAfter {
			toDelete = append(toDelete, entry)
			delete(m.applied, k)
		}
	}
	m.mu.Unlock()

	for _, entry := range toDelete {
		if err := m.cfg.Applier.DeleteNetworkPolicy(ctx, entry.namespace, entry.name); err != nil {
			m.logger.Warn("failed to delete expired NetworkPolicy",
				slog.String("name", entry.name),
				slog.String("namespace", entry.namespace),
				slog.Any("error", err),
			)
		} else {
			m.logger.Info("expired NetworkPolicy deleted",
				slog.String("name", entry.name),
				slog.String("namespace", entry.namespace),
			)
		}
	}
}

// Close stops the cleanup goroutine.
func (m *NetworkPolicyManager) Close() {
	if m.stopCleanup != nil {
		m.stopCleanup()
	}
}

// policyName generates a deterministic, DNS-safe NetworkPolicy name.
func policyName(podName, namespace, alertID string) string {
	suffix := alertID
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	parts := []string{"ebpf-guard-quarantine"}
	if podName != "" {
		parts = append(parts, sanitizeDNSLabel(podName))
	}
	parts = append(parts, sanitizeDNSLabel(namespace), suffix)
	name := strings.Join(parts, "-")
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-")
}

// sanitizeDNSLabel lowercases and strips characters invalid in a DNS label.
func sanitizeDNSLabel(s string) string {
	s = strings.ToLower(s)
	var b bytes.Buffer
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else if c == '.' || c == '_' {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func policyKey(namespace, name string) string {
	return namespace + "/" + name
}

// networkPolicyYAML is a lightweight struct used for YAML marshalling
// because networking/v1 types carry json tags, not yaml tags.
type networkPolicyYAML struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	Metadata   npMetaYAML            `yaml:"metadata"`
	Spec       npSpecYAML            `yaml:"spec"`
}

type npMetaYAML struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type npSpecYAML struct {
	PodSelector npSelectorYAML `yaml:"podSelector"`
	PolicyTypes []string       `yaml:"policyTypes,omitempty"`
	Egress      []interface{}  `yaml:"egress,omitempty"`
}

type npSelectorYAML struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

func marshalNetworkPolicy(p *networkingv1.NetworkPolicy) (string, error) {
	policyTypes := make([]string, len(p.Spec.PolicyTypes))
	for i, pt := range p.Spec.PolicyTypes {
		policyTypes[i] = string(pt)
	}

	doc := networkPolicyYAML{
		APIVersion: p.APIVersion,
		Kind:       p.Kind,
		Metadata: npMetaYAML{
			Name:        p.Name,
			Namespace:   p.Namespace,
			Annotations: p.Annotations,
		},
		Spec: npSpecYAML{
			PodSelector: npSelectorYAML{
				MatchLabels: p.Spec.PodSelector.MatchLabels,
			},
			PolicyTypes: policyTypes,
		},
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("networkpolicy: marshal yaml: %w", err)
	}
	return string(out), nil
}
