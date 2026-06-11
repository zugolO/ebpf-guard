package enforcer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	networkingv1 "k8s.io/api/networking/v1"
)

// fakePolicyApplier records Apply/Delete calls for assertions.
type fakePolicyApplier struct {
	applied []string
	deleted []string
}

func (f *fakePolicyApplier) ApplyNetworkPolicy(_ context.Context, namespace string, policy *networkingv1.NetworkPolicy) error {
	f.applied = append(f.applied, namespace+"/"+policy.Name)
	return nil
}

func (f *fakePolicyApplier) DeleteNetworkPolicy(_ context.Context, namespace, name string) error {
	f.deleted = append(f.deleted, namespace+"/"+name)
	return nil
}

// fakePolicyNotifier records suggestion calls.
type fakePolicyNotifier struct {
	suggestions []string
}

func (f *fakePolicyNotifier) SendPolicySuggestion(_ context.Context, _ types.Alert, yaml string) error {
	f.suggestions = append(f.suggestions, yaml)
	return nil
}

func makeAlert(podName, ns, alertID, ruleID string, labels map[string]string) types.Alert {
	return types.Alert{
		ID:     alertID,
		RuleID: ruleID,
		Enrichment: types.EnrichmentInfo{
			PodName:   podName,
			Namespace: ns,
			Labels:    labels,
		},
	}
}

func TestNetworkPolicyGenerateYAML(t *testing.T) {
	m := NewNetworkPolicyManager(testLogger(), NetworkPolicyCfg{
		Enabled:     true,
		Mode:        NetworkPolicyModeSuggest,
		EgressBlock: true,
		Notify:      false,
	})

	alert := makeAlert("nginx-abc", "production", "alert-001", "crypto_c2", map[string]string{
		"app": "nginx",
		"env": "prod",
	})

	_, policyYAML, err := m.generatePolicy(alert)
	if err != nil {
		t.Fatalf("generatePolicy: %v", err)
	}

	for _, want := range []string{
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"namespace: production",
		"ebpf-guard/alert-id",
		"alert-001",
		"ebpf-guard/rule-id",
		"crypto_c2",
		"Egress",
		"app: nginx",
	} {
		if !strings.Contains(policyYAML, want) {
			t.Errorf("policy YAML missing %q:\n%s", want, policyYAML)
		}
	}
}

func TestNetworkPolicyNameSanitisation(t *testing.T) {
	tests := []struct {
		pod, ns, id string
		wantPrefix  string
	}{
		{"nginx-abc", "default", "alert-001", "ebpf-guard-quarantine-nginx-abc-default-"},
		{"Pod_With.Dots", "kube-system", "x", "ebpf-guard-quarantine-pod-with-dots-kube-system-"},
		{"", "ns", "abc12345", "ebpf-guard-quarantine-ns-"},
	}
	for _, tc := range tests {
		name := policyName(tc.pod, tc.ns, tc.id)
		if !strings.HasPrefix(name, tc.wantPrefix) {
			t.Errorf("policyName(%q, %q, %q) = %q, want prefix %q", tc.pod, tc.ns, tc.id, name, tc.wantPrefix)
		}
		if len(name) > 63 {
			t.Errorf("policyName too long: %d > 63: %s", len(name), name)
		}
	}
}

func TestNetworkPolicySuggestMode(t *testing.T) {
	notifier := &fakePolicyNotifier{}
	m := NewNetworkPolicyManager(testLogger(), NetworkPolicyCfg{
		Enabled:  true,
		Mode:     NetworkPolicyModeSuggest,
		Notify:   true,
		Notifier: notifier,
	})

	alert := makeAlert("app-pod", "staging", "alert-42", "rule-net-001", map[string]string{"app": "myapp"})
	if err := m.Execute(context.Background(), alert); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(notifier.suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(notifier.suggestions))
	}
	if !strings.Contains(notifier.suggestions[0], "kind: NetworkPolicy") {
		t.Errorf("suggestion missing NetworkPolicy kind:\n%s", notifier.suggestions[0])
	}
}

func TestNetworkPolicyApplyMode(t *testing.T) {
	applier := &fakePolicyApplier{}
	m := NewNetworkPolicyManager(testLogger(), NetworkPolicyCfg{
		Enabled: true,
		Mode:    NetworkPolicyModeApply,
		Applier: applier,
	})

	alert := makeAlert("worker", "prod", "alert-99", "rule-001", map[string]string{"role": "worker"})
	if err := m.Execute(context.Background(), alert); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(applier.applied) != 1 {
		t.Fatalf("expected 1 applied policy, got %d", len(applier.applied))
	}
	if !strings.HasPrefix(applier.applied[0], "prod/ebpf-guard-quarantine-") {
		t.Errorf("unexpected applied policy key: %s", applier.applied[0])
	}
}

func TestNetworkPolicyAutoCleanup(t *testing.T) {
	applier := &fakePolicyApplier{}
	ttl := 100 * time.Millisecond
	m := NewNetworkPolicyManager(testLogger(), NetworkPolicyCfg{
		Enabled:          true,
		Mode:             NetworkPolicyModeApply,
		Applier:          applier,
		AutoCleanupAfter: ttl,
	})
	defer m.Close()

	alert := makeAlert("pod-x", "ns-x", "alert-cleanup", "rule-x", nil)
	if err := m.Execute(context.Background(), alert); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(applier.applied) != 1 {
		t.Fatalf("expected 1 applied, got %d", len(applier.applied))
	}

	// Force cleanup directly after TTL expires (don't rely on goroutine timing).
	time.Sleep(ttl + 10*time.Millisecond)
	m.cleanupExpired(context.Background())

	if len(applier.deleted) != 1 {
		t.Fatalf("expected 1 deleted policy after TTL, got %d", len(applier.deleted))
	}
}

func TestNetworkPolicyFallbackToSuggestWhenNoApplier(t *testing.T) {
	notifier := &fakePolicyNotifier{}
	m := NewNetworkPolicyManager(testLogger(), NetworkPolicyCfg{
		Enabled:  true,
		Mode:     NetworkPolicyModeApply, // apply mode but no Applier
		Notify:   true,
		Notifier: notifier,
		Applier:  nil, // intentionally nil
	})

	alert := makeAlert("pod", "ns", "alert-fb", "rule-fb", nil)
	if err := m.Execute(context.Background(), alert); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Should fall back to suggest mode.
	if len(notifier.suggestions) != 1 {
		t.Fatalf("expected fallback to suggest: got %d suggestions", len(notifier.suggestions))
	}
}

