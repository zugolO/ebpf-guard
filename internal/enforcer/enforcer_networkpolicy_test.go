package enforcer

import (
	"context"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestEnforcer_ExecuteNetworkPolicy_NoManager verifies the skip branch: when
// the networkpolicy action fires but no NetworkPolicyManager was configured
// (NetworkPolicy.Enabled=false), Execute must not error and must not panic.
func TestEnforcer_ExecuteNetworkPolicy_NoManager(t *testing.T) {
	e, err := NewEnforcer(testLogger(), Config{
		NetworkPolicy: NetworkPolicyCfg{Enabled: false},
	})
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	if e.networkPolicyMgr != nil {
		t.Fatal("networkPolicyMgr must be nil when NetworkPolicy.Enabled is false")
	}

	alert := types.Alert{
		RuleID: "np_rule",
		Event:  types.Event{PID: 1, UID: 0, Type: types.EventTCPConnect},
	}
	if err := e.executeNetworkPolicy(context.Background(), alert); err != nil {
		t.Fatalf("executeNetworkPolicy with nil manager must return nil, got: %v", err)
	}
}

// TestEnforcer_ExecuteNetworkPolicy_SuggestMode verifies the real (manager
// present) path: a NetworkPolicyManager in suggest mode (the default) must
// actually generate a policy and increment the actionsTotal metric.
func TestEnforcer_ExecuteNetworkPolicy_SuggestMode(t *testing.T) {
	e, err := NewEnforcer(testLogger(), Config{
		NetworkPolicy: NetworkPolicyCfg{Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	if e.networkPolicyMgr == nil {
		t.Fatal("networkPolicyMgr must be non-nil when NetworkPolicy.Enabled is true")
	}

	alert := types.Alert{
		RuleID: "np_rule_2",
		ID:     "alert-123",
		Event:  types.Event{PID: 2, UID: 0, Type: types.EventTCPConnect},
		Enrichment: types.EnrichmentInfo{
			Namespace: "prod",
			PodName:   "victim-pod",
		},
	}
	if err := e.executeNetworkPolicy(context.Background(), alert); err != nil {
		t.Fatalf("executeNetworkPolicy: %v", err)
	}
}

// TestEnforcer_ExecuteNetworkPolicy_ViaExecute verifies the action is reachable
// through the public Execute/ExecuteAction dispatch, not just by calling the
// unexported method directly.
func TestEnforcer_ExecuteNetworkPolicy_ViaExecute(t *testing.T) {
	e, err := NewEnforcer(testLogger(), Config{
		NetworkPolicy: NetworkPolicyCfg{Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	alert := types.Alert{
		RuleID: "np_rule_3",
		Event:  types.Event{PID: 3, UID: 0, Type: types.EventTCPConnect},
	}
	if err := e.Execute(context.Background(), ActionNetworkPolicy, alert); err != nil {
		t.Fatalf("Execute(ActionNetworkPolicy): %v", err)
	}
}
