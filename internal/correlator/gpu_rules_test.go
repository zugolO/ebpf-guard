package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestGPURules_LargeDtoHCopy(t *testing.T) {
	rule := Rule{
		ID:        "gpu_large_dtoh_copy",
		Name:      "Large GPU DtoH Copy",
		EventType: types.EventGPU,
		Condition: RuleCondition{
			Field:  "gpu_size",
			Op:     OpGreaterThan,
			Values: []string{"104857600"}, // 100 MB
		},
		Severity: types.SeverityCritical,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	t.Run("fires for 200 MB DtoH", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			PID:  1234,
			GPU:  &types.GPUEvent{Op: types.GPUOpMemcpyDtoH, Size: 200 * 1024 * 1024},
		}
		assert.Len(t, engine.Evaluate(event), 1)
	})

	t.Run("fires for 1 GB alloc", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			GPU:  &types.GPUEvent{Op: types.GPUOpAlloc, Size: 1024 * 1024 * 1024},
		}
		assert.Len(t, engine.Evaluate(event), 1)
	})

	t.Run("does not fire for 50 MB DtoH", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			GPU:  &types.GPUEvent{Op: types.GPUOpMemcpyDtoH, Size: 50 * 1024 * 1024},
		}
		assert.Empty(t, engine.Evaluate(event))
	})

	t.Run("nil GPU payload returns no alert", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			GPU:  nil,
		}
		assert.Empty(t, engine.Evaluate(event))
	})
}

func TestGPURules_DtoHFromShell(t *testing.T) {
	rule := Rule{
		ID:        "gpu_dtoh_from_shell",
		Name:      "GPU DtoH from Shell",
		EventType: types.EventGPU,
		ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "gpu_op", Op: OpEquals, Values: []string{"memcpy_dtoh"}},
				{Field: "comm", Op: OpIn, Values: []string{"bash", "sh", "curl", "wget"}},
			},
		},
		Severity: types.SeverityCritical,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	makeEvent := func(comm string, op types.GPUOpType) types.Event {
		var commArr [16]byte
		copy(commArr[:], comm)
		return types.Event{
			Type: types.EventGPU,
			Comm: commArr,
			GPU:  &types.GPUEvent{Op: op, Size: 1024},
		}
	}

	t.Run("fires for bash DtoH", func(t *testing.T) {
		assert.Len(t, engine.Evaluate(makeEvent("bash", types.GPUOpMemcpyDtoH)), 1)
	})

	t.Run("fires for curl DtoH", func(t *testing.T) {
		assert.Len(t, engine.Evaluate(makeEvent("curl", types.GPUOpMemcpyDtoH)), 1)
	})

	t.Run("no alert for bash alloc (wrong op)", func(t *testing.T) {
		assert.Empty(t, engine.Evaluate(makeEvent("bash", types.GPUOpAlloc)))
	})

	t.Run("no alert for python DtoH (not in shell list)", func(t *testing.T) {
		assert.Empty(t, engine.Evaluate(makeEvent("python3", types.GPUOpMemcpyDtoH)))
	})
}

func TestGPURules_KernelLaunchFromShell(t *testing.T) {
	rule := Rule{
		ID:        "gpu_kernel_launch_from_shell",
		Name:      "GPU Kernel Launch from Shell",
		EventType: types.EventGPU,
		ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "gpu_op", Op: OpEquals, Values: []string{"kernel_launch"}},
				{Field: "comm", Op: OpIn, Values: []string{"xmrig", "nbminer", "bash", "sh"}},
			},
		},
		Severity: types.SeverityCritical,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	makeEvent := func(comm string, op types.GPUOpType) types.Event {
		var commArr [16]byte
		copy(commArr[:], comm)
		return types.Event{
			Type: types.EventGPU,
			Comm: commArr,
			GPU:  &types.GPUEvent{Op: op},
		}
	}

	t.Run("fires for xmrig kernel launch", func(t *testing.T) {
		assert.Len(t, engine.Evaluate(makeEvent("xmrig", types.GPUOpKernelLaunch)), 1)
	})

	t.Run("fires for bash kernel launch", func(t *testing.T) {
		assert.Len(t, engine.Evaluate(makeEvent("bash", types.GPUOpKernelLaunch)), 1)
	})

	t.Run("no alert for python kernel launch", func(t *testing.T) {
		assert.Empty(t, engine.Evaluate(makeEvent("python3", types.GPUOpKernelLaunch)))
	})

	t.Run("no alert for xmrig DtoH (wrong op)", func(t *testing.T) {
		assert.Empty(t, engine.Evaluate(makeEvent("xmrig", types.GPUOpMemcpyDtoH)))
	})
}

func TestGPURules_RootDtoHCopy(t *testing.T) {
	rule := Rule{
		ID:        "gpu_root_dtoh_copy",
		Name:      "GPU DtoH by Root",
		EventType: types.EventGPU,
		ConditionGroup: &RuleConditionGroup{
			Operator: "and",
			Conditions: []RuleCondition{
				{Field: "gpu_op", Op: OpEquals, Values: []string{"memcpy_dtoh"}},
				{Field: "uid", Op: OpEquals, Values: []string{"0"}},
				{Field: "gpu_size", Op: OpGreaterThan, Values: []string{"1048576"}}, // 1 MB
			},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	t.Run("fires for root DtoH over 1 MB", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			UID:  0,
			GPU:  &types.GPUEvent{Op: types.GPUOpMemcpyDtoH, Size: 2 * 1024 * 1024},
		}
		assert.Len(t, engine.Evaluate(event), 1)
	})

	t.Run("no alert for non-root DtoH", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			UID:  1000,
			GPU:  &types.GPUEvent{Op: types.GPUOpMemcpyDtoH, Size: 2 * 1024 * 1024},
		}
		assert.Empty(t, engine.Evaluate(event))
	})

	t.Run("no alert for root DtoH under threshold", func(t *testing.T) {
		event := types.Event{
			Type: types.EventGPU,
			UID:  0,
			GPU:  &types.GPUEvent{Op: types.GPUOpMemcpyDtoH, Size: 512 * 1024},
		}
		assert.Empty(t, engine.Evaluate(event))
	})
}

func TestGPURules_OpNameMapping(t *testing.T) {
	opRule := func(op string) Rule {
		return Rule{
			ID:        "op_test",
			Name:      "Op Test",
			EventType: types.EventGPU,
			Condition: RuleCondition{
				Field:  "gpu_op",
				Op:     OpEquals,
				Values: []string{op},
			},
			Severity: types.SeverityWarning,
			Action:   ActionAlert,
		}
	}

	cases := []struct {
		opName   string
		gpuOp    types.GPUOpType
		expected bool
	}{
		{"alloc", types.GPUOpAlloc, true},
		{"free", types.GPUOpFree, true},
		{"memcpy_htod", types.GPUOpMemcpyHtoD, true},
		{"memcpy_dtoh", types.GPUOpMemcpyDtoH, true},
		{"memcpy_dtod", types.GPUOpMemcpyDtoD, true},
		{"kernel_launch", types.GPUOpKernelLaunch, true},
		{"alloc", types.GPUOpFree, false},
	}

	for _, tc := range cases {
		engine := NewRuleEngine([]Rule{opRule(tc.opName)})
		event := types.Event{
			Type: types.EventGPU,
			GPU:  &types.GPUEvent{Op: tc.gpuOp},
		}
		alerts := engine.Evaluate(event)
		if tc.expected {
			assert.Len(t, alerts, 1, "op %q should match gpuOp %d", tc.opName, tc.gpuOp)
		} else {
			assert.Empty(t, alerts, "op %q should not match gpuOp %d", tc.opName, tc.gpuOp)
		}
	}
}

func TestGPURules_WrongEventType(t *testing.T) {
	rule := Rule{
		ID:        "gpu_wrong_type",
		Name:      "GPU Rule",
		EventType: types.EventGPU,
		Condition: RuleCondition{
			Field:  "gpu_size",
			Op:     OpGreaterThan,
			Values: []string{"0"},
		},
		Severity: types.SeverityWarning,
		Action:   ActionAlert,
	}
	engine := NewRuleEngine([]Rule{rule})

	t.Run("GPU rule does not fire for network event", func(t *testing.T) {
		event := types.Event{
			Type:    types.EventTCPConnect,
			Network: &types.NetworkEvent{Dport: 3333},
		}
		assert.Empty(t, engine.Evaluate(event))
	})
}

func TestGPURules_FieldValidation(t *testing.T) {
	valid := []string{"gpu_op", "gpu_size", "gpu_dev_ptr", "gpu_host_ptr", "comm", "uid"}
	for _, field := range valid {
		rule := &Rule{
			ID:        "val_" + field,
			Name:      "Validation test",
			EventType: types.EventGPU,
			Condition: RuleCondition{Field: field, Op: OpEquals, Values: []string{"test"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}
		err := validateRule(rule)
		require.NoError(t, err, "field %q should be valid for GPU events", field)
	}

	invalid := []string{"dport", "filename", "nr", "qname"}
	for _, field := range invalid {
		rule := &Rule{
			ID:        "inv_" + field,
			Name:      "Validation test",
			EventType: types.EventGPU,
			Condition: RuleCondition{Field: field, Op: OpEquals, Values: []string{"test"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}
		err := validateRule(rule)
		assert.Error(t, err, "field %q should be invalid for GPU events", field)
	}
}
