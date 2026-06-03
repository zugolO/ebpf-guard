package enforcer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// makeTCPAlert builds a minimal alert with a NetworkEvent for XDP testing.
func makeTCPAlert(daddr [16]byte, dport uint16, family types.AddressFamily) types.Alert {
	return types.Alert{
		RuleID:   "test_xdp_rule",
		RuleName: "XDP Test",
		Severity: types.SeverityWarning,
		Event: types.Event{
			Type: types.EventTCPConnect,
			PID:  100,
			TGID: 100,
			UID:  1000,
			Comm: [16]byte{'t', 'e', 's', 't'},
			Network: &types.NetworkEvent{
				Daddr:  daddr,
				Dport:  dport,
				Family: family,
			},
		},
	}
}

func newXDPEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer(testLogger(), Config{
		EnableBlock:  true,
		BlockBackend: BlockBackendXDP,
		XDPInterface: "", // empty → dry-run / stub mode
		DryRun:       true,
	})
	require.NoError(t, err)
	require.NotNil(t, e.xdpMgr, "XDP manager must be initialised for xdp backend")
	return e
}

func TestEnforcer_XDP_BlocksIPv4(t *testing.T) {
	e := newXDPEnforcer(t)

	var daddr [16]byte
	copy(daddr[:4], []byte{203, 0, 113, 1})

	alert := makeTCPAlert(daddr, 4444, 2 /* AF_INET */)
	require.NoError(t, e.Execute(context.Background(), ActionBlock, alert))

	// IP and port must appear in the in-memory blocklist.
	assert.Contains(t, e.xdpMgr.GetBlockedIPs(), "203.0.113.1")
	assert.Contains(t, e.xdpMgr.GetBlockedPorts(), uint16(4444))
}

func TestEnforcer_XDP_NoNetworkEvent_LogOnly(t *testing.T) {
	e := newXDPEnforcer(t)

	alert := types.Alert{
		RuleID: "test_xdp_no_net",
		Event: types.Event{
			Type: types.EventSyscall,
			PID:  100,
			TGID: 100,
			UID:  1000,
			Comm: [16]byte{'t', 'e', 's', 't'},
		},
	}

	// No network event → log-only, must not error.
	require.NoError(t, e.Execute(context.Background(), ActionBlock, alert))
	assert.Empty(t, e.xdpMgr.GetBlockedIPs())
	assert.Empty(t, e.xdpMgr.GetBlockedPorts())
}

func TestEnforcer_XDP_ParseBlockBackend(t *testing.T) {
	b, err := ParseBlockBackend("xdp")
	require.NoError(t, err)
	assert.Equal(t, BlockBackendXDP, b)
}

func TestEnforcer_XDP_GetBlockBackend(t *testing.T) {
	e := newXDPEnforcer(t)
	assert.Equal(t, BlockBackendXDP, e.GetBlockBackend())
}

func TestEnforcer_XDP_Close(t *testing.T) {
	e := newXDPEnforcer(t)
	require.NoError(t, e.Close())
}

func TestEnforcer_XDP_DisabledAction_Error(t *testing.T) {
	// Block enabled = false → Execute must return an error for ActionBlock.
	e, err := NewEnforcer(testLogger(), Config{
		EnableBlock:  false,
		BlockBackend: BlockBackendXDP,
		DryRun:       true,
	})
	require.NoError(t, err)

	alert := makeTCPAlert([16]byte{1}, 80, 2)
	err = e.Execute(context.Background(), ActionBlock, alert)
	require.Error(t, err, "disabled action must return error")
}
