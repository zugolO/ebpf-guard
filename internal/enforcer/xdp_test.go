package enforcer

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ReadStats — returns zeros when BPF is not loaded (dry-run / stub mode)
// ---------------------------------------------------------------------------

func TestXDPManager_ReadStats_NotLoaded(t *testing.T) {
	m := newTestXDPManager(t)
	agg, err := m.ReadStats()
	require.NoError(t, err, "ReadStats must not error in dry-run mode")
	assert.Equal(t, uint64(0), agg.Dropped, "dropped must be zero when BPF is not loaded")
	assert.Equal(t, uint64(0), agg.Passed, "passed must be zero when BPF is not loaded")
}

func TestXDPManager_ReadStats_AfterClose(t *testing.T) {
	m := newTestXDPManager(t)
	require.NoError(t, m.Close())
	agg, err := m.ReadStats()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), agg.Dropped)
	assert.Equal(t, uint64(0), agg.Passed)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

// requireRoot skips the calling test when it is not running as root. Tests that
// program real kernel state (nftables/iptables netlink, cgroup cpu.max writes)
// need CAP_NET_ADMIN / write access under /sys/fs/cgroup, which shared CI
// runners execute without — there the operations fail with EPERM. Locally (or
// in a privileged container) these still run and provide the real coverage.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("test programs real kernel state (netfilter/cgroup) and requires root")
	}
}

func newTestXDPManager(t *testing.T) *XDPManager {
	t.Helper()
	// DryRun + empty interface → in-memory log-only mode (no BPF required).
	m, err := NewXDPManager(testLogger(), XDPConfig{DryRun: true})
	require.NoError(t, err)
	return m
}

// ---------------------------------------------------------------------------
// BlockIP / UnblockIP
// ---------------------------------------------------------------------------

func TestXDPManager_BlockIP_IPv4(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("192.168.1.100")
	require.NotNil(t, ip)

	require.NoError(t, m.BlockIP(context.Background(), ip))
	assert.Contains(t, m.GetBlockedIPs(), "192.168.1.100")
}

func TestXDPManager_BlockIP_IPv6(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("2001:db8::1")
	require.NotNil(t, ip)

	require.NoError(t, m.BlockIP(context.Background(), ip))
	assert.Contains(t, m.GetBlockedIPs(), "2001:db8::1")
}

func TestXDPManager_BlockIP_Idempotent(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("10.0.0.1")
	require.NoError(t, m.BlockIP(context.Background(), ip))
	require.NoError(t, m.BlockIP(context.Background(), ip)) // second call is no-op
	assert.Len(t, m.GetBlockedIPs(), 1)
}

func TestXDPManager_UnblockIP(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("10.0.0.2")

	require.NoError(t, m.BlockIP(context.Background(), ip))
	require.NoError(t, m.UnblockIP(context.Background(), ip))
	assert.Empty(t, m.GetBlockedIPs())
}

func TestXDPManager_UnblockIP_NotBlocked_Noop(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("10.0.0.99")
	// Unblocking an IP that was never blocked must not error.
	require.NoError(t, m.UnblockIP(context.Background(), ip))
}

// ---------------------------------------------------------------------------
// BlockPort / UnblockPort
// ---------------------------------------------------------------------------

func TestXDPManager_BlockPort(t *testing.T) {
	m := newTestXDPManager(t)

	require.NoError(t, m.BlockPort(context.Background(), 4444))
	assert.Contains(t, m.GetBlockedPorts(), uint16(4444))
}

func TestXDPManager_BlockPort_Idempotent(t *testing.T) {
	m := newTestXDPManager(t)
	require.NoError(t, m.BlockPort(context.Background(), 8080))
	require.NoError(t, m.BlockPort(context.Background(), 8080))
	assert.Len(t, m.GetBlockedPorts(), 1)
}

func TestXDPManager_UnblockPort(t *testing.T) {
	m := newTestXDPManager(t)
	require.NoError(t, m.BlockPort(context.Background(), 9999))
	require.NoError(t, m.UnblockPort(context.Background(), 9999))
	assert.Empty(t, m.GetBlockedPorts())
}

func TestXDPManager_UnblockPort_NotBlocked_Noop(t *testing.T) {
	m := newTestXDPManager(t)
	require.NoError(t, m.UnblockPort(context.Background(), 1234))
}

// ---------------------------------------------------------------------------
// BlockTuple
// ---------------------------------------------------------------------------

func TestXDPManager_BlockTuple_BothIPAndPort(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("203.0.113.1")

	require.NoError(t, m.BlockTuple(context.Background(), ip, 4444))
	assert.Contains(t, m.GetBlockedIPs(), "203.0.113.1")
	assert.Contains(t, m.GetBlockedPorts(), uint16(4444))
}

func TestXDPManager_BlockTuple_NilIP_PortOnly(t *testing.T) {
	m := newTestXDPManager(t)
	require.NoError(t, m.BlockTuple(context.Background(), nil, 31337))
	assert.Empty(t, m.GetBlockedIPs())
	assert.Contains(t, m.GetBlockedPorts(), uint16(31337))
}

func TestXDPManager_BlockTuple_ZeroPort_IPOnly(t *testing.T) {
	m := newTestXDPManager(t)
	ip := net.ParseIP("198.51.100.1")
	require.NoError(t, m.BlockTuple(context.Background(), ip, 0))
	assert.Contains(t, m.GetBlockedIPs(), "198.51.100.1")
	assert.Empty(t, m.GetBlockedPorts())
}

// ---------------------------------------------------------------------------
// Multiple distinct entries
// ---------------------------------------------------------------------------

func TestXDPManager_MultipleIPs(t *testing.T) {
	m := newTestXDPManager(t)
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, s := range ips {
		require.NoError(t, m.BlockIP(context.Background(), net.ParseIP(s)))
	}
	assert.Len(t, m.GetBlockedIPs(), 3)
	for _, s := range ips {
		assert.Contains(t, m.GetBlockedIPs(), s)
	}
}

func TestXDPManager_MultiplePorts(t *testing.T) {
	m := newTestXDPManager(t)
	ports := []uint16{80, 443, 8080, 9090}
	for _, p := range ports {
		require.NoError(t, m.BlockPort(context.Background(), p))
	}
	assert.Len(t, m.GetBlockedPorts(), 4)
}

// ---------------------------------------------------------------------------
// IsLoaded (always false in dry-run / stub mode)
// ---------------------------------------------------------------------------

func TestXDPManager_IsLoaded_DryRun(t *testing.T) {
	m := newTestXDPManager(t)
	assert.False(t, m.IsLoaded(), "dry-run mode must not report loaded")
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

func TestXDPManager_Close(t *testing.T) {
	m := newTestXDPManager(t)
	require.NoError(t, m.BlockIP(context.Background(), net.ParseIP("1.2.3.4")))
	require.NoError(t, m.Close())
	// After close, IsLoaded must be false.
	assert.False(t, m.IsLoaded())
}

// ---------------------------------------------------------------------------
// ipToKey helper
// ---------------------------------------------------------------------------

func TestIPToKey_IPv4(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	key := ipToKey(ip)
	assert.Equal(t, uint8(192), key[0])
	assert.Equal(t, uint8(168), key[1])
	assert.Equal(t, uint8(1), key[2])
	assert.Equal(t, uint8(1), key[3])
	// bytes 4-15 must be zero
	for i := 4; i < 16; i++ {
		assert.Equal(t, uint8(0), key[i], "byte %d must be 0 for IPv4", i)
	}
}

func TestIPToKey_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	key := ipToKey(ip)
	// First two bytes of 2001:db8::1 in big-endian
	assert.Equal(t, uint8(0x20), key[0])
	assert.Equal(t, uint8(0x01), key[1])
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestXDPManager_Concurrent(t *testing.T) {
	m := newTestXDPManager(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := net.ParseIP("10.0.0.1")
			_ = m.BlockIP(ctx, ip)
			_ = m.BlockPort(ctx, uint16(n+1))
			_ = m.GetBlockedIPs()
			_ = m.GetBlockedPorts()
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// loadBPF — graceful degradation when the BPF object is a compile-time stub
// ---------------------------------------------------------------------------

// TestXDPManager_LoadBPF_StubDegradesToLogOnly exercises loadBPF() itself.
//
// In this build internal/bpf.LoadXDPObjects is a hand-written stub that ALWAYS
// returns an error (no `make generate` / clang toolchain here), so constructing
// a manager with DryRun=false and a real interface ("lo") drives loadBPF() into
// its very first failure branch: LoadXDPObjects errors → warn logged → the
// method returns with loaded==false. The interface-lookup-failure and
// XDP-attach-failure branches inside loadBPF are UNREACHABLE without a real
// compiled BPF object and are a documented coverage ceiling (needs the BPF
// toolchain, out of scope here).
//
// The behavioural contract we assert is graceful degradation: the manager is
// still fully usable in log-only mode.
func TestXDPManager_LoadBPF_StubDegradesToLogOnly(t *testing.T) {
	m, err := NewXDPManager(testLogger(), XDPConfig{DryRun: false, Interface: "lo"})
	require.NoError(t, err, "constructor must not fail even when BPF load fails")

	// loadBPF was invoked (DryRun=false + non-empty Interface) but the stub
	// LoadXDPObjects failed, so the program must NOT be reported as loaded.
	assert.False(t, m.IsLoaded(), "stub BPF load must degrade to log-only (loaded=false)")
	require.Nil(t, m.objs, "objs must remain nil after failed load")
	require.Nil(t, m.xdpLink, "xdpLink must remain nil after failed load")

	// Log-only mode must still track blocks in memory.
	require.NoError(t, m.BlockIP(context.Background(), net.ParseIP("203.0.113.7")))
	require.NoError(t, m.BlockPort(context.Background(), 4444))
	assert.Contains(t, m.GetBlockedIPs(), "203.0.113.7")
	assert.Contains(t, m.GetBlockedPorts(), uint16(4444))

	// ReadStats returns zero values because nothing is loaded.
	agg, err := m.ReadStats()
	require.NoError(t, err)
	assert.Equal(t, uint64(0), agg.Dropped)

	require.NoError(t, m.Close())
}

// ---------------------------------------------------------------------------
// RegisterMetrics — real Prometheus registration and duplicate detection
// ---------------------------------------------------------------------------

func TestXDPManager_RegisterMetrics_Success(t *testing.T) {
	m := newTestXDPManager(t)
	reg := prometheus.NewRegistry()
	require.NoError(t, m.RegisterMetrics(reg))

	// All three collectors must actually be present in the registry.
	mfs, err := reg.Gather()
	require.NoError(t, err)
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	assert.True(t, names["ebpf_guard_xdp_dropped_total"], "dropped_total must be registered")
	assert.True(t, names["ebpf_guard_xdp_blocked_ips"], "blocked_ips gauge must be registered")
	assert.True(t, names["ebpf_guard_xdp_blocked_ports"], "blocked_ports gauge must be registered")
}

func TestXDPManager_RegisterMetrics_DuplicateFails(t *testing.T) {
	reg := prometheus.NewRegistry()

	m1 := newTestXDPManager(t)
	require.NoError(t, m1.RegisterMetrics(reg), "first registration must succeed")

	// A second manager exposes collectors with identical metric names; a shared
	// registry must reject the duplicate with a real AlreadyRegisteredError.
	m2 := newTestXDPManager(t)
	err := m2.RegisterMetrics(reg)
	require.Error(t, err, "duplicate metric registration must fail")

	var are prometheus.AlreadyRegisteredError
	assert.True(t, errors.As(err, &are),
		"error must be a Prometheus AlreadyRegisteredError, got %T: %v", err, err)
}

// ---------------------------------------------------------------------------
// isMapKeyNotFound — exact error-classification unit test
// ---------------------------------------------------------------------------

func TestIsMapKeyNotFound(t *testing.T) {
	assert.True(t, isMapKeyNotFound(ebpf.ErrKeyNotExist),
		"ErrKeyNotExist must be classified as key-not-found")
	assert.True(t, isMapKeyNotFound(fmtWrap(ebpf.ErrKeyNotExist)),
		"a wrapped ErrKeyNotExist must still be classified as key-not-found")
	assert.False(t, isMapKeyNotFound(errors.New("some other error")),
		"unrelated errors must not be classified as key-not-found")
	assert.False(t, isMapKeyNotFound(nil), "nil must not be classified as key-not-found")
}

// fmtWrap wraps an error so we can assert errors.Is traversal in isMapKeyNotFound.
func fmtWrap(err error) error {
	return errWrapper{err}
}

type errWrapper struct{ err error }

func (e errWrapper) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrapper) Unwrap() error { return e.err }

// ---------------------------------------------------------------------------
// Close — idempotency on a never-loaded manager (objs/xdpLink nil)
// ---------------------------------------------------------------------------

func TestXDPManager_Close_Idempotent_NeverLoaded(t *testing.T) {
	m := newTestXDPManager(t)
	require.Nil(t, m.objs)
	require.Nil(t, m.xdpLink)

	// First close on a never-loaded manager is a clean no-op.
	require.NoError(t, m.Close())
	assert.False(t, m.IsLoaded())

	// Second close must not panic on already-nil fields and must return nil.
	require.NoError(t, m.Close())
	assert.False(t, m.IsLoaded())
}
