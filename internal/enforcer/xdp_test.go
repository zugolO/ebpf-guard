package enforcer

import (
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
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
