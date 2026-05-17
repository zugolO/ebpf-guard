package correlator

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewMiningPoolDetector(t *testing.T) {
	// Create a temporary file with test data
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	content := `# Test mining pools
192.0.2.0/24         # Test documentation range
198.51.100.0/24      # Another test range
pool.example.com     # Test pool domain
xmr.example.org      # Another test domain
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	// Check counts
	if count := detector.GetPoolCount(); count != 4 {
		t.Errorf("expected 4 pools, got %d", count)
	}
	if count := detector.GetDomainCount(); count != 2 {
		t.Errorf("expected 2 domains, got %d", count)
	}
}

func TestMiningPoolDetector_IsMiningPoolIP(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	// 10.0.0.0/8 is RFC-1918 and will be silently rejected by the loader.
	// Use 198.51.100.0/24 (TEST-NET-2, public documentation range) instead.
	content := `192.0.2.0/24
198.51.100.0/24
2001:db8::/32
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IP in 192.0.2.0/24", "192.0.2.100", true},
		{"IP at start of range", "192.0.2.0", true},
		{"IP at end of range", "192.0.2.255", true},
		{"IP in 198.51.100.0/24", "198.51.100.1", true},
		{"IP not in any range", "8.8.8.8", false},
		{"Invalid IP", "invalid", false},
		{"Empty IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.IsMiningPoolIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsMiningPoolIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestMiningPoolDetector_IsMiningPoolDomain(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	content := `pool.example.com
xmr.test.org
MINING.POOL.NET
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{"Exact match", "pool.example.com", true},
		{"Different case", "POOL.EXAMPLE.COM", true},
		{"Subdomain match", "us.pool.example.com", true},
		{"Another exact match", "xmr.test.org", true},
		{"Not a mining pool", "google.com", false},
		{"Empty domain", "", false},
		{"Partial match not enough", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.IsMiningPoolDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("IsMiningPoolDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestMiningPoolDetector_IsMiningPool(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	content := `192.0.2.0/24
pool.example.com
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	tests := []struct {
		name     string
		ip       string
		domain   string
		expected bool
	}{
		{"IP match only", "192.0.2.100", "", true},
		{"Domain match only", "", "pool.example.com", true},
		{"Both match", "192.0.2.100", "pool.example.com", true},
		{"Neither match", "8.8.8.8", "google.com", false},
		{"Empty both", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.IsMiningPool(tt.ip, tt.domain)
			if result != tt.expected {
				t.Errorf("IsMiningPool(%q, %q) = %v, want %v", tt.ip, tt.domain, result, tt.expected)
			}
		})
	}
}

func TestMiningPoolDetector_Reload(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	// Initial content
	content1 := `192.0.2.0/24
pool.example.com
`
	if err := os.WriteFile(testFile, []byte(content1), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	if count := detector.GetPoolCount(); count != 2 {
		t.Errorf("expected 2 pools after initial load, got %d", count)
	}

	// Wait a bit to ensure different timestamp
	time.Sleep(10 * time.Millisecond)

	// Update content
	content2 := `198.51.100.0/24
xmr.test.org
another.pool.com
`
	if err := os.WriteFile(testFile, []byte(content2), 0644); err != nil {
		t.Fatalf("failed to update test file: %v", err)
	}

	// Reload
	if err := detector.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if count := detector.GetPoolCount(); count != 3 {
		t.Errorf("expected 3 pools after reload, got %d", count)
	}

	// Check that old entries are gone
	if detector.IsMiningPoolIP("192.0.2.100") {
		t.Error("old IP should not be in pools after reload")
	}

	// Check that new entries are present
	if !detector.IsMiningPoolIP("198.51.100.50") {
		t.Error("new IP should be in pools after reload")
	}
}

func TestMiningPoolDetector_FileNotFound(t *testing.T) {
	_, err := NewMiningPoolDetector("/nonexistent/path/pools.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestMiningPoolDetector_GetLastReload(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	if err := os.WriteFile(testFile, []byte("192.0.2.0/24\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	before := time.Now()
	detector, err := NewMiningPoolDetector(testFile)
	after := time.Now()

	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	reloadTime := detector.GetLastReload()
	if reloadTime.Before(before) || reloadTime.After(after) {
		t.Error("GetLastReload returned unexpected time")
	}
}

func TestMiningPoolDetector_GetAllPools(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	content := `192.0.2.0/24
pool.example.com
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	pools := detector.GetAllPools()
	if len(pools) != 2 {
		t.Errorf("expected 2 pools, got %d", len(pools))
	}

	// Verify the copy is independent
	pools[0].Value = "modified"
	if detector.pools[0].Value == "modified" {
		t.Error("GetAllPools should return a copy, not the original slice")
	}
}

func TestIsKnownMiningPort(t *testing.T) {
	tests := []struct {
		port     uint16
		expected bool
	}{
		{3333, true},
		{4444, true},
		{8080, true},
		{14444, true},
		{80, false},
		{443, false},
		{22, false},
		{0, false},
		{65535, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("port_%d", tt.port), func(t *testing.T) {
			result := IsKnownMiningPort(tt.port)
			if result != tt.expected {
				t.Errorf("IsKnownMiningPort(%d) = %v, want %v", tt.port, result, tt.expected)
			}
		})
	}
}

func TestIsKnownMiningProcess(t *testing.T) {
	tests := []struct {
		name     string
		comm     string
		expected bool
	}{
		{"xmrig exact", "xmrig", true},
		{"XMRIG uppercase", "XMRIG", true},
		{"xmrig with suffix", "xmrig-worker1", true},
		{"minerd", "minerd", true},
		{"cgminer", "cgminer", true},
		{"ethminer", "ethminer", true},
		{"normal process", "nginx", false},
		{"empty", "", false},
		{"bash", "bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKnownMiningProcess(tt.comm)
			if result != tt.expected {
				t.Errorf("IsKnownMiningProcess(%q) = %v, want %v", tt.comm, result, tt.expected)
			}
		})
	}
}

func TestKnownMiningPortsNotEmpty(t *testing.T) {
	if len(KnownMiningPorts) == 0 {
		t.Error("KnownMiningPorts should not be empty")
	}
}

func TestKnownMiningProcessNamesNotEmpty(t *testing.T) {
	if len(KnownMiningProcessNames) == 0 {
		t.Error("KnownMiningProcessNames should not be empty")
	}
}

// BenchmarkMiningPoolDetector_IsMiningPoolIP benchmarks IP lookups.
func BenchmarkMiningPoolDetector_IsMiningPoolIP(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	// Use public documentation ranges (not RFC-1918) so they are accepted by the loader.
	content := ""
	for i := 0; i < 100; i++ {
		content += fmt.Sprintf("203.0.%d.0/24\n", i)
	}
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		b.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		b.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.IsMiningPoolIP("203.0.50.1")
	}
}

// BenchmarkMiningPoolDetector_IsMiningPoolDomain benchmarks domain lookups.
func BenchmarkMiningPoolDetector_IsMiningPoolDomain(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "test-pools.txt")

	// Create file with many domains
	content := ""
	for i := 0; i < 100; i++ {
		content += fmt.Sprintf("pool%d.example.com\n", i)
	}
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		b.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		b.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.IsMiningPoolDomain("pool50.example.com")
	}
}

// TestMiningPoolConcurrentReload verifies that two simultaneous Reload() calls
// do not panic and leave the detector in a consistent state (Sprint 27.0 Part D).
func TestMiningPoolConcurrentReload(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "pools.txt")

	content := "pool.example.com\n192.0.2.0/24\n"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = detector.Reload()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d Reload() returned error: %v", i, err)
		}
	}

	// Detector must still be functional after concurrent reloads.
	if !detector.IsMiningPoolDomain("pool.example.com") {
		t.Error("IsMiningPoolDomain returned false after concurrent reloads")
	}
	if count := detector.GetPoolCount(); count == 0 {
		t.Error("pool count is 0 after concurrent reloads")
	}
}

// TestMiningPoolDetector_RFC1918Rejected verifies that RFC-1918 and loopback
// CIDR ranges are silently skipped and never added to the blocklist.
func TestMiningPoolDetector_RFC1918Rejected(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "pools.txt")

	// All of these must be rejected by the loader.
	content := `127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
::1/128
fc00::/7
192.0.2.0/24
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	detector, err := NewMiningPoolDetector(testFile)
	if err != nil {
		t.Fatalf("NewMiningPoolDetector failed: %v", err)
	}

	// Only 192.0.2.0/24 (public documentation range) should be accepted.
	if count := detector.GetPoolCount(); count != 1 {
		t.Errorf("expected 1 pool (public range only), got %d", count)
	}

	// Private IPs must not be flagged as mining pool IPs.
	privateIPs := []string{
		"127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1",
	}
	for _, ip := range privateIPs {
		if detector.IsMiningPoolIP(ip) {
			t.Errorf("RFC-1918 IP %s should not be detected as mining pool", ip)
		}
	}

	// The public documentation IP must still be detected.
	if !detector.IsMiningPoolIP("192.0.2.50") {
		t.Error("public range 192.0.2.50 should be detected as mining pool")
	}
}
