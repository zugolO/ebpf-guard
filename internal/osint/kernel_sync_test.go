package osint

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/config"
)

// fakeBlocklist is a thread-safe in-memory BlocklistUpdater for tests.
type fakeBlocklist struct {
	mu      sync.Mutex
	subnets map[string]bool
	addErr  error
	rmErr   error
}

func newFakeBlocklist() *fakeBlocklist {
	return &fakeBlocklist{subnets: make(map[string]bool)}
}

func (f *fakeBlocklist) AddSubnet(cidr string) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subnets[cidr] = true
	return nil
}

func (f *fakeBlocklist) RemoveSubnet(cidr string) error {
	if f.rmErr != nil {
		return f.rmErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.subnets, cidr)
	return nil
}

func (f *fakeBlocklist) Has(cidr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subnets[cidr]
}

func (f *fakeBlocklist) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subnets)
}

// newTestSyncer returns a KernelSyncer backed by a fresh Prometheus registry
// so tests don't collide on the default registry.
func newTestSyncer(t *testing.T, updater BlocklistUpdater, maxEntries int) *KernelSyncer {
	t.Helper()
	reg := prometheus.NewRegistry()
	ks, err := NewKernelSyncer(KernelSyncerConfig{
		Updater:    updater,
		MaxEntries: maxEntries,
		Registerer: reg,
	})
	if err != nil {
		t.Fatalf("NewKernelSyncer: %v", err)
	}
	return ks
}

func makeResult(src Source, iocs []IoC) FeedResult {
	return FeedResult{
		Source:    src,
		IoCs:      iocs,
		FetchedAt: time.Now().UTC(),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// NewKernelSyncer construction
// ────────────────────────────────────────────────────────────────────────────

func TestNewKernelSyncer_NilUpdater(t *testing.T) {
	reg := prometheus.NewRegistry()
	ks, err := NewKernelSyncer(KernelSyncerConfig{
		Updater:    nil,
		Registerer: reg,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ks == nil {
		t.Fatal("expected non-nil syncer")
	}
	// SyncToKernel with nil updater must be a no-op.
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, []IoC{{Value: "1.2.3.4", Type: IoCTypeIP}})})
	if err != nil {
		t.Errorf("nil updater: unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("nil updater: want 0 active entries, got %d", n)
	}
}

func TestNewKernelSyncer_DefaultMaxEntries(t *testing.T) {
	reg := prometheus.NewRegistry()
	ks, err := NewKernelSyncer(KernelSyncerConfig{
		Updater:    newFakeBlocklist(),
		MaxEntries: 0, // should default to 100 000
		Registerer: reg,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ks.maxEntries != defaultMaxKernelEntries {
		t.Errorf("maxEntries: want %d, got %d", defaultMaxKernelEntries, ks.maxEntries)
	}
}

func TestNewKernelSyncer_MetricRegistrationConflict(t *testing.T) {
	reg := prometheus.NewRegistry()
	// Register once.
	_, err := NewKernelSyncer(KernelSyncerConfig{Registerer: reg})
	if err != nil {
		t.Fatalf("first registration: %v", err)
	}
	// Register again on the same registry — AlreadyRegisteredError must be ignored.
	_, err = NewKernelSyncer(KernelSyncerConfig{Registerer: reg})
	if err != nil {
		t.Fatalf("second registration should not fail: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: IP IoCs
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_IPv4(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{
		{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.9},
		{Value: "5.6.7.8", Type: IoCTypeIP, ThreatScore: 0.8},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 active entries, got %d", n)
	}
	if !bl.Has("1.2.3.4/32") {
		t.Error("expected 1.2.3.4/32 in blocklist")
	}
	if !bl.Has("5.6.7.8/32") {
		t.Error("expected 5.6.7.8/32 in blocklist")
	}
}

func TestSyncToKernel_IPv6(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{
		{Value: "2001:db8::1", Type: IoCTypeIP, ThreatScore: 0.7},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 active entry, got %d", n)
	}
	if !bl.Has("2001:db8::1/128") {
		t.Error("expected 2001:db8::1/128 in blocklist")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: CIDR IoCs
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_CIDR(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{
		{Value: "10.0.0.0/8", Type: IoCTypeCIDR, ThreatScore: 0.6},
		{Value: "192.168.1.0/24", Type: IoCTypeCIDR, ThreatScore: 0.5},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceOpenCTI, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 active entries, got %d", n)
	}
	if !bl.Has("10.0.0.0/8") {
		t.Error("expected 10.0.0.0/8 in blocklist")
	}
	if !bl.Has("192.168.1.0/24") {
		t.Error("expected 192.168.1.0/24 in blocklist")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: domain / URL IoCs are skipped
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_DomainsSkipped(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{
		{Value: "evil.com", Type: IoCTypeDomain, ThreatScore: 0.9},
		{Value: "http://phish.io/payload", Type: IoCTypeURL, ThreatScore: 0.8},
		{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.7},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	// Only the IP should be in the kernel map.
	if n != 1 {
		t.Errorf("want 1 active entry (only IP), got %d", n)
	}
	if bl.Has("evil.com") || bl.Has("http://phish.io/payload") {
		t.Error("domain/URL must not appear in the kernel blocklist")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: deduplication across multiple FeedResults
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_Dedup(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	ip := "1.2.3.4"
	results := []FeedResult{
		makeResult(SourceMISP, []IoC{{Value: ip, Type: IoCTypeIP, ThreatScore: 0.8}}),
		makeResult(SourceOpenCTI, []IoC{{Value: ip, Type: IoCTypeIP, ThreatScore: 0.9}}),
	}
	n, err := ks.SyncToKernel(results)
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 (deduped), got %d", n)
	}
	if bl.Count() != 1 {
		t.Errorf("blocklist has %d entries, want 1", bl.Count())
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: max entries cap
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_MaxEntries(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 3)

	// 5 IPs, scores descending so we know which 3 win.
	iocs := []IoC{
		{Value: "1.1.1.1", Type: IoCTypeIP, ThreatScore: 0.9},
		{Value: "2.2.2.2", Type: IoCTypeIP, ThreatScore: 0.8},
		{Value: "3.3.3.3", Type: IoCTypeIP, ThreatScore: 0.7},
		{Value: "4.4.4.4", Type: IoCTypeIP, ThreatScore: 0.2},
		{Value: "5.5.5.5", Type: IoCTypeIP, ThreatScore: 0.1},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 3 {
		t.Errorf("want 3 (capped), got %d", n)
	}
	if !bl.Has("1.1.1.1/32") || !bl.Has("2.2.2.2/32") || !bl.Has("3.3.3.3/32") {
		t.Error("top-3 highest-scored IPs should be present")
	}
	if bl.Has("4.4.4.4/32") || bl.Has("5.5.5.5/32") {
		t.Error("lowest-scored IPs should have been evicted by the cap")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: hot-reload — stale entries are removed
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_HotReload(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	// First sync: add two IPs.
	r1 := makeResult(SourceMISP, []IoC{
		{Value: "1.1.1.1", Type: IoCTypeIP, ThreatScore: 0.9},
		{Value: "2.2.2.2", Type: IoCTypeIP, ThreatScore: 0.8},
	})
	n, err := ks.SyncToKernel([]FeedResult{r1})
	if err != nil || n != 2 {
		t.Fatalf("first sync: n=%d err=%v", n, err)
	}

	// Second sync: remove 1.1.1.1, add 3.3.3.3.
	r2 := makeResult(SourceMISP, []IoC{
		{Value: "2.2.2.2", Type: IoCTypeIP, ThreatScore: 0.8},
		{Value: "3.3.3.3", Type: IoCTypeIP, ThreatScore: 0.7},
	})
	n, err = ks.SyncToKernel([]FeedResult{r2})
	if err != nil || n != 2 {
		t.Fatalf("second sync: n=%d err=%v", n, err)
	}

	if bl.Has("1.1.1.1/32") {
		t.Error("1.1.1.1/32 should have been removed on hot-reload")
	}
	if !bl.Has("2.2.2.2/32") {
		t.Error("2.2.2.2/32 should still be present")
	}
	if !bl.Has("3.3.3.3/32") {
		t.Error("3.3.3.3/32 should have been added")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: invalid IP/CIDR values are silently skipped
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_InvalidIPSkipped(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{
		{Value: "not-an-ip", Type: IoCTypeIP, ThreatScore: 0.9},
		{Value: "300.400.500.600", Type: IoCTypeIP, ThreatScore: 0.8},
		{Value: "not-a-cidr/x", Type: IoCTypeCIDR, ThreatScore: 0.7},
		{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.5},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 valid entry, got %d", n)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: AddSubnet error is tolerated (partial sync)
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_AddSubnetError(t *testing.T) {
	bl := newFakeBlocklist()
	bl.addErr = fmt.Errorf("map full")
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.9}}
	_, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err == nil {
		t.Error("expected error when AddSubnet fails")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: RemoveSubnet error is tolerated (partial sync)
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_RemoveSubnetError(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	// First sync adds an entry successfully.
	r1 := makeResult(SourceMISP, []IoC{{Value: "1.1.1.1", Type: IoCTypeIP, ThreatScore: 0.9}})
	_, _ = ks.SyncToKernel([]FeedResult{r1})

	// Inject a remove error.
	bl.rmErr = fmt.Errorf("map locked")

	// Second sync should try to remove "1.1.1.1/32" and fail.
	r2 := makeResult(SourceMISP, []IoC{{Value: "2.2.2.2", Type: IoCTypeIP, ThreatScore: 0.8}})
	_, err := ks.SyncToKernel([]FeedResult{r2})
	if err == nil {
		t.Error("expected error when RemoveSubnet fails")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: empty results are a no-op
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_EmptyResults(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	n, err := ks.SyncToKernel(nil)
	if err != nil {
		t.Fatalf("empty results: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0, got %d", n)
	}
	if bl.Count() != 0 {
		t.Errorf("blocklist should be empty")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: idempotent — syncing the same set twice doesn't double-add
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_Idempotent(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	r := makeResult(SourceMISP, []IoC{{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.9}})

	n1, _ := ks.SyncToKernel([]FeedResult{r})
	n2, _ := ks.SyncToKernel([]FeedResult{r})

	if n1 != n2 {
		t.Errorf("idempotent: n changed from %d to %d", n1, n2)
	}
	if bl.Count() != 1 {
		t.Errorf("idempotent: expected 1 entry, got %d", bl.Count())
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: CIDR normalisation (host bits zeroed by net.ParseCIDR)
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_CIDRNormalisation(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	// 192.168.1.5/24 normalises to 192.168.1.0/24.
	iocs := []IoC{{Value: "192.168.1.5/24", Type: IoCTypeCIDR, ThreatScore: 0.6}}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1, got %d", n)
	}
	if !bl.Has("192.168.1.0/24") {
		t.Errorf("expected normalised CIDR 192.168.1.0/24 in blocklist; got: %v", bl.subnets)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// SyncToKernel: dedup keeps highest ThreatScore
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_DedupScoreMax(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 2)

	// 3 IoCs with the same IP at different scores; only 2 unique IPs after dedup.
	// After capping to 2, the highest-score pair should win.
	iocs := []IoC{
		{Value: "1.1.1.1", Type: IoCTypeIP, ThreatScore: 0.5},
		{Value: "1.1.1.1", Type: IoCTypeIP, ThreatScore: 0.9}, // same IP, higher score
		{Value: "2.2.2.2", Type: IoCTypeIP, ThreatScore: 0.4},
		{Value: "3.3.3.3", Type: IoCTypeIP, ThreatScore: 0.1},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	// 3 unique IPs, capped to 2: 1.1.1.1 (score 0.9) + 2.2.2.2 (score 0.4).
	if n != 2 {
		t.Errorf("want 2, got %d", n)
	}
	if !bl.Has("1.1.1.1/32") {
		t.Error("highest-scored IP (1.1.1.1) should be present")
	}
	if !bl.Has("2.2.2.2/32") {
		t.Error("second-scored IP (2.2.2.2) should be present")
	}
	if bl.Has("3.3.3.3/32") {
		t.Error("lowest-scored IP (3.3.3.3) should have been evicted")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// ActiveCount
// ────────────────────────────────────────────────────────────────────────────

func TestKernelSyncer_ActiveCount(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	if ks.ActiveCount() != 0 {
		t.Errorf("want 0 before any sync, got %d", ks.ActiveCount())
	}

	iocs := []IoC{
		{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.9},
		{Value: "5.6.7.8", Type: IoCTypeIP, ThreatScore: 0.8},
	}
	ks.SyncToKernel([]FeedResult{makeResult(SourceMISP, iocs)}) //nolint:errcheck

	if ks.ActiveCount() != 2 {
		t.Errorf("want 2 after sync, got %d", ks.ActiveCount())
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Concurrency: parallel SyncToKernel calls are safe
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_ConcurrentSafe(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.9}}
	r := makeResult(SourceMISP, iocs)

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			ks.SyncToKernel([]FeedResult{r}) //nolint:errcheck
		}()
	}
	wg.Wait()

	if ks.ActiveCount() != 1 {
		t.Errorf("concurrent sync: expected 1 active entry, got %d", ks.ActiveCount())
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Mixed IP + CIDR + domain in one result
// ────────────────────────────────────────────────────────────────────────────

func TestSyncToKernel_MixedIoCTypes(t *testing.T) {
	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)

	iocs := []IoC{
		{Value: "10.0.0.0/8", Type: IoCTypeCIDR, ThreatScore: 0.8},
		{Value: "1.2.3.4", Type: IoCTypeIP, ThreatScore: 0.9},
		{Value: "evil.com", Type: IoCTypeDomain, ThreatScore: 1.0},
		{Value: "http://c2.example.com/shell", Type: IoCTypeURL, ThreatScore: 0.95},
	}
	n, err := ks.SyncToKernel([]FeedResult{makeResult(SourceVirusTotal, iocs)})
	if err != nil {
		t.Fatalf("SyncToKernel: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 kernel entries (IP + CIDR), got %d", n)
	}
	if !bl.Has("1.2.3.4/32") || !bl.Has("10.0.0.0/8") {
		t.Error("expected IP and CIDR entries in blocklist")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Manager: WithKernelSyncer wires the syncer and calls it on sync
// ────────────────────────────────────────────────────────────────────────────

func TestManager_WithKernelSyncer(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(osintCfgForTest(dir))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	bl := newFakeBlocklist()
	ks := newTestSyncer(t, bl, 0)
	m.WithKernelSyncer(ks)

	if m.kernelSyncer != ks {
		t.Error("kernelSyncer not set")
	}
}

func TestManager_WithKernelSyncer_NilManager(t *testing.T) {
	// Calling WithKernelSyncer on a nil Manager must not panic.
	var m *Manager
	bl := newFakeBlocklist()
	reg := prometheus.NewRegistry()
	ks, _ := NewKernelSyncer(KernelSyncerConfig{Updater: bl, Registerer: reg})
	result := m.WithKernelSyncer(ks)
	if result != nil {
		t.Errorf("expected nil for nil receiver, got non-nil")
	}
}

func TestManager_WithKernelSyncer_NilSyncer(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(osintCfgForTest(dir))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// Passing nil should not panic.
	m.WithKernelSyncer(nil)
	if m.kernelSyncer != nil {
		t.Error("kernelSyncer should remain nil")
	}
}

// ────────────────────────────────────────────────────────────────────────────
// buildDesiredSet (internal)
// ────────────────────────────────────────────────────────────────────────────

func TestBuildDesiredSet_Empty(t *testing.T) {
	reg := prometheus.NewRegistry()
	ks, _ := NewKernelSyncer(KernelSyncerConfig{Registerer: reg})
	set, err := ks.buildDesiredSet(nil)
	if err != nil {
		t.Fatalf("buildDesiredSet: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("expected empty set, got %v", set)
	}
}

func TestBuildDesiredSet_OnlyDomains(t *testing.T) {
	reg := prometheus.NewRegistry()
	ks, _ := NewKernelSyncer(KernelSyncerConfig{Registerer: reg})
	iocs := []IoC{
		{Value: "evil.com", Type: IoCTypeDomain},
		{Value: "http://x.io/y", Type: IoCTypeURL},
	}
	set, err := ks.buildDesiredSet([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("buildDesiredSet: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("domains/URLs must not appear in desired set; got %v", set)
	}
}

func TestBuildDesiredSet_Cap(t *testing.T) {
	reg := prometheus.NewRegistry()
	ks, _ := NewKernelSyncer(KernelSyncerConfig{MaxEntries: 2, Registerer: reg})

	var iocs []IoC
	for i := 0; i < 5; i++ {
		iocs = append(iocs, IoC{
			Value:       fmt.Sprintf("%d.%d.%d.%d", i+1, i+1, i+1, i+1),
			Type:        IoCTypeIP,
			ThreatScore: float64(i) / 10.0,
		})
	}
	set, err := ks.buildDesiredSet([]FeedResult{makeResult(SourceMISP, iocs)})
	if err != nil {
		t.Fatalf("buildDesiredSet: %v", err)
	}
	if len(set) != 2 {
		t.Errorf("expected 2 entries (capped), got %d: %v", len(set), set)
	}
	// Highest score is 0.4 (index 4) → 5.5.5.5; next is 0.3 (index 3) → 4.4.4.4.
	for cidr := range set {
		if !strings.HasSuffix(cidr, "/32") {
			t.Errorf("unexpected CIDR format: %q", cidr)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Config field: SyncToKernelMaps / MaxKernelEntries
// ────────────────────────────────────────────────────────────────────────────

func TestOSINTConfig_NewFields(t *testing.T) {
	cfg := osintCfgForTest(t.TempDir())
	cfg.SyncToKernelMaps = true
	cfg.MaxKernelEntries = 50_000

	if !cfg.SyncToKernelMaps {
		t.Error("SyncToKernelMaps should be settable")
	}
	if cfg.MaxKernelEntries != 50_000 {
		t.Errorf("MaxKernelEntries: got %d", cfg.MaxKernelEntries)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

// osintCfgForTest returns a minimal OSINTConfig suitable for Manager construction.
func osintCfgForTest(dir string) config.OSINTConfig {
	return config.OSINTConfig{
		Enabled:        true,
		OutputDir:      dir,
		MaxIoCsPerRule: 10,
	}
}
