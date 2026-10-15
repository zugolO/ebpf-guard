package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/bpf"
)

// Волна 8.6 B, Д14а / №563: блокирующая половина LSM. Что можно проверить без
// ядра — здесь; привязка и отказ ядра — смок на стенде (w86-lsm-smoke.sh).

type memMap struct {
	mu   sync.Mutex
	rows map[uint32]uint8
	fail bool
}

func newMemMap() *memMap { return &memMap{rows: map[uint32]uint8{}} }

func (m *memMap) Update(key, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("map update failed")
	}
	m.rows[key.(uint32)] = value.(uint8)
	return nil
}

func (m *memMap) Delete(key interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, key.(uint32))
	return nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

type lsmUpRecorder struct {
	mu  sync.Mutex
	ups []bool
}

func (u *lsmUpRecorder) SetUp(name string, up bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if name == "lsm" {
		u.ups = append(u.ups, up)
	}
}

func (u *lsmUpRecorder) last() (bool, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.ups) == 0 {
		return false, false
	}
	return u.ups[len(u.ups)-1], true
}

// loadedKmod — KmodCollector, у которого «загрузка» уже случилась (как после
// успешного EnsureLoaded на ядре): хуки привязаны по флагам.
func loadedKmod(t *testing.T, block bool, linked [3]bool) *KmodCollector {
	t.Helper()
	kc, err := NewKmodCollector(quietLogger())
	require.NoError(t, err)
	kc.available = true
	kc.WithBlockHooks(block)
	kc.loadOnce.Do(func() {})
	kc.kmodObjs = &bpf.KmodObjects{}
	kc.linked = linked
	return kc
}

func newLSM(t *testing.T) *LSMCollector {
	t.Helper()
	lc, err := NewLSMCollector(LSMConfig{Enabled: "auto"}, quietLogger())
	require.NoError(t, err)
	lc.available = true // как на ядре с lsm=bpf
	return lc
}

func TestLSMLoad_NoKmodBound_FailsLoudly(t *testing.T) {
	lc := newLSM(t)
	require.Error(t, lc.Load())
	assert.False(t, lc.IsAvailable())
	assert.False(t, lc.enforcing())
}

func TestLSMLoad_BlockHooksNotRequested_Inactive(t *testing.T) {
	lc := newLSM(t).BindKmod(loadedKmod(t, false, [3]bool{}))
	require.NoError(t, lc.Load())
	assert.False(t, lc.IsAvailable(), "block_backend != lsm: менеджер не активен")
	assert.False(t, lc.enforcing())
}

func TestLSMLoad_HooksNotAttached_Unavailable(t *testing.T) {
	// объект загружен, но file_open/socket_connect не привязаны (прежнее состояние №563)
	lc := newLSM(t).BindKmod(loadedKmod(t, true, [3]bool{false, false, true}))
	err := lc.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not attached")
	assert.False(t, lc.IsAvailable())
	assert.False(t, lc.enforcing())
}

func TestLSMLoad_HooksAttached_NeedsPolicyBeforeEnforcing(t *testing.T) {
	lc := newLSM(t).BindKmod(loadedKmod(t, true, [3]bool{true, true, true}))
	require.NoError(t, lc.Load())
	assert.True(t, lc.IsAvailable())
	assert.False(t, lc.enforcing(), "хуки привязаны, политика ещё не залита: collector_up{lsm} должен быть 0")
}

func TestLSMApplyPolicy_LoadsPathsAndGatesEnforcing(t *testing.T) {
	lc := newLSM(t)
	paths := newMemMap()
	lc.objs = &lsmObjects{LsmPathBlocklist: paths, LsmBlocklist: newMemMap(), LsmAgentWhitelist: newMemMap()}

	require.NoError(t, lc.ApplyPolicy([]string{"/root/w86/canary/blocked.txt", "/tmp//x/"}, bpf.NetworkBlocklistConfig{}))
	assert.True(t, lc.enforcing())
	assert.Contains(t, paths.rows, fnv32a("/root/w86/canary/blocked.txt"))
	assert.Contains(t, paths.rows, fnv32a("/tmp/x"), "путь чистится как в ядре: FNV от filepath.Clean")
	assert.NotContains(t, paths.rows, fnv32a("/root/w86/canary/neighbour.txt"), "соседний файл не заблокирован")

	// Перезагрузка политики снимает прежние пути конфига.
	require.NoError(t, lc.ApplyPolicy([]string{"/etc/only"}, bpf.NetworkBlocklistConfig{}))
	assert.NotContains(t, paths.rows, fnv32a("/root/w86/canary/blocked.txt"))
	assert.Contains(t, paths.rows, fnv32a("/etc/only"))

	// Отказ карты — политика не загружена, collector_up{lsm} падает в 0.
	paths.fail = true
	require.Error(t, lc.ApplyPolicy([]string{"/etc/other"}, bpf.NetworkBlocklistConfig{}))
	assert.False(t, lc.enforcing())
}

func TestLSMApplyPolicy_NetworkConfiguredWithoutMaps_IsAnError(t *testing.T) {
	lc := newLSM(t)
	lc.objs = &lsmObjects{LsmPathBlocklist: newMemMap()}
	err := lc.ApplyPolicy(nil, bpf.NetworkBlocklistConfig{Ports: []uint16{19777}})
	require.Error(t, err, "network_blocklist задан, а карт net_block_* нет — молча терять нельзя")
	assert.False(t, lc.enforcing())
}

func TestLSMStart_CollectorUpFollowsEnforcing(t *testing.T) {
	run := func(lc *LSMCollector) (bool, bool) {
		rec := &lsmUpRecorder{}
		lc.WithStatusReporter(rec)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = lc.Start(ctx, nil); close(done) }()
		require.Eventually(t, func() bool { _, ok := rec.last(); return ok }, time.Second, 5*time.Millisecond)
		up, ok := rec.last()
		cancel()
		<-done
		return up, ok
	}

	// Хуки привязаны, политики нет → 0.
	lc := newLSM(t)
	lc.objs = &lsmObjects{LsmPathBlocklist: newMemMap()}
	up, _ := run(lc)
	assert.False(t, up)

	// Хуки привязаны, политика залита → 1.
	lc2 := newLSM(t)
	lc2.objs = &lsmObjects{LsmPathBlocklist: newMemMap()}
	require.NoError(t, lc2.ApplyPolicy([]string{"/x"}, bpf.NetworkBlocklistConfig{}))
	up, _ = run(lc2)
	assert.True(t, up)

	// Ядро без LSM (stub) → 0, как и раньше (№457).
	stub, err := NewLSMCollector(LSMConfig{Enabled: "false"}, quietLogger())
	require.NoError(t, err)
	up, _ = run(stub)
	assert.False(t, up)
}

func lsmAuditRecord(action, hook uint8, path string) []byte {
	raw := make([]byte, lsmAuditEventSize)
	binary.LittleEndian.PutUint32(raw[0:4], 11) // EVENT_TYPE_LSM_AUDIT
	binary.LittleEndian.PutUint32(raw[12:16], 4242)
	raw[24], raw[25] = action, hook
	copy(raw[27:43], "cat\x00")
	copy(raw[43:107], path+"\x00")
	return raw
}

// Счётчик lsm_block — отказы ядра: растёт на deny file_open/socket_connect и
// молчит на аудите task_kill (action=0) и на разрешённых событиях.
func TestKmodCollector_DenyObserverCountsKernelRefusalsOnly(t *testing.T) {
	kc, err := NewKmodCollector(quietLogger())
	require.NoError(t, err)
	var hooks []string
	kc.WithLSMDenyObserver(func(h string) { hooks = append(hooks, h) })

	for _, raw := range [][]byte{
		lsmAuditRecord(1, 0, "/root/w86/canary/blocked.txt"), // deny file_open
		lsmAuditRecord(1, 1, ""),                             // deny socket_connect
		lsmAuditRecord(0, 2, ""),                             // audit task_kill
	} {
		ev, err := kc.parseKmodOrFallback(raw)
		require.NoError(t, err)
		assert.Nil(t, ev)
	}
	assert.Equal(t, []string{"file_open", "socket_connect"}, hooks)
}

// Агент вносится в whitelist ДО привязки, привязка идёт только при block_backend: lsm.
func TestKmodCollector_AttachBlockHooksOnlyWhenRequested(t *testing.T) {
	kc, err := NewKmodCollector(quietLogger())
	require.NoError(t, err)
	calls := 0
	kc.attachBlock = func() { calls++ }
	kc.kmodObjs = &bpf.KmodObjects{}
	// loadKmod ходит в настоящий загрузчик; здесь проверяется только решение «привязывать».
	if kc.blockHooks {
		kc.attachBlockHooks()
	}
	assert.Zero(t, calls, "без WithBlockHooks блокирующие хуки не привязываются")
	kc.WithBlockHooks(true)
	if kc.blockHooks {
		kc.attachBlockHooks()
	}
	assert.Equal(t, 1, calls)
	assert.False(t, kc.blockHooksAttached(), "заглушка привязки флагов не ставит")
}

func TestKmodEnsureLoaded_NoLSMKernel(t *testing.T) {
	kc, err := NewKmodCollector(quietLogger())
	require.NoError(t, err)
	kc.available = false
	assert.ErrorIs(t, kc.EnsureLoaded(), errLSMUnavailable)
}

// Мутационный страж: путь в политике хэшируется ровно так, как хэширует ядро
// (FNV-32a от Clean), — иначе блок молча не сработает.
func TestFNV32aMatchesKernelHelperForCanary(t *testing.T) {
	p := filepath.Clean("/root/w86/canary/blocked.txt")
	h := uint32(2166136261)
	for i := 0; i < len(p); i++ {
		h ^= uint32(p[i])
		h *= 16777619
	}
	assert.Equal(t, h, fnv32a("/root/w86/canary/blocked.txt"))
}
