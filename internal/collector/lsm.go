// lsm.go — eBPF LSM hook collectors
//
// LSMCollector  (Sprint 22.0): loads file_open / socket_connect / task_kill
//   hooks for pre-execution enforcement.
// KmodCollector (Sprint 33.0): reads kernel_module_request / kernel_read_file
//   and cgroup_attach_task events and forwards them to the correlation engine.

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/audit"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fnv32a returns the FNV-1a 32-bit hash of s. This must produce the same
// output as the fnv32a() BPF helper in bpf/lsm.bpf.c so that paths added
// via AddPathToBlocklist map correctly to what the kernel checks.
func fnv32a(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// lsmAuditEventRaw mirrors struct lsm_audit_event from bpf/common.h.
// The struct is __attribute__((packed)), so fields are at fixed byte offsets with no padding.
// Layout (107 bytes total):
//
//	type(4) + timestamp_ns(8) + pid(4) + target_pid(4) + uid(4) +
//	action(1) + hook(1) + sig(1) + comm(16) + path(64)
type lsmAuditEventRaw struct {
	Type      uint32
	Timestamp uint64
	PID       uint32
	TargetPID uint32
	UID       uint32
	Action    uint8
	Hook      uint8
	Sig       uint8
	Comm      [16]byte
	Path      [64]byte
}

// lsmAuditEventSize is derived from the Go mirror (№477); wire_size_test.go pins 107.
var lsmAuditEventSize = binary.Size(lsmAuditEventRaw{})

var lsmHookNames = [3]string{"file_open", "socket_connect", "task_kill"}

// parseLSMAuditEventRaw deserialises a raw ring-buffer record into lsmAuditEventRaw.
func parseLSMAuditEventRaw(raw []byte) (lsmAuditEventRaw, error) {
	if len(raw) < lsmAuditEventSize {
		return lsmAuditEventRaw{}, fmt.Errorf("lsm_audit_event too short: %d < %d", len(raw), lsmAuditEventSize)
	}
	var e lsmAuditEventRaw
	e.Type = binary.LittleEndian.Uint32(raw[0:4])
	e.Timestamp = binary.LittleEndian.Uint64(raw[4:12])
	e.PID = binary.LittleEndian.Uint32(raw[12:16])
	e.TargetPID = binary.LittleEndian.Uint32(raw[16:20])
	e.UID = binary.LittleEndian.Uint32(raw[20:24])
	e.Action = raw[24]
	e.Hook = raw[25]
	e.Sig = raw[26]
	copy(e.Comm[:], raw[27:43])
	copy(e.Path[:], raw[43:107])
	return e, nil
}

// toAuditEntry converts a parsed LSM audit event into an audit.Entry for the JSONL log.
func (e lsmAuditEventRaw) toAuditEntry() audit.Entry {
	hookName := "unknown"
	if int(e.Hook) < len(lsmHookNames) {
		hookName = lsmHookNames[e.Hook]
	}
	action := "audit"
	if e.Action == 1 { // LSM_ACTION_DENY
		action = "deny"
	}
	return audit.Entry{
		TS:        time.Now(),
		Action:    action,
		PID:       e.PID,
		Rule:      "lsm_audit",
		Comm:      nullTermString(e.Comm[:]),
		Enforced:  e.Action == 1,
		Hook:      hookName,
		TargetPID: e.TargetPID,
		Path:      nullTermString(e.Path[:]),
		UID:       e.UID,
	}
}

// nullTermString converts a NUL-padded byte slice to a Go string.
func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// LSMConfig holds configuration for the LSM collector.
type LSMConfig struct {
	// Enabled controls LSM hook loading:
	// "auto" - load if kernel supports (default)
	// "true" - require kernel support, fail if unavailable
	// "false" - disable LSM hooks
	Enabled string `mapstructure:"enabled"`
}

// DefaultLSMConfig returns default LSM configuration.
func DefaultLSMConfig() LSMConfig {
	return LSMConfig{
		Enabled: "auto",
	}
}

// LSMCollector manages eBPF LSM hooks for pre-execution enforcement.
//
// Волна 8.6, заход B, Д14а / №563. Коллектор — менеджер блокирующей половины,
// а не владелец объекта BPF: все шесть программ lsm.bpf.c лежат в ОДНОМ объекте
// Kmod, и грузит его KmodCollector (kmod/cgroup-события читает тоже он). Карты
// и привязка хуков file_open/socket_connect/task_kill берутся из того же
// объекта — второй загрузки (вторая копия карт, вторые кольца) нет. Load()
// просит KmodCollector загрузить объект, усыновляет его карты и заливает
// политику (lsm_path_blocklist, network_blocklist); «доступен» — это хуки
// привязаны И политика загружена, а не «ядро умеет LSM».
type LSMCollector struct {
	config    LSMConfig
	logger    *slog.Logger
	objs      *lsmObjects
	links     []link.Link
	available bool
	mu        sync.RWMutex
	// status publishes the collector's real up/down state. Finding №457:
	// without it collector_up{lsm} kept the optimistic pre-Start 1 forever,
	// so on a kernel without LSM BPF the series reported a healthy collector
	// that had in fact entered stub mode and said so in the log. №438 was
	// declared closed while this one series still lied.
	status StatusReporter

	// kmod — владелец загруженного объекта (см. выше); nil — коллектор без ядра.
	kmod *KmodCollector
	// netCtl пишет network_blocklist в карты net_block_* того же объекта.
	netCtl *bpf.NetworkBlocklistController
	// policyLoaded — политика (пути и сеть) залита в карты; без неё available=false.
	policyLoaded bool
	// statsLast — прошлые суммы lsm_stats по индексам, для приращений счётчика.
	statsLast [8]uint64

	// configPathKeys tracks the FNV-32a keys loaded from the config-driven
	// lsm_path_blocklist so SetPathBlocklist can remove stale entries on reload.
	configPathKeys []uint32

	// Metrics
	blocksTotal *prometheus.CounterVec
}

// lsmMapOps — то, что менеджер делает с картами политики; *ebpf.Map его
// удовлетворяет, тесты подставляют память.
type lsmMapOps interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
}

// lsmObjects — карты объекта Kmod, которыми управляет менеджер. Принадлежат
// KmodCollector и закрываются им; LSMCollector их не закрывает.
type lsmObjects struct {
	LsmBlocklist      lsmMapOps
	LsmAgentWhitelist lsmMapOps
	LsmPathBlocklist  lsmMapOps // FNV-32a hash → blocked flag
	// LsmStats читается пакетно по индексам; nil — счётчики не снимаются.
	LsmStats *ebpf.Map
}

// NewLSMCollector creates a new LSM collector.
func NewLSMCollector(config LSMConfig, logger *slog.Logger) (*LSMCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	lc := &LSMCollector{
		config: config,
		logger: logger,
		links:  make([]link.Link, 0),
		blocksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_lsm_blocks_total",
			Help: "Total number of LSM hook invocations and blocking decisions",
		}, []string{"hook", "action"}),
	}

	// Pre-initialize the known label combinations to 0 so the metric is present
	// in /metrics from startup (rather than appearing only after the first block),
	// which lets dashboards and alerting rules reference it immediately.
	for _, hook := range []string{"file_open", "socket_connect", "task_kill"} {
		for _, action := range []string{"allow", "block"} {
			lc.blocksTotal.WithLabelValues(hook, action)
		}
	}

	lc.status = NoopStatusReporter{}

	// Check availability
	available := lc.checkAvailability()
	lc.available = available

	if !available {
		if config.Enabled == "true" {
			return nil, fmt.Errorf("lsm: kernel does not support LSM BPF (required but disabled)")
		}
		logger.Info("lsm: kernel does not support LSM BPF, collector in stub mode")
		return lc, nil
	}

	if config.Enabled == "false" {
		logger.Info("lsm: LSM BPF disabled by configuration")
		lc.available = false
		return lc, nil
	}

	logger.Info("lsm: LSM BPF is available")
	return lc, nil
}

// activeLSMListPath is the kernel's list of active LSMs; BPF LSM is usable when
// it names "bpf". A variable so tests can present both kernels on any host
// instead of asserting whatever kernel the test happens to run on.
var activeLSMListPath = "/sys/kernel/security/lsm"

// checkAvailability checks if the kernel supports LSM BPF.
func (lc *LSMCollector) checkAvailability() bool {
	// Check kernel version (5.7+)
	// This is a simplified check; real implementation would parse uname
	data, err := os.ReadFile(activeLSMListPath)
	if err != nil {
		lc.logger.Debug("lsm: cannot read active LSM list", "path", activeLSMListPath, "error", err)
		return false
	}

	lsms := string(data)
	if !strings.Contains(lsms, "bpf") {
		lc.logger.Debug("lsm: bpf not in active LSMs", "lsm", strings.TrimSpace(lsms))
		return false
	}

	return true
}

// BindKmod связывает менеджер с владельцем объекта BPF (см. LSMCollector).
func (lc *LSMCollector) BindKmod(kc *KmodCollector) *LSMCollector {
	lc.kmod = kc
	return lc
}

// Load поднимает блокирующую половину: просит KmodCollector загрузить объект
// (идемпотентно), усыновляет его карты и заливает политику. После успеха
// IsAvailable() истинно; при любой неудаче — ложно, а причина в журнале и в
// возвращаемой ошибке. Вызывать из старта ДО запуска коллекторов.
func (lc *LSMCollector) Load() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if !lc.available {
		return nil
	}
	if lc.kmod == nil {
		lc.available = false
		return fmt.Errorf("lsm: no kmod collector bound, blocking half cannot load")
	}
	if !lc.kmod.blockHooks {
		lc.available = false
		lc.logger.Info("lsm: blocking hooks not requested (enforcement.block_backend is not \"lsm\"); manager inactive")
		return nil
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		lc.available = false
		return fmt.Errorf("lsm: remove memlock limit: %w", err)
	}
	if err := lc.kmod.EnsureLoaded(); err != nil {
		lc.available = false
		return fmt.Errorf("lsm: load kernel object: %w", err)
	}
	if !lc.kmod.blockHooksAttached() {
		lc.available = false
		return fmt.Errorf("lsm: file_open/socket_connect hooks are not attached (see kmod log)")
	}
	lc.objs = lc.kmod.lsmObjects()
	if o := lc.kmod.kmodObjs; o != nil && o.NetBlockIpv4 != nil && o.NetBlockIpv6 != nil && o.NetBlockPorts != nil {
		ctl, err := bpf.NewNetworkBlocklistController(o.NetBlockIpv4, o.NetBlockIpv6, o.NetBlockPorts)
		if err != nil {
			lc.available = false
			return fmt.Errorf("lsm: network blocklist controller: %w", err)
		}
		lc.netCtl = ctl
	}
	lc.logger.Info("lsm: blocking hooks attached; waiting for policy")
	return nil
}

// ApplyPolicy заливает политику блокировки: пути для file_open и сеть для
// socket_connect. Вызывается из старта после Load и при перезагрузке конфига.
// Политика считается загруженной только при успехе обеих половин.
func (lc *LSMCollector) ApplyPolicy(paths []string, nb bpf.NetworkBlocklistConfig) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.objs == nil || lc.objs.LsmPathBlocklist == nil {
		return fmt.Errorf("lsm: policy not applied: blocking half not loaded")
	}
	if err := lc.setPathBlocklistLocked(paths); err != nil {
		lc.policyLoaded = false
		return err
	}
	if lc.netCtl != nil {
		if err := lc.netCtl.SetBlocklist(nb); err != nil {
			lc.policyLoaded = false
			return fmt.Errorf("lsm: network blocklist: %w", err)
		}
	} else if len(nb.Subnets) > 0 || len(nb.Ports) > 0 {
		lc.policyLoaded = false
		return fmt.Errorf("lsm: network blocklist configured but net_block maps are unavailable")
	}
	lc.policyLoaded = true
	lc.logger.Info("lsm: policy loaded", "paths", len(paths), "subnets", len(nb.Subnets), "ports", len(nb.Ports))
	return nil
}

// enforcing — блокировка действительно работает: хуки привязаны и политика залита.
func (lc *LSMCollector) enforcing() bool {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.available && lc.objs != nil && lc.policyLoaded
}

// AddToBlocklist adds a PID to the LSM blocklist.
func (lc *LSMCollector) AddToBlocklist(pid uint32) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if !lc.available || lc.objs == nil || lc.objs.LsmBlocklist == nil {
		return fmt.Errorf("lsm: collector not available or not loaded")
	}

	val := uint8(1)
	if err := lc.objs.LsmBlocklist.Update(pid, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("lsm: add to blocklist: %w", err)
	}

	lc.logger.Info("lsm: PID added to blocklist", "pid", pid)
	return nil
}

// RemoveFromBlocklist removes a PID from the LSM blocklist.
func (lc *LSMCollector) RemoveFromBlocklist(pid uint32) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if !lc.available || lc.objs == nil || lc.objs.LsmBlocklist == nil {
		return fmt.Errorf("lsm: collector not available or not loaded")
	}

	if err := lc.objs.LsmBlocklist.Delete(pid); err != nil {
		return fmt.Errorf("lsm: remove from blocklist: %w", err)
	}

	lc.logger.Info("lsm: PID removed from blocklist", "pid", pid)
	return nil
}

// AddPathToBlocklist adds a path to the per-path BPF blocklist.
// The path is normalised to its absolute form before hashing so that
// "/tmp/evil", "./evil" relative to /tmp, and "/tmp//evil" all resolve
// to the same key.  The BPF hook blocks any open of a path whose FNV-32a
// hash is present in the map, regardless of which PID opens it.
func (lc *LSMCollector) AddPathToBlocklist(path string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if !lc.available || lc.objs == nil || lc.objs.LsmPathBlocklist == nil {
		return fmt.Errorf("lsm: path blocklist not available (LSM not loaded)")
	}

	// Use filepath.Clean so the hash matches what bpf_d_path returns.
	key := fnv32a(filepath.Clean(path))
	val := uint8(1)
	if err := lc.objs.LsmPathBlocklist.Update(key, val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("lsm: add path to blocklist %q: %w", path, err)
	}
	lc.logger.Info("lsm: path added to blocklist", "path", path, "hash", key)
	return nil
}

// RemovePathFromBlocklist removes a path from the per-path BPF blocklist.
func (lc *LSMCollector) RemovePathFromBlocklist(path string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if !lc.available || lc.objs == nil || lc.objs.LsmPathBlocklist == nil {
		return fmt.Errorf("lsm: path blocklist not available (LSM not loaded)")
	}

	key := fnv32a(filepath.Clean(path))
	if err := lc.objs.LsmPathBlocklist.Delete(key); err != nil {
		return fmt.Errorf("lsm: remove path from blocklist %q: %w", path, err)
	}
	lc.logger.Info("lsm: path removed from blocklist", "path", path)
	return nil
}

// SetPathBlocklist atomically replaces the config-driven portion of the
// path blocklist.  It removes every key that was previously loaded from
// config (tracked in configPathKeys) and then inserts the new set.
// Dynamically blocked paths (added via AddPathToBlocklist at rule-fire
// time) are preserved.
func (lc *LSMCollector) SetPathBlocklist(paths []string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.setPathBlocklistLocked(paths)
}

func (lc *LSMCollector) setPathBlocklistLocked(paths []string) error {
	if !lc.available || lc.objs == nil || lc.objs.LsmPathBlocklist == nil {
		return fmt.Errorf("lsm: path blocklist not available (LSM not loaded)")
	}

	// Remove previously configured paths.
	for _, old := range lc.configPathKeys {
		_ = lc.objs.LsmPathBlocklist.Delete(old) // best-effort; ignore ENOENT
	}

	newKeys := make([]uint32, 0, len(paths))
	val := uint8(1)
	for _, p := range paths {
		key := fnv32a(filepath.Clean(p))
		if err := lc.objs.LsmPathBlocklist.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("lsm: config path blocklist %q: %w", p, err)
		}
		newKeys = append(newKeys, key)
		lc.logger.Debug("lsm: config path blocklisted", "path", p, "hash", key)
	}
	lc.configPathKeys = newKeys
	lc.logger.Info("lsm: path blocklist reloaded", "count", len(paths))
	return nil
}

// IsAvailable returns true if LSM BPF is available and enabled.
func (lc *LSMCollector) IsAvailable() bool {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.available
}

// IsAvailable выше отвечает «блокирующая половина загружена»; публикуемое
// здоровье collector_up{lsm} строже — см. enforcing().

// Start implements the Collector interface.
// LSM hooks are loaded once and run continuously; no event reading needed.
func (lc *LSMCollector) Start(ctx context.Context, out chan<- types.Event) error {
	// №457 + Д14а/№563: collector_up{lsm} = 1 только когда блокирующие хуки
	// привязаны И политика залита. Режим «ядро умеет LSM, но мы не грузили» и
	// «объект загружен, хуки не привязаны» — оба 0, с причиной в журнале.
	if !lc.enforcing() {
		lc.status.SetUp("lsm", false)
		<-ctx.Done()
		return ctx.Err()
	}

	lc.status.SetUp("lsm", true)
	lc.logger.Info("lsm: blocking hooks active, waiting for shutdown")

	lc.runStatsCollector(ctx)
	<-ctx.Done()
	return ctx.Err()
}

// runStatsCollector раз в 10 с переносит lsm_stats в ebpf_guard_lsm_blocks_total.
func (lc *LSMCollector) runStatsCollector(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				lc.collectStats()
			}
		}
	}()
}

// lsmStatLabels — индекс lsm_stats → (hook, action) метрики.
var lsmStatLabels = [8][2]string{
	{"file_open", "allow"}, {"file_open", "block"},
	{"socket_connect", "allow"}, {"socket_connect", "block"},
	{"task_kill", "allow"}, {"task_kill", "block"},
}

// collectStats читает сумму по CPU каждого индекса и прибавляет приращение.
func (lc *LSMCollector) collectStats() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.objs == nil || lc.objs.LsmStats == nil {
		return
	}
	for idx := uint32(0); idx < uint32(len(lsmStatLabels)); idx++ {
		var perCPU []uint64
		if err := lc.objs.LsmStats.Lookup(idx, &perCPU); err != nil {
			continue
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		if sum > lc.statsLast[idx] {
			l := lsmStatLabels[idx]
			lc.blocksTotal.WithLabelValues(l[0], l[1]).Add(float64(sum - lc.statsLast[idx]))
		}
		lc.statsLast[idx] = sum
	}
}

// Name returns the collector name.
func (lc *LSMCollector) Name() string {
	return "lsm"
}

// WithStatusReporter sets the StatusReporter used to signal up/down state
// (№457). Without it collector_up{lsm} carried main's optimistic pre-Start
// default and could never read 0, even on a kernel that has no LSM BPF at all.
func (lc *LSMCollector) WithStatusReporter(r StatusReporter) *LSMCollector {
	if r != nil {
		lc.status = r
	}
	return lc
}

// Close отпускает менеджер. Карты и связи принадлежат KmodCollector и закрываются
// им — блок снимается его Close (отвязка хуков).
func (lc *LSMCollector) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.objs = nil
	lc.netCtl = nil
	lc.policyLoaded = false
	lc.available = false
	lc.logger.Info("lsm: LSM collector closed")
	return nil
}

// RegisterMetrics registers Prometheus metrics.
func (lc *LSMCollector) RegisterMetrics(reg prometheus.Registerer) error {
	return reg.Register(lc.blocksTotal)
}

// -----------------------------------------------------------------------
// KmodCollector — Sprint 33.0
// -----------------------------------------------------------------------

// KmodCollector reads EVENT_KMOD_LOAD and EVENT_CGROUP_ESC events from the
// lsm_events and cgroup_events ring buffers written by lsm.bpf.c and
// cgroup.bpf.c respectively. It provides a tracepoint fallback
// (sys_enter_init_module) for kernels older than 5.7.
type KmodCollector struct {
	logger       *slog.Logger
	kmodObjs     *bpf.KmodObjects
	cgroupObjs   *bpf.CgroupObjects
	kmodLinks    []link.Link
	cgroupLinks  []link.Link
	kmodReader   *bpf.RingbufReader
	cgroupReader *bpf.RingbufReader
	loadError    error
	dropLogger   *dropLogger
	status       StatusReporter
	strategy     BackpressureStrategy
	available    bool
	lostTotal    atomic.Uint64
	auditLogger  *audit.Logger // optional; routes LSM audit events out-of-band

	// Д14а/№563: блокирующие хуки (file_open, socket_connect, task_kill) того же
	// объекта. blockHooks — «привязывать» (block_backend: lsm); linked — что
	// удалось привязать. Объект грузится один раз (EnsureLoaded), из Start или
	// из LSMCollector.Load, смотря что раньше.
	blockHooks  bool
	loadOnce    sync.Once
	loadErr     error
	linked      [3]bool // file_open, socket_connect, task_kill
	onLSMDeny   func(hook string)
	agentPID    uint32 // pid, внесённый в lsm_agent_whitelist до привязки
	attachBlock func() // тестовый шов; nil — настоящая привязка
}

// WithBlockHooks включает привязку блокирующих хуков. Выключено — объект
// грузится, kmod-хуки живут, блокирующие программы остаются непривязанными.
func (c *KmodCollector) WithBlockHooks(on bool) *KmodCollector {
	c.blockHooks = on
	return c
}

// WithLSMDenyObserver подписывает на отказы ядра: fn(hook) зовётся на каждое
// событие lsm_audit с действием deny — единственный источник
// enforcement_actions_total{action="lsm_block"}.
func (c *KmodCollector) WithLSMDenyObserver(fn func(hook string)) *KmodCollector {
	c.onLSMDeny = fn
	return c
}

// EnsureLoaded грузит объект Kmod и привязывает хуки один раз. Повторные
// вызовы возвращают тот же итог. Ядро без BPF LSM — ошибка errLSMUnavailable.
func (c *KmodCollector) EnsureLoaded() error {
	if !c.available {
		return errLSMUnavailable
	}
	c.loadOnce.Do(func() {
		c.loadErr = c.loadKmod()
		if c.loadErr != nil {
			c.available = false
		}
	})
	return c.loadErr
}

var errLSMUnavailable = fmt.Errorf("lsm: kernel does not expose BPF LSM")

// blockHooksAttached — привязаны оба блокирующих хука. task_kill — только аудит
// и в условие не входит.
func (c *KmodCollector) blockHooksAttached() bool { return c.linked[0] && c.linked[1] }

// lsmObjects отдаёт менеджеру карты загруженного объекта (без владения).
func (c *KmodCollector) lsmObjects() *lsmObjects {
	o := c.kmodObjs
	if o == nil {
		return nil
	}
	out := &lsmObjects{LsmStats: o.LsmStats}
	if o.LsmBlocklist != nil {
		out.LsmBlocklist = o.LsmBlocklist
	}
	if o.LsmAgentWhitelist != nil {
		out.LsmAgentWhitelist = o.LsmAgentWhitelist
	}
	if o.PathBlocklist != nil {
		out.LsmPathBlocklist = o.PathBlocklist
	}
	return out
}

// NewKmodCollector creates a new kernel-module-load and cgroup-escape collector.
func NewKmodCollector(logger *slog.Logger) (*KmodCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	c := &KmodCollector{
		logger:     logger.With("collector", "kmod"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}
	// Determine whether LSM BPF is available (same check as LSMCollector).
	data, err := os.ReadFile(activeLSMListPath)
	if err == nil && strings.Contains(string(data), "bpf") {
		c.available = true
	}
	return c, nil
}

// WithStatusReporter sets the StatusReporter.
func (c *KmodCollector) WithStatusReporter(r StatusReporter) *KmodCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy.
func (c *KmodCollector) WithBackpressureStrategy(s BackpressureStrategy) *KmodCollector {
	c.strategy = s
	return c
}

// WithAuditLogger wires an audit.Logger so that LSM audit events (EVENT_TYPE_LSM_AUDIT)
// are written to the JSONL audit log instead of forwarded to the event channel.
func (c *KmodCollector) WithAuditLogger(l *audit.Logger) *KmodCollector {
	c.auditLogger = l
	return c
}

// Name returns the collector identifier.
func (c *KmodCollector) Name() string { return "kmod" }

// IsHealthy returns true if the collector loaded without error.
func (c *KmodCollector) IsHealthy() bool { return c.loadError == nil }

// Start attaches eBPF programs and begins forwarding events. Blocks until ctx is cancelled.
//
// There is no tracepoint-based fallback for kernel-module-load detection:
// bpf/lsm.bpf.c only defines LSM-type programs (SEC("lsm/...")), and the
// compiled "Kmod" object bundles all of them together, so even attempting to
// load it on a kernel without BPF LSM support (no CONFIG_BPF_LSM / lsm=bpf)
// fails outright — there is nothing to fall back to. When LSM is unavailable,
// skip kmod load detection entirely rather than logging a misleading error.
//
// №502 (28.09.2026) — что этот комментарий ДОЛГО объяснял неверно. Загрузка
// падала здесь и на ядре С поддержкой BPF LSM: три программы lsm.bpf.c несли
// имена хуков с лишним префиксом (SEC("lsm/bpf_file_open") и два соседа), то
// есть искали точки привязки bpf_lsm_bpf_file_open, которых нет нигде.
// Поскольку attach_btf_id у LSM резолвится на ЗАГРУЗКЕ, а все шесть программ
// лежат в одном объекте, падал объект целиком — и два ГОДНЫХ хука, которые
// loadKmod() единственные и привязывает, не привязывались никогда. Отказ
// списывался на «ядро без BPF LSM», хотя `/sys/kernel/security/lsm` содержал
// bpf. Имена исправлены; ветка ниже остаётся законной для ядер, где BPF LSM
// действительно выключен.
func (c *KmodCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting kmod collector", "lsm_available", c.available)

	if c.available {
		if err := c.EnsureLoaded(); err != nil {
			c.logger.Warn("kmod: LSM load failed, kernel module load detection disabled", "error", err)
		}
	} else {
		c.logger.Info("kmod: LSM BPF unavailable — the 7 event_type=kmod rules are inert on this kernel; module loads are still seen on the syscall axis (rootkit_init_module_syscall nr 175/313, rootkit_delete_module_syscall nr 176) when the syscall collector is enabled")
	}

	if err := c.loadCgroup(); err != nil {
		// Cgroup escape detection is best-effort; log and continue.
		c.logger.Warn("kmod: cgroup escape collector unavailable", "error", err)
	}

	// Item 6 волны 6.5: «up» означает «хотя бы один ридер поднят», а не
	// «Start дошёл до этой строки» — иначе без LSM BPF и cgroup-программы
	// серия лжёт единицей при нуле работающих хуков (№438).
	c.status.SetUp("kmod", c.kmodReader != nil || c.cgroupReader != nil)

	var kmodDone, cgroupDone <-chan struct{}
	if c.kmodReader != nil {
		kmodDone = runReadLoop(func() { c.readLoop(ctx, out, c.kmodReader, c.parseKmodOrFallback) })
	}
	if c.cgroupReader != nil {
		cgroupDone = runReadLoop(func() { c.readLoop(ctx, out, c.cgroupReader, c.parseCgroupEsc) })
	}

	// Wait for context cancellation, then for both readLoops to actually stop
	// sending (5.8d) — Close() unblocks the ring buffer Read() a readLoop may
	// be parked in, and Close() runs after ctx is already done.
	<-ctx.Done()
	c.logger.Info("stopping kmod collector")
	if kmodDone != nil {
		<-kmodDone
	}
	if cgroupDone != nil {
		<-cgroupDone
	}
	return nil
}

// Close releases all eBPF resources.
func (c *KmodCollector) Close() error {
	// Wave 6.6 revision item 6: print whatever the drop-log window has
	// accumulated. Its window is closed by a 5s timer, so a run that ends
	// sooner than that after its last drop lost the count from the log
	// entirely — the metric still had it, but the log is where the HOP of
	// the loss is named (№474).
	c.dropLogger.flushOnClose()

	if c.kmodReader != nil {
		c.kmodReader.Close()
		c.kmodReader = nil
	}
	if c.cgroupReader != nil {
		c.cgroupReader.Close()
		c.cgroupReader = nil
	}
	for _, l := range c.kmodLinks {
		l.Close()
	}
	c.kmodLinks = nil
	for _, l := range c.cgroupLinks {
		l.Close()
	}
	c.cgroupLinks = nil
	if c.kmodObjs != nil {
		c.kmodObjs.Close()
		c.kmodObjs = nil
	}
	if c.cgroupObjs != nil {
		c.cgroupObjs.Close()
		c.cgroupObjs = nil
	}
	return nil
}

func (c *KmodCollector) loadKmod() error {
	c.kmodObjs = &bpf.KmodObjects{}
	if err := bpf.LoadKmodObjects(c.kmodObjs, bpf.WithSharedKernelTypes(&ebpf.CollectionOptions{})); err != nil {
		return err
	}
	// Attach LSM hooks.
	l1, err := link.AttachLSM(link.LSMOptions{Program: c.kmodObjs.LsmKernelModuleRequest})
	if err != nil {
		return fmt.Errorf("attach kernel_module_request: %w", err)
	}
	c.kmodLinks = append(c.kmodLinks, l1)

	l2, err := link.AttachLSM(link.LSMOptions{Program: c.kmodObjs.LsmKernelReadFile})
	if err != nil {
		return fmt.Errorf("attach kernel_read_file: %w", err)
	}
	c.kmodLinks = append(c.kmodLinks, l2)

	// Attach exec tracepoint for initial-cgroup recording.
	l3, err := link.Tracepoint("sched", "sched_process_exec", c.kmodObjs.TraceExecRecordCgroup, nil)
	if err != nil {
		c.logger.Warn("kmod: sched_process_exec tracepoint unavailable", "error", err)
	} else {
		c.kmodLinks = append(c.kmodLinks, l3)
	}

	reader, err := bpf.NewRingbufReader(c.kmodObjs.LsmEvents)
	if err != nil {
		return fmt.Errorf("kmod ringbuf reader: %w", err)
	}
	c.kmodReader = reader

	if c.blockHooks {
		c.attachBlockHooks()
	}
	return nil
}

// attachBlockHooks привязывает file_open, socket_connect и task_kill того же
// объекта (№563: они грузились, но не привязывались никогда). Неудача любого —
// предупреждение, kmod-хуки живут дальше; LSMCollector видит это через
// blockHooksAttached и не объявляет блокировку работающей. Агент вносится в
// lsm_agent_whitelist ДО привязки: хуки пропускают его без проверки политики.
func (c *KmodCollector) attachBlockHooks() {
	if c.attachBlock != nil {
		c.attachBlock()
		return
	}
	o := c.kmodObjs
	if o.LsmAgentWhitelist == nil {
		c.logger.Warn("kmod: lsm_agent_whitelist map missing; blocking hooks not attached")
		return
	}
	c.agentPID = uint32(os.Getpid())
	if err := o.LsmAgentWhitelist.Update(c.agentPID, uint8(1), ebpf.UpdateAny); err != nil {
		c.logger.Warn("kmod: cannot whitelist agent pid; blocking hooks not attached", "error", err)
		return
	}
	for i, h := range []struct {
		name string
		prog *ebpf.Program
	}{{"file_open", o.LsmFileOpen}, {"socket_connect", o.LsmSocketConnect}, {"task_kill", o.LsmTaskKill}} {
		if h.prog == nil {
			c.logger.Warn("kmod: blocking hook program missing", "hook", h.name)
			continue
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: h.prog})
		if err != nil {
			c.logger.Warn("kmod: blocking hook attach failed", "hook", h.name, "error", err)
			continue
		}
		c.kmodLinks = append(c.kmodLinks, l)
		c.linked[i] = true
		c.logger.Info("kmod: blocking hook attached", "hook", h.name)
	}
}

func (c *KmodCollector) loadCgroup() error {
	c.cgroupObjs = &bpf.CgroupObjects{}
	if err := bpf.LoadCgroupObjects(c.cgroupObjs, bpf.WithSharedKernelTypes(&ebpf.CollectionOptions{})); err != nil {
		return err
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: c.cgroupObjs.LsmCgroupAttachTask})
	if err != nil {
		return fmt.Errorf("attach cgroup_attach_task: %w", err)
	}
	c.cgroupLinks = append(c.cgroupLinks, l)

	reader, err := bpf.NewRingbufReader(c.cgroupObjs.CgroupEvents)
	if err != nil {
		return fmt.Errorf("cgroup ringbuf reader: %w", err)
	}
	c.cgroupReader = reader
	return nil
}

type parseFunc func([]byte) (*types.Event, error)

func (c *KmodCollector) readLoop(ctx context.Context, out chan<- types.Event, reader *bpf.RingbufReader, parse parseFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		record, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("kmod: ringbuf read error", "error", err)
			continue
		}
		event, err := parse(record.RawSample)
		if err != nil {
			c.logger.Error("kmod: parse error", "error", err)
			continue
		}
		if event == nil {
			// Consumed inline (e.g. LSM audit event routed to audit logger).
			continue
		}
		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordEventDrop("kmod", "ringbuf_to_router", defaultEventPriority(event.Type))
			c.dropLogger.record(c.logger, "ringbuf_to_router")
			c.lostTotal.Add(1)
		})
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *KmodCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

func (c *KmodCollector) parseKmodOrFallback(raw []byte) (*types.Event, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("kmod: raw event too short (%d bytes)", len(raw))
	}
	evtType := binary.LittleEndian.Uint32(raw[:4])
	if evtType == uint32(types.EventLSMAudit) {
		// LSM audit events are routed to the audit logger, not the event channel.
		if c.auditLogger != nil || c.onLSMDeny != nil {
			ae, err := parseLSMAuditEventRaw(raw)
			if err != nil {
				return nil, fmt.Errorf("kmod: lsm audit event: %w", err)
			}
			entry := ae.toAuditEntry()
			// Отказ ядра — единственный источник enforcement_actions_total{lsm_block}
			// (Д14а): считается здесь, по событию, а не по алерту правила.
			if ae.Action == 1 && c.onLSMDeny != nil {
				c.onLSMDeny(entry.Hook)
			}
			if c.auditLogger != nil {
				// Хвост пункта 8 ревизии 6.6: cgroup id по смещению, мимо зеркала
				// (его размер 107 гейтит разбор); 0 на записи старого объекта.
				entry.CgroupID = bpf.LSMAuditCgroupIDFromRecord(raw)
				if logErr := c.auditLogger.Log(entry); logErr != nil {
					c.logger.Warn("kmod: audit log write failed", "error", logErr)
				}
			}
		}
		return nil, nil // consumed; do not forward to the event channel
	}
	var ke bpf.KmodRawEvent
	if err := bpf.ParseKmodEventInto(raw, &ke); err != nil {
		return nil, err
	}
	result := ke.ToTypesEvent()
	return &result, nil
}

func (c *KmodCollector) parseCgroupEsc(raw []byte) (*types.Event, error) {
	var ce bpf.CgroupEscapeRawEvent
	if err := bpf.ParseCgroupEscapeEventInto(raw, &ce); err != nil {
		return nil, err
	}
	result := ce.ToTypesEvent()
	return &result, nil
}
