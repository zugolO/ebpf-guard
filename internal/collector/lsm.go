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
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fnv32a returns the FNV-1a 32-bit hash of s, matching the fnv32a() BPF helper
// in bpf/lsm.bpf.c, so that paths added via AddPathToBlocklist map correctly to
// what the kernel checks. Delegates to the single shared implementation in
// internal/util so this and internal/sandbox never diverge from each other or
// from the kernel (issue #271).
func fnv32a(s string) uint32 {
	return util.FNV32aPath(s)
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

const lsmAuditEventSize = 4 + 8 + 4 + 4 + 4 + 1 + 1 + 1 + 16 + 64 // 107 bytes

var lsmHookNames = [9]string{
	"file_open", "socket_connect", "task_kill", "bprm_check",
	"bpf", "ptrace", "mount", "module", "uring",
}

// LSM_HOOK_SOCKET_CONNECT and the ai_sandbox action codes, mirroring
// bpf/common.h. Duplicated here (rather than imported) because these are C
// #defines with no Go binding.
const (
	lsmHookSocketConnect  = 1
	lsmActionSandboxAudit = 2
	lsmActionSandboxDeny  = 3
)

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
	// Action codes match LSM_ACTION_* in bpf/common.h:
	//   0 audit-only, 1 deny, 2 ai_sandbox audit, 3 ai_sandbox deny.
	action := "audit"
	rule := "lsm_audit"
	enforced := false
	switch e.Action {
	case 1:
		action, enforced = "deny", true
	case 2:
		action, rule = "sandbox_audit", "ai_sandbox"
	case 3:
		action, rule, enforced = "sandbox_deny", "ai_sandbox", true
	}
	path := nullTermString(e.Path[:])
	if e.Hook == lsmHookSocketConnect && (e.Action == lsmActionSandboxAudit || e.Action == lsmActionSandboxDeny) {
		// sandbox_emit() packs socket_connect violations as port(2, BE) + raw
		// address bytes rather than a path string (see bpf/lsm.bpf.c); decode
		// that instead of null-terminating it as text.
		path = decodeSandboxAddr(e.Sig, e.Path[:])
	}

	return audit.Entry{
		TS:        time.Now(),
		Action:    action,
		PID:       e.PID,
		Rule:      rule,
		Comm:      nullTermString(e.Comm[:]),
		Enforced:  enforced,
		Hook:      hookName,
		TargetPID: e.TargetPID,
		Path:      path,
		UID:       e.UID,
	}
}

// DecodeLSMAuditRecord decodes one raw lsm_events ring-buffer record into an
// audit.Entry, reporting whether it is an ai_sandbox decision. It lets callers
// outside this package (the `ebpf-guard run` wrapper) drain the sandbox
// lsm_events buffer and write audit records without duplicating the wire format
// (issue #268). Returns ok=false for a record that is not an LSM audit event.
func DecodeLSMAuditRecord(raw []byte) (entry audit.Entry, sandbox, ok bool, err error) {
	if len(raw) < 4 {
		return audit.Entry{}, false, false, fmt.Errorf("lsm audit record too short (%d bytes)", len(raw))
	}
	if binary.LittleEndian.Uint32(raw[:4]) != uint32(types.EventLSMAudit) {
		return audit.Entry{}, false, false, nil
	}
	ae, perr := parseLSMAuditEventRaw(raw)
	if perr != nil {
		return audit.Entry{}, false, false, perr
	}
	return ae.toAuditEntry(), ae.isSandboxAction(), true, nil
}

// isSandboxAction reports whether the action code is an ai_sandbox decision
// (sandbox_audit / sandbox_deny) rather than an enforcer file/socket/task block.
func (e lsmAuditEventRaw) isSandboxAction() bool {
	return e.Action == lsmActionSandboxAudit || e.Action == lsmActionSandboxDeny
}

// toTypesEvent converts a parsed LSM audit event into a types.Event carrying an
// LSMAuditEvent, so ai_sandbox decisions can flow through the correlation
// pipeline (rules → /api/v1/alerts → Prometheus) like any other event. It reuses
// toAuditEntry for consistent hook/decision/path decoding.
func (e lsmAuditEventRaw) toTypesEvent() types.Event {
	entry := e.toAuditEntry()
	ev := types.Event{
		Type:      types.EventLSMAudit,
		Timestamp: e.Timestamp,
		PID:       e.PID,
		TGID:      e.PID,
		UID:       e.UID,
		LSMAudit: &types.LSMAuditEvent{
			Hook:      entry.Hook,
			Decision:  entry.Action,
			Enforced:  entry.Enforced,
			Path:      entry.Path,
			TargetPID: e.TargetPID,
		},
	}
	copy(ev.Comm[:], e.Comm[:])
	return ev
}

// recordSandboxAudit writes an ai_sandbox decision to the dedicated sandbox sink
// (falling back to the shared enforcement audit logger when no dedicated sink is
// configured) and bumps the Prometheus counter. The pipeline forwarding in
// parseKmodOrFallback is independent of this: a sandbox event is surfaced even
// when no audit sink at all is configured (issue #268).
func (c *KmodCollector) recordSandboxAudit(ae lsmAuditEventRaw) {
	entry := ae.toAuditEntry()
	if c.sandboxEvents != nil {
		c.sandboxEvents.WithLabelValues(entry.Hook, entry.Action).Inc()
	}
	sink := c.sandboxAudit
	if sink == nil {
		sink = c.auditLogger // fall back to the shared enforcement sink
	}
	if sink == nil {
		return
	}
	if err := sink.Log(entry); err != nil {
		c.logger.Warn("kmod: sandbox audit log write failed", "error", err)
	}
}

// decodeSandboxAddr decodes an ai_sandbox socket_connect violation's packed
// path[] field — port(2, BE) followed by raw address bytes, family given by
// the event's sig byte — into a "host:port" string. Returns "" for an
// unrecognised family or a short buffer.
func decodeSandboxAddr(family uint8, path []byte) string {
	const (
		afINET  = 2
		afINET6 = 10
	)
	if len(path) < 2 {
		return ""
	}
	port := binary.BigEndian.Uint16(path[:2])
	var addrLen int
	switch family {
	case afINET:
		addrLen = 4
	case afINET6:
		addrLen = 16
	default:
		return ""
	}
	if len(path) < 2+addrLen {
		return ""
	}
	ip := net.IP(path[2 : 2+addrLen])
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
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
type LSMCollector struct {
	config    LSMConfig
	logger    *slog.Logger
	objs      *lsmObjects
	links     []link.Link
	available bool
	mu        sync.RWMutex

	// configPathKeys tracks the FNV-32a keys loaded from the config-driven
	// lsm_path_blocklist so SetPathBlocklist can remove stale entries on reload.
	configPathKeys []uint32

	// Metrics
	blocksTotal *prometheus.CounterVec
}

// lsmObjects contains all eBPF objects for LSM hooks.
// This will be generated by bpf2go; the struct is hand-maintained until
// `make generate` is re-run after bpf/lsm.bpf.c stabilises.
type lsmObjects struct {
	LsmBlocklist      *ebpf.Map `ebpf:"lsm_blocklist"`
	LsmAgentWhitelist *ebpf.Map `ebpf:"lsm_agent_whitelist"`
	LsmStats          *ebpf.Map `ebpf:"lsm_stats"`
	LsmPathBlocklist  *ebpf.Map `ebpf:"path_blocklist"` // FNV-32a hash → blocked flag
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

// checkAvailability checks if the kernel supports LSM BPF.
func (lc *LSMCollector) checkAvailability() bool {
	// Check kernel version (5.7+)
	// This is a simplified check; real implementation would parse uname
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		lc.logger.Debug("lsm: cannot read /sys/kernel/security/lsm", "error", err)
		return false
	}

	lsms := string(data)
	if !strings.Contains(lsms, "bpf") {
		lc.logger.Debug("lsm: bpf not in active LSMs", "lsm", strings.TrimSpace(lsms))
		return false
	}

	return true
}

// Load loads the LSM BPF programs.
func (lc *LSMCollector) Load() error {
	if !lc.available {
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("lsm: remove memlock limit: %w", err)
	}

	// lsm_bpf_gen.go does not exist yet — run `make generate` after
	// bpf/lsm.bpf.c is finalised to produce it and replace this block
	// with the real LoadLsmObjects call + link.AttachLSM calls.
	// Until then, mark as unavailable so IsAvailable(), AddToBlocklist(),
	// and the enforcer LSM path all correctly report no enforcement active.
	lc.logger.Warn("lsm: bpf2go bindings not yet generated; LSM enforcement inactive — run `make generate`")
	lc.available = false
	return nil
}

// whitelistAgentPID adds the current process to the agent whitelist.
func (lc *LSMCollector) whitelistAgentPID() error {
	if lc.objs == nil || lc.objs.LsmAgentWhitelist == nil {
		return nil // Stub mode
	}

	pid := os.Getpid()
	val := uint8(1)
	if err := lc.objs.LsmAgentWhitelist.Update(uint32(pid), val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update agent whitelist: %w", err)
	}

	lc.logger.Debug("lsm: agent PID whitelisted", "pid", pid)
	return nil
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

// Start implements the Collector interface.
// LSM hooks are loaded once and run continuously; no event reading needed.
func (lc *LSMCollector) Start(ctx context.Context, out chan<- types.Event) error {
	if !lc.available {
		// Stub mode: just wait for context cancellation
		<-ctx.Done()
		return ctx.Err()
	}

	// LSM hooks run in kernel space; we just need to keep the BPF objects loaded
	lc.logger.Info("lsm: LSM hooks active, waiting for shutdown")

	// Periodically update metrics from BPF stats map
	ticker := lc.startStatsCollector(ctx)
	defer ticker.Stop()

	<-ctx.Done()
	return ctx.Err()
}

// startStatsCollector starts a goroutine to collect LSM stats.
func (lc *LSMCollector) startStatsCollector(ctx context.Context) *time.Ticker {
	// Stub: would read from lsm_stats map periodically
	return time.NewTicker(30 * time.Second)
}

// Name returns the collector name.
func (lc *LSMCollector) Name() string {
	return "lsm"
}

// Close unloads LSM BPF programs.
func (lc *LSMCollector) Close() error {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	for _, l := range lc.links {
		l.Close()
	}
	lc.links = nil

	if lc.objs != nil {
		if lc.objs.LsmBlocklist != nil {
			lc.objs.LsmBlocklist.Close()
		}
		if lc.objs.LsmAgentWhitelist != nil {
			lc.objs.LsmAgentWhitelist.Close()
		}
		if lc.objs.LsmStats != nil {
			lc.objs.LsmStats.Close()
		}
		if lc.objs.LsmPathBlocklist != nil {
			lc.objs.LsmPathBlocklist.Close()
		}
		lc.objs = nil
	}

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
	auditLogger  *audit.Logger // optional; routes enforcer LSM audit events out-of-band

	// sandboxAudit is a dedicated append-only sink for ai_sandbox decisions,
	// independent of the enforcement.audit_log sink above (issue #268). When set,
	// sandbox_audit/sandbox_deny records are written here regardless of whether
	// the enforcement audit log is configured.
	sandboxAudit *audit.Logger

	// sandboxEvents counts ai_sandbox decisions surfaced from the lsm_events ring
	// buffer, labelled by hook and decision, so violations show up in Prometheus
	// even before any correlation rule fires (issue #268).
	sandboxEvents *prometheus.CounterVec

	// lsmStats mirrors the kernel lsm_stats percpu counters into Prometheus. It
	// replaces the previous startStatsCollector stub that never read the map
	// (issue #268).
	lsmStats      *prometheus.GaugeVec
	statsInterval time.Duration
}

// lsmStatNames maps each lsm_stats index (see LSM_STAT_* in bpf/lsm.bpf.c) to
// its Prometheus counter label. The order MUST match the C #defines.
var lsmStatNames = [12]string{
	"file_open_allow", "file_open_block",
	"sock_conn_allow", "sock_conn_block",
	"task_kill_allow", "task_kill_block",
	"kmod_load", "cgroup_esc",
	"sbx_bpf_block", "sbx_ptrace_block",
	"sbx_mount_block", "sbx_module_block",
}

// NewKmodCollector creates a new kernel-module-load and cgroup-escape collector.
func NewKmodCollector(logger *slog.Logger) (*KmodCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	c := &KmodCollector{
		logger:        logger.With("collector", "kmod"),
		dropLogger:    newDropLogger(5 * time.Second),
		status:        NoopStatusReporter{},
		strategy:      StrategyDrop,
		statsInterval: 15 * time.Second,
		sandboxEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_sandbox_events_total",
			Help: "ai_sandbox LSM decisions surfaced from the lsm_events ring buffer, by hook and decision.",
		}, []string{"hook", "decision"}),
		lsmStats: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_lsm_stats",
			Help: "Kernel LSM hook counters from the lsm_stats map (allow/block per hook, incl. ai_sandbox escape-primitive blocks).",
		}, []string{"counter"}),
	}
	// Determine whether LSM BPF is available (same check as LSMCollector).
	data, err := os.ReadFile("/sys/kernel/security/lsm")
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

// WithAuditLogger wires an audit.Logger so that enforcer LSM audit events
// (file_open / socket_connect / task_kill blocks) are written to the JSONL
// audit log out-of-band instead of forwarded to the event channel.
func (c *KmodCollector) WithAuditLogger(l *audit.Logger) *KmodCollector {
	c.auditLogger = l
	return c
}

// WithSandboxAudit wires a dedicated append-only sink for ai_sandbox decisions,
// independent of the enforcement.audit_log sink (issue #268). When set, every
// sandbox_audit/sandbox_deny record is written here in addition to being
// forwarded through the correlation pipeline.
func (c *KmodCollector) WithSandboxAudit(l *audit.Logger) *KmodCollector {
	c.sandboxAudit = l
	return c
}

// RegisterMetrics registers the collector's Prometheus metrics.
func (c *KmodCollector) RegisterMetrics(reg prometheus.Registerer) error {
	if err := reg.Register(c.sandboxEvents); err != nil {
		return err
	}
	return reg.Register(c.lsmStats)
}

// Name returns the collector identifier.
func (c *KmodCollector) Name() string { return "kmod" }

// IsHealthy returns true if the collector loaded without error.
func (c *KmodCollector) IsHealthy() bool { return c.loadError == nil }

// Load performs the eBPF load/attach for kernel-module-load detection ahead of
// Start, so callers that need the resulting *bpf.KmodObjects up front (the
// ai_sandbox Manager — issue #260) can share this one load instead of issuing
// a second, independent LoadKmodObjects call against the same lsm.bpf.c
// object. Idempotent: a no-op if already loaded or LSM is unavailable. Start
// calls this itself, so it is safe to leave unloaded here and let Start do it.
func (c *KmodCollector) Load() error {
	if !c.available || c.kmodObjs != nil {
		return nil
	}
	if err := c.loadKmod(); err != nil {
		c.available = false
		// loadKmod assigns c.kmodObjs before it can fail, so a failed load
		// still leaves a non-nil but unusable object; clear it so Objects()
		// correctly reports "nothing loaded" rather than a broken pointer.
		c.kmodObjs = nil
		return err
	}
	return nil
}

// Objects returns the loaded *bpf.KmodObjects, or nil if LSM is unavailable or
// nothing has loaded it yet (call Load or Start first). Exposed so the
// ai_sandbox Manager can attach its own programs against this same object
// instead of loading a second, independent copy whose maps and lsm_events
// ring buffer nobody else reads (issue #260).
func (c *KmodCollector) Objects() *bpf.KmodObjects {
	return c.kmodObjs
}

// Start attaches eBPF programs and begins forwarding events. Blocks until ctx is cancelled.
//
// There is no tracepoint-based fallback for kernel-module-load detection:
// bpf/lsm.bpf.c only defines LSM-type programs (SEC("lsm/...")), and the
// compiled "Kmod" object bundles all of them together, so even attempting to
// load it on a kernel without BPF LSM support (no CONFIG_BPF_LSM / lsm=bpf)
// fails outright — there is nothing to fall back to. When LSM is unavailable,
// skip kmod load detection entirely rather than logging a misleading error.
func (c *KmodCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting kmod collector", "lsm_available", c.available)

	switch {
	case c.available && c.kmodObjs != nil:
		c.logger.Info("kmod: using LSM objects pre-loaded via Load (shared with ai_sandbox)")
	case c.available:
		if err := c.loadKmod(); err != nil {
			c.logger.Warn("kmod: LSM load failed, kernel module load detection disabled", "error", err)
			c.available = false
		}
	default:
		c.logger.Info("kmod: LSM BPF unavailable, kernel module load detection disabled (no tracepoint fallback exists)")
	}

	if err := c.loadCgroup(); err != nil {
		// Cgroup escape detection is best-effort; log and continue.
		c.logger.Warn("kmod: cgroup escape collector unavailable", "error", err)
	}

	c.status.SetUp("kmod", true)

	if c.kmodReader != nil {
		go c.readLoop(ctx, out, c.kmodReader, c.parseKmodOrFallback)
	}
	if c.cgroupReader != nil {
		go c.readLoop(ctx, out, c.cgroupReader, c.parseCgroupEsc)
	}
	c.startStatsLoop(ctx)

	<-ctx.Done()
	c.logger.Info("stopping kmod collector")
	return nil
}

// startStatsLoop periodically mirrors the shared lsm_stats percpu counters into
// Prometheus. The map is written by every LSM program in lsm.bpf.c (including
// the ai_sandbox hooks the Manager attaches), so this is the reader the issue
// #268 stub was missing. No-op when the map or metric is unavailable.
func (c *KmodCollector) startStatsLoop(ctx context.Context) {
	if c.kmodObjs == nil || c.kmodObjs.LsmStats == nil || c.lsmStats == nil {
		return
	}
	interval := c.statsInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		c.collectLSMStats() // publish an initial sample immediately
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.collectLSMStats()
			}
		}
	}()
}

// collectLSMStats reads the percpu lsm_stats array, sums each counter across
// CPUs, and publishes it as a Prometheus gauge labelled by counter name.
func (c *KmodCollector) collectLSMStats() {
	m := c.kmodObjs.LsmStats
	if m == nil || c.lsmStats == nil {
		return
	}
	for idx, name := range lsmStatNames {
		var perCPU []uint64
		if err := m.Lookup(uint32(idx), &perCPU); err != nil { // #nosec G115 -- idx is bounded by len(lsmStatNames)
			c.logger.Debug("kmod: lsm_stats lookup failed", "index", idx, "error", err)
			continue
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		c.lsmStats.WithLabelValues(name).Set(float64(total))
	}
}

// Close releases all eBPF resources.
func (c *KmodCollector) Close() error {
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
	if err := bpf.LoadKmodObjects(c.kmodObjs, &ebpf.CollectionOptions{}); err != nil {
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
	return nil
}

func (c *KmodCollector) loadCgroup() error {
	c.cgroupObjs = &bpf.CgroupObjects{}
	if err := bpf.LoadCgroupObjects(c.cgroupObjs, &ebpf.CollectionOptions{}); err != nil {
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
			c.dropLogger.record(c.logger, "kmod")
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
		ae, err := parseLSMAuditEventRaw(raw)
		if err != nil {
			return nil, fmt.Errorf("kmod: lsm audit event: %w", err)
		}
		if ae.isSandboxAction() {
			// ai_sandbox decisions are recorded to the dedicated sandbox sink
			// (independent of enforcement.audit_log) and forwarded through the
			// pipeline so they reach the correlator, /api/v1/alerts and Prometheus
			// even when no enforcement audit log is configured (issue #268).
			c.recordSandboxAudit(ae)
			ev := ae.toTypesEvent()
			return &ev, nil
		}
		// Enforcer LSM audit events (file_open / socket_connect / task_kill
		// blocks) keep the original behaviour: routed to the enforcement audit
		// logger out-of-band, never forwarded to the event channel.
		if c.auditLogger != nil {
			if logErr := c.auditLogger.Log(ae.toAuditEntry()); logErr != nil {
				c.logger.Warn("kmod: audit log write failed", "error", logErr)
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
