// Package profiler provides process lineage tracking (ancestry chains).
package profiler

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// lineageProvisionalComms считает узлы со скобочным comm в снимках дерева —
// находка №301. Сторож нужен ровно затем, чтобы «ноль скобочных корней» на
// следующем прогоне отличался от «нормализация не вызывалась»: тот же класс,
// что счётчик попыток исключений (№292) и «ленивый промоушен» базы дрейфа
// (память drift-stuck-is-lazily-evaluated).
var lineageProvisionalComms = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_lineage_provisional_comm_total",
		Help: "Process-tree nodes carrying systemd's transitional \"(name)\" comm, by outcome (seen, renormalized, unresolved).",
	},
	[]string{"outcome"},
)

func init() {
	// Материализация с нуля: прогон, где ни одного скобочного имени не было,
	// обязан отличаться в /metrics от бинаря, который про них не знает.
	for _, outcome := range []string{"seen", "renormalized", "unresolved"} {
		lineageProvisionalComms.WithLabelValues(outcome)
	}
}

// parentInfoPool reduces per-event heap allocations for parentInfo structs.
var parentInfoPool = sync.Pool{
	New: func() any { return &parentInfo{} },
}

// LineageConfig holds configuration for lineage tracking.
type LineageConfig struct {
	// Enabled controls whether lineage tracking is active. When false,
	// Track() (ancestry building) is a no-op. Disable this if process tree
	// enrichment is not needed to avoid the per-event cost (~2.3 µs/op, 442 B,
	// 4 allocs on a changed PPID/comm).
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
	// MaxDepth is the maximum number of ancestors stored per process.
	// Zero or negative values default to 16.
	MaxDepth int `yaml:"max_depth"`
}

// DefaultLineageConfig returns default lineage configuration.
// Волна 8.6, Д4 (№558): зашитых паттернов цепочек больше нет — детект «веб-сервер
// → шелл» и прочие цепочки живут правилами (proc.lineage, parent_comm).
func DefaultLineageConfig() LineageConfig {
	return LineageConfig{
		Enabled:  true,
		TTL:      5 * time.Minute,
		MaxDepth: 8,
	}
}

// parentInfo tracks parent process information.
type parentInfo struct {
	PPID       uint32
	ParentComm string
	Timestamp  time.Time
}

// procEntry caches a /proc lookup result for a PID, avoiding repeated reads.
// Both comm and ppid are populated by readProcStatus in a single syscall.
type procEntry struct {
	comm      string
	ppid      uint32
	timestamp time.Time
	// ppidMissing records that readProcStatus was already tried for this PID
	// and could not supply a parent — the process had exited, or /proc is not
	// available at all (non-Linux, restricted container). Without this, the
	// PPID==0 fallback in lookupOwnPPID re-reads /proc on *every* event from
	// such a PID, since a failed read leaves nothing to cache. That is the hot
	// path: getParentInfo runs per event, ahead of store()'s steady-state fast
	// path, and short-lived forking attackers (sqlmap) are exactly the workload
	// that produces dead PIDs at volume. Measured cost of the uncached miss was
	// ~100x the cached path, so the negative result has to be cached too.
	// TTL eviction in Cleanup applies to these entries like any other, so a
	// recycled PID gets a fresh lookup.
	ppidMissing bool
}

// lineageShardCount is the number of PID-keyed shards the tracker is split into.
// A single global mutex previously serialised every per-event Track call across
// the entire PID-partitioned ingest worker pool, negating its parallelism.
// Sharding by PID lets independent PIDs proceed concurrently. Must be a power of
// two so lineageShardMask can select a shard with a bitmask.
const lineageShardCount = 16
const lineageShardMask = lineageShardCount - 1

// lineageShard holds the lineage/ancestry/procCache maps for a subset of PIDs,
// guarded by its own RWMutex.
type lineageShard struct {
	mu       sync.RWMutex
	lineage  map[uint32]*parentInfo
	ancestry map[uint32][]types.ProcessNode // PID → full ancestor chain (root → PID)
	// ancestryTS — своя метка времени записи ancestry. Запись по pid родителя без
	// собственных событий (bootstrap из /proc) не имеет lineage[pid], и Cleanup,
	// выселявший ancestry только вместе с lineage, её не удалял (волна 8.2,
	// доводка T1: потолок был pid_max).
	ancestryTS map[uint32]time.Time
	procCache  map[uint32]*procEntry // pid → (comm, ppid, ts), avoids repeated /proc reads
}

// LineageTracker tracks process parent-child relationships (ancestry chains).
type LineageTracker struct {
	config   LineageConfig
	shards   [lineageShardCount]*lineageShard
	maxDepth int

	// table — таблица процессов в ядре (волна 8.5, P1). Пока источник установлен, трекер —
	// тонкое чтение карты: Track не делает ничего, дерево и родитель читаются точечным lookup
	// по ppid, /proc не трогается, TTL-уборки у него нет (см. lineage_table.go). Без источника
	// (ядро без поддержки, dry-run, сбой загрузки) работает прежний путь на Go-картах и /proc.
	table atomic.Pointer[procSourceBox]
}

// shardFor returns the shard owning pid.
func (lt *LineageTracker) shardFor(pid uint32) *lineageShard {
	return lt.shards[pid&lineageShardMask]
}

// NewLineageTracker creates a new lineage tracker.
// logger не используется с Д4 (волна 8.6): паттерны, которым он писал, удалены;
// параметр оставлен ради вызывающих.
func NewLineageTracker(config LineageConfig, _ *slog.Logger) *LineageTracker {
	if config.TTL <= 0 {
		config.TTL = 5 * time.Minute
	}
	maxDepth := config.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 16
	}

	lt := &LineageTracker{
		config:   config,
		maxDepth: maxDepth,
	}
	for i := range lt.shards {
		lt.shards[i] = &lineageShard{
			lineage:    make(map[uint32]*parentInfo),
			ancestry:   make(map[uint32][]types.ProcessNode),
			ancestryTS: make(map[uint32]time.Time),
			procCache:  make(map[uint32]*procEntry),
		}
	}

	return lt
}

// Enabled — включён ли трекер (LineageConfig.Enabled).
func (lt *LineageTracker) Enabled() bool { return lt.config.Enabled }

// Track records the process ancestry for e.
// CorrelationEngine calls this on every event so that GetProcessTree can later
// return the full ancestor chain when enriching alerts.
//
// Performance: steady state (PID/PPID/comm unchanged since the last call, the
// overwhelmingly common case for a long-lived process) is a single shard lock
// plus a comparison — no allocation. A changed PPID/comm triggers a full
// ancestry rebuild, priced at ~2.3 µs/op, 442 B, 4 allocs (via
// BenchmarkLineageTrackerUpdate). Callers should gate this behind
// config.Enabled and ppid>0 checks. For high-throughput deployments where
// process tree enrichment is not required, set LineageConfig.Enabled=false to
// eliminate this per-event cost entirely.
func (lt *LineageTracker) Track(e types.Event) {
	if !lt.config.Enabled {
		return
	}
	if lt.table.Load() != nil {
		// Родословную ведёт ядро (fork/exec/exit): событию, отфильтрованному в ядре (F1),
		// не нужно «освежать» цепочку, а Go-карт и /proc здесь больше нет.
		return
	}
	ppid, parentComm := lt.getParentInfo(e)
	if ppid == 0 {
		return
	}
	comm := cleanComm(e.Comm[:])
	lt.store(e.PID, ppid, parentComm, comm)
}

// store records lineage/procCache for pid and (re)builds its ancestry chain.
//
// Steady state fast path: a long-lived process emits a stream of events with
// the same PID/PPID/comm on every call. When the recorded lineage and the
// last ancestry node already match, only the timestamp is refreshed (for TTL
// purposes) under a single lock — no allocation, no ancestry rebuild.
func (lt *LineageTracker) store(pid, ppid uint32, parentComm, comm string) {
	now := time.Now()
	s := lt.shardFor(pid)

	s.mu.Lock()
	if info, ok := s.lineage[pid]; ok && info.PPID == ppid && info.ParentComm == parentComm {
		if chain := s.ancestry[pid]; len(chain) > 0 {
			if last := chain[len(chain)-1]; last.PID == pid && last.PPID == ppid && last.Comm == comm {
				info.Timestamp = now
				s.ancestryTS[pid] = now
				if entry, ok := s.procCache[pid]; ok {
					entry.comm, entry.ppid, entry.timestamp = comm, ppid, now
					// A BPF-supplied ppid supersedes an earlier failed /proc
					// read, so the negative-cache flag must not outlive it.
					entry.ppidMissing = ppid == 0 && entry.ppidMissing
				} else if comm != "" || ppid > 0 {
					s.procCache[pid] = &procEntry{comm: comm, ppid: ppid, timestamp: now}
				}
				s.mu.Unlock()
				return
			}
		}
	}
	s.mu.Unlock()

	info := parentInfoPool.Get().(*parentInfo)
	info.PPID = ppid
	info.ParentComm = parentComm
	info.Timestamp = now

	s.mu.Lock()
	if old := s.lineage[pid]; old != nil && old != info {
		// Return the displaced entry to the pool instead of leaking it to GC;
		// only Cleanup used to do this, so hot PIDs bypassed the pool entirely.
		old.PPID = 0
		old.ParentComm = ""
		parentInfoPool.Put(old)
	}
	s.lineage[pid] = info
	// Eagerly cache BPF-provided comm+ppid so buildChainFromProc avoids
	// /proc reads when this process becomes a parent in later chain builds.
	if entry, ok := s.procCache[pid]; ok {
		entry.comm, entry.ppid, entry.timestamp = comm, ppid, now
		// A BPF-supplied ppid supersedes an earlier failed /proc read.
		entry.ppidMissing = ppid == 0 && entry.ppidMissing
	} else if comm != "" || ppid > 0 {
		s.procCache[pid] = &procEntry{comm: comm, ppid: ppid, timestamp: now}
	}
	s.mu.Unlock()

	lt.buildAncestry(pid, ppid, parentComm, comm)
}

// GetProcessTree returns the full ancestor chain for pid, ordered from the
// oldest known ancestor to pid itself.  Returns nil if no ancestry has been
// recorded for the PID.
func (lt *LineageTracker) GetProcessTree(pid uint32) types.ProcessTree {
	if box := lt.table.Load(); box != nil {
		return lt.tableTree(box.src, pid)
	}
	s := lt.shardFor(pid)
	s.mu.RLock()
	chain := s.ancestry[pid]
	if len(chain) == 0 {
		s.mu.RUnlock()
		return nil
	}
	result := make(types.ProcessTree, len(chain))
	copy(result, chain)
	s.mu.RUnlock()
	lt.normalizeProvisionalComms(result)
	return result
}

// --- Волна 6.2.9.F.1, находка №301: скобочный comm корня -------------------
//
// ЧТО ИЗМЕРЕНО (архив collect-6.2.9.F.1). Один и тот же pid с ppid==1 приходит
// в окне под ДВУМЯ-ТРЕМЯ разными comm:
//
//	16094  (fwupdmgr) | fwupdmgr | pool-fwupdmgr
//	16763  (ystemctl) | systemctl
//	16764  (otd-news) | 50-motd-news
//
// Скобочная форма — НЕ дефект нашего событийного пути: это настоящий comm,
// который systemd ставит форкнутому потомку между fork() и execve(). Буфер
// под имя — 11 байт («(» + имя + «)» + NUL), при переполнении держится ХВОСТ
// имени, отсюда «(50-motd-news)» → «(otd-news)» и «(systemctl)» →
// «(ystemctl)». Правило совпадает с наблюдением побайтово.
//
// БОЛЬНО ДРУГОЕ: ключ дерева — comm КОРНЯ, а он у одного процесса меняется на
// его жизни. Из-за этого дробится вход сужения (состав величины по корню:
// «(fwupdmgr) 3» и «fwupdmgr 6» — разные строки), одно событие ноды получает
// два разных Incident.RootComm, и база дрейфа, ключ которой тоже comm
// (память drift-workload-key-is-comm), заводит две «молодые» нагрузки на один
// процесс.
//
// ПОЧЕМУ НОРМАЛИЗАЦИЯ НА ЧТЕНИИ, А НЕ НА ЗАПИСИ. Ancestry пишется с тем comm,
// который известен в момент события, и копируется в цепочки потомков;
// переписывать задним числом все уже собранные цепочки дорого и гонко. Снимок
// же строится редко (на алерт), и переразрешение затрагивает только узлы со
// скобочным именем.
//
// ОТКАЗ ОТКРЫТЫЙ: не разрешилось — узел остаётся как есть. Ноль вместо лжи.

// isProvisionalComm reports whether comm is systemd's transitional
// «(name)» form, set with prctl(PR_SET_NAME) between fork() and execve().
// Форма именно КРУГЛЫХ скобок: runc:[2:INIT] и прочие квадратные имена —
// настоящие и постоянные.
func isProvisionalComm(comm string) bool {
	return len(comm) > 2 && comm[0] == '(' && comm[len(comm)-1] == ')'
}

// normalizeProvisionalComms переразрешает узлы со скобочным comm по
// procCache и /proc. Правит КОПИЮ снимка: запись в ancestry не трогается.
func (lt *LineageTracker) normalizeProvisionalComms(tree types.ProcessTree) {
	for i := range tree {
		if !isProvisionalComm(tree[i].Comm) {
			continue
		}
		lineageProvisionalComms.WithLabelValues("seen").Inc()
		resolved := lt.resolveCurrentComm(tree[i].PID)
		if resolved == "" || isProvisionalComm(resolved) {
			lineageProvisionalComms.WithLabelValues("unresolved").Inc()
			continue
		}
		tree[i].Comm = resolved
		lineageProvisionalComms.WithLabelValues("renormalized").Inc()
	}
}

// resolveCurrentComm отдаёт последнее известное имя процесса: сперва кэш
// /proc этого шарда, потом сам /proc. Скобочное значение кэша ответом не
// считается — иначе нормализация «разрешала» бы имя в него же самого.
func (lt *LineageTracker) resolveCurrentComm(pid uint32) string {
	if pid == 0 {
		return ""
	}
	s := lt.shardFor(pid)
	s.mu.RLock()
	entry, ok := s.procCache[pid]
	var cached string
	if ok && entry != nil {
		cached = entry.comm
	}
	s.mu.RUnlock()
	if cached != "" && !isProvisionalComm(cached) {
		return cached
	}
	comm, _ := readProcStatus(pid)
	return comm
}

// buildAncestry extends the ancestry chain for pid. It is deadlock-free under
// sharding: it reads (and may bootstrap) the parent's chain in the parent's
// shard, releases that lock, then writes pid's chain in pid's shard — the two
// shard locks are never held simultaneously.
func (lt *LineageTracker) buildAncestry(pid, ppid uint32, parentComm, comm string) {
	ps := lt.shardFor(ppid)
	ps.mu.RLock()
	parentChain := ps.ancestry[ppid]
	ps.mu.RUnlock()

	if len(parentChain) == 0 {
		// We haven't seen the parent's events yet; try to bootstrap from /proc.
		parentChain = lt.buildChainFromProc(ppid, lt.maxDepth-1)
		// Cache so subsequent events with the same ppid skip /proc entirely.
		// A chain of nodes with no comm and no ppid (dead parent: /proc miss) is
		// not worth keeping — nothing in it can be reused.
		if len(parentChain) > 0 && !chainIsEmpty(parentChain) {
			ps.mu.Lock()
			// Re-check: another goroutine may have built the chain meanwhile.
			if existing := ps.ancestry[ppid]; len(existing) == 0 {
				ps.ancestry[ppid] = parentChain
				ps.ancestryTS[ppid] = time.Now()
			} else {
				parentChain = existing
			}
			ps.mu.Unlock()
		}
	}

	node := types.ProcessNode{PID: pid, PPID: ppid, Comm: comm}
	newLen := len(parentChain) + 1
	newChain := make([]types.ProcessNode, newLen, newLen)
	copy(newChain, parentChain)
	newChain[len(parentChain)] = node

	// Ensure the parent node's Comm is set correctly (may have been set to "" by /proc miss).
	if len(newChain) >= 2 {
		parent := &newChain[len(newChain)-2]
		if parent.PID == ppid && parent.Comm == "" {
			parent.Comm = parentComm
		}
	}

	if len(newChain) > lt.maxDepth {
		newChain = newChain[len(newChain)-lt.maxDepth:]
	}

	s := lt.shardFor(pid)
	s.mu.Lock()
	s.ancestry[pid] = newChain
	s.ancestryTS[pid] = time.Now()
	s.mu.Unlock()
}

// chainIsEmpty reports whether no node of chain carries any information
// (comm=="" and ppid==0 everywhere), i.e. /proc had nothing for these pids.
func chainIsEmpty(chain []types.ProcessNode) bool {
	for _, n := range chain {
		if n.Comm != "" || n.PPID != 0 {
			return false
		}
	}
	return true
}

// buildChainFromProc walks /proc to reconstruct up to maxDepth ancestors for pid.
// Results are ordered from oldest ancestor to pid.  Per-process /proc results are
// cached in the owning shard's procCache so that subsequent chain builds (for
// different children of the same subtree) avoid repeated syscalls.
//
// Locking: each ancestor's procCache entry is read/written under that PID's own
// shard lock, acquired and released per iteration. The lock is never held across
// the readProcStatus syscall, so a slow /proc read cannot block other PIDs.
//
// Uses readProcStatus to fetch both comm and ppid in a single /proc read,
// halving the number of /proc syscalls per ancestor compared to separate
// readProcComm + readProcPPID calls.
func (lt *LineageTracker) buildChainFromProc(pid uint32, maxDepth int) []types.ProcessNode {
	if maxDepth <= 0 {
		return nil
	}
	var chain []types.ProcessNode
	cur := pid
	for len(chain) < maxDepth && cur > 1 {
		s := lt.shardFor(cur)
		s.mu.RLock()
		entry, ok := s.procCache[cur]
		var comm string
		var ppid uint32
		cached := ok && entry.comm != "" && entry.ppid > 0
		if cached {
			comm = entry.comm
			ppid = entry.ppid
		}
		s.mu.RUnlock()

		if !cached {
			// Read /proc without holding any shard lock.
			comm, ppid = readProcStatus(cur)
			if comm != "" || ppid > 0 {
				s.mu.Lock()
				if e2, ok2 := s.procCache[cur]; ok2 {
					e2.comm = comm
					e2.ppid = ppid
					e2.timestamp = time.Now()
				} else {
					s.procCache[cur] = &procEntry{comm: comm, ppid: ppid, timestamp: time.Now()}
				}
				s.mu.Unlock()
			}
		}
		chain = append([]types.ProcessNode{{PID: cur, PPID: ppid, Comm: comm}}, chain...)
		if ppid == 0 || ppid == cur {
			break
		}
		cur = ppid
	}
	return chain
}

// readProcStatus reads the process name and parent PID from /proc/<pid>/status
// in a single syscall, replacing the separate readProcComm + readProcPPID calls
// that previously required two /proc reads per level.
func readProcStatus(pid uint32) (comm string, ppid uint32) {
	lineageProcReads.Inc() // 8.5.5: чтений /proc трекером; на пути с таблицей ядра их быть не должно
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Clone: fields[1] is a substring of string(data), and the comm
				// outlives this call in the ancestry/proc caches. Without the
				// copy every cached comm pins the whole ~1.3 KiB status file
				// (wave 8.2 stage 4: 7 MiB of live heap after one attack pack).
				comm = strings.Clone(fields[1])
			}
		} else if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					ppid = uint32(v)
				}
			}
		}
		if comm != "" && ppid > 0 {
			break
		}
	}
	return comm, ppid
}

// getParentInfo extracts parent PID and comm from event or /proc.
//
// Two resolution paths converge on the same parent-comm lookup:
//
//  1. BPF populated e.PPID (preferred) — used directly.
//  2. e.PPID == 0 — BPF left the field unset. Until wave 5.9.3a (#45) this was
//     the common case: the shared fill_process_info in bpf/common.h zeroed
//     ppid/parent_comm by design (the "BPF verifier issues with pointer-chasing
//     through task_struct on kernel 5.15" caveat), and userspace had to recover
//     the parent via /proc for all four main collectors (syscall, network,
//     fileaccess, privesc). 5.9.3a reads task_struct->real_parent in the kernel
//     instead, so those four now take path 1. Path 2 remains the only route for
//     the dns collector (no ppid/parent_comm in struct dns_event at all — see
//     plan.md 5.9.3d), for synthetic test events, for older BPF programs, and
//     as the backstop whenever the kernel read comes back empty.
//
// The previous implementation skipped path 2 entirely with a comment claiming
// "real BPF events always carry PPID" — that claim was provably false against
// the shipped BPF, and was the root cause of P0-1: ProcessTree stayed empty
// across four attack runs because Track() never stored ancestry for any event
// from the main collectors.
//
// Path 2 performs a /proc/<e.PID>/status read on the first unseen PID, caches
// the result in procCache, and subsequent events for the same PID hit the
// cache — so the per-event syscall cost is paid once per process, not per
// event. When /proc is unavailable (e.g. non-Linux tests, or the process has
// already exited) path 2 returns (0, "") and the event is silently skipped,
// preserving the previous no-crash behaviour.
func (lt *LineageTracker) getParentInfo(e types.Event) (uint32, string) {
	ppid := e.PPID
	if ppid == 0 {
		// BPF did not populate PPID. Recover the parent PID from /proc so the
		// main collectors (syscall/network/fileaccess/privesc) still feed the
		// ancestry chain — without this, P0-1 regresses and every incident
		// comes back with an empty ProcessTree.
		ppid = lt.lookupOwnPPID(e.PID)
		if ppid == 0 {
			return 0, ""
		}
	}

	// Prefer the parent comm captured by BPF at fork/exec time. This is
	// authoritative and, crucially, survives short-lived parents (e.g. the
	// bash in nginx→bash→curl) that may already have exited before we can
	// read /proc. Without this, attack-chain detection silently misses the
	// most interesting cases.
	if ppid == e.PPID {
		if parentComm := cleanComm(e.ParentComm[:]); parentComm != "" {
			return ppid, parentComm
		}
	}

	// Check lineage map and procCache under a single RLock on the ppid shard.
	ps := lt.shardFor(ppid)
	ps.mu.RLock()
	if info, ok := ps.lineage[ppid]; ok {
		comm := info.ParentComm
		ps.mu.RUnlock()
		return ppid, comm
	}
	if entry, ok := ps.procCache[ppid]; ok && entry.comm != "" {
		comm := entry.comm
		ps.mu.RUnlock()
		return ppid, comm
	}
	ps.mu.RUnlock()

	// Cache miss: read /proc/<ppid>/status (single syscall for comm+ppid).
	comm, grandPPID := readProcStatus(ppid)
	if comm != "" || grandPPID > 0 {
		ps.mu.Lock()
		ps.procCache[ppid] = &procEntry{comm: comm, ppid: grandPPID, timestamp: time.Now()}
		ps.mu.Unlock()
	}
	return ppid, comm
}

// lookupOwnPPID returns the parent PID of pid by reading /proc/<pid>/status.
// Results are cached in procCache — both hits and misses — so subsequent events
// for the same PID pay the syscall at most once per TTL window. Returns 0 when
// /proc is unavailable or the process has exited, in which case the caller
// treats the event as having no resolvable parent.
//
// Caching the miss matters as much as caching the hit: this runs on the
// per-event hot path (getParentInfo → Track, ahead of store()'s steady-state
// fast path), and a forking attacker leaves behind dead PIDs whose /proc entry
// is gone before the event is processed. See procEntry.ppidMissing.
func (lt *LineageTracker) lookupOwnPPID(pid uint32) uint32 {
	if pid == 0 {
		return 0
	}
	s := lt.shardFor(pid)
	s.mu.RLock()
	if entry, ok := s.procCache[pid]; ok {
		if entry.ppid > 0 {
			ppid := entry.ppid
			s.mu.RUnlock()
			return ppid
		}
		if entry.ppidMissing {
			// Already tried and failed within the TTL window — don't re-read.
			s.mu.RUnlock()
			return 0
		}
	}
	s.mu.RUnlock()

	_, ppid := readProcStatus(pid)

	now := time.Now()
	s.mu.Lock()
	if e, ok := s.procCache[pid]; ok {
		e.ppid = ppid
		e.ppidMissing = ppid == 0
		e.timestamp = now
	} else {
		s.procCache[pid] = &procEntry{ppid: ppid, ppidMissing: ppid == 0, timestamp: now}
	}
	s.mu.Unlock()
	return ppid
}

// cleanComm removes null bytes from comm string.
//
// Wave 8.2, C2 (№540): interned, not copied — comm is a handful of distinct
// strings, and a copy per call was 20 B on every event (Track runs on all of them).
func cleanComm(comm []byte) string {
	return util.InternBytes(comm)
}

// Cleanup removes stale lineage and ancestry entries across all shards.
func (lt *LineageTracker) Cleanup(now time.Time) {
	cutoff := now.Add(-lt.config.TTL)
	for _, s := range lt.shards {
		s.mu.Lock()
		for pid, info := range s.lineage {
			if now.Sub(info.Timestamp) > lt.config.TTL {
				delete(s.lineage, pid)
				delete(s.ancestry, pid)
				delete(s.ancestryTS, pid)
				// Reset and return to pool to amortise allocations across long-lived processes.
				info.PPID = 0
				info.ParentComm = ""
				parentInfoPool.Put(info)
			}
		}
		// ancestry has its own clock: entries bootstrapped for parents without
		// events have no lineage record. An entry with no timestamp (written
		// directly) lives as long as its lineage did.
		for pid := range s.ancestry {
			if ts, ok := s.ancestryTS[pid]; ok {
				if now.Sub(ts) > lt.config.TTL {
					delete(s.ancestry, pid)
					delete(s.ancestryTS, pid)
				}
			} else if _, alive := s.lineage[pid]; !alive {
				delete(s.ancestry, pid)
			}
		}
		// Evict procCache entries older than TTL rather than clearing wholesale.
		for pid, entry := range s.procCache {
			if entry.timestamp.Before(cutoff) {
				delete(s.procCache, pid)
			}
		}
		s.mu.Unlock()
	}
}

// ParentOf returns the parent PID of pid and that parent's comm, as recorded
// from the kernel-supplied pid/ppid/parent_comm of an earlier event. Волна
// 6.2.6, item 5 (№277/№285).
//
// Отличия от GetLineage, ради которых заведён отдельный метод:
//   - возвращает КОПИЮ, а не указатель в шард. GetLineage отдаёт *parentInfo,
//     живущий в карте под мьютексом и возвращаемый в пул из Cleanup, — читать
//     его вне пакета значит гоняться с уборкой;
//   - не ходит в /proc. Вызывающая сторона (обход родословной в
//     correlator/exepath.go) работает по ЗАВЕДОМО МЁРТВЫМ pid'ам — в этом весь
//     смысл обхода, — и фолбэк на readProcStatus там был бы syscall'ом,
//     заведомо возвращающим ENOENT, на горячем пути разбора правил.
//
// ok=false означает «про этот pid ничего не записано», а не «у него нет
// родителя»: карта живёт TTL Cleanup'а, и очень старая цепочка из неё уходит.
func (lt *LineageTracker) ParentOf(pid uint32) (ppid uint32, parentComm string, ok bool) {
	if pid == 0 {
		return 0, "", false
	}
	if box := lt.table.Load(); box != nil {
		return lt.tableParentOf(box.src, pid)
	}
	s := lt.shardFor(pid)
	s.mu.RLock()
	info, found := s.lineage[pid]
	if found {
		ppid, parentComm = info.PPID, info.ParentComm
	}
	s.mu.RUnlock()
	if !found || ppid == 0 {
		return 0, "", false
	}
	return ppid, parentComm, true
}

// GetLineage returns the parent info for a PID (for testing).
func (lt *LineageTracker) GetLineage(pid uint32) (*parentInfo, bool) {
	s := lt.shardFor(pid)
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.lineage[pid]
	return info, ok
}

// Size returns the number of tracked processes across all shards.
func (lt *LineageTracker) Size() int {
	if lt.table.Load() != nil {
		return 0 // записи живут в ядре, не в Go
	}
	n := 0
	for _, s := range lt.shards {
		s.mu.RLock()
		n += len(s.lineage)
		s.mu.RUnlock()
	}
	return n
}
