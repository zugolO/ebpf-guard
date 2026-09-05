// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func init() {
	// Register the process-wide string interner as a Prometheus collector so
	// ebpf_guard_interner_hits_total, _misses_total, and _size are scraped.
	prometheus.MustRegister(util.DefaultInterner)

	// Materialise both counting-canary stages at zero from the first scrape
	// (same reasoning as dns_decode_errors_total in internal/collector/dns.go,
	// 5.9.5c): without this, a clean mode=null run — where the canary series
	// is expected to stay at exactly 0 all along — is indistinguishable in
	// /metrics from "this binary predates 5.9.8b", which is exactly the
	// ambiguity a criterion checking for "canary series = 0" cannot resolve.
	CountingCanaryTotal.WithLabelValues("events")
	CountingCanaryTotal.WithLabelValues("dropped")

	// Same reasoning for both drop reasons of proc.args (6.0j/№210): a run
	// where the fallback path never fired must be distinguishable in /metrics
	// from a binary that predates the counter, or "argv0_mismatch = 0" reads
	// as "no blindness" when it may mean "no instrument".
	// Та же причина для привязки chmod-хуков (6.2.1, слой 3): прогон, где ни
	// один хук не привязался, обязан отличаться в /metrics от бинаря без
	// счётчика — иначе тишина трёх правил читается как успешное сужение.
	for _, h := range []string{"sys_enter_chmod", "sys_enter_fchmodat", "sys_enter_fchmod"} {
		for _, r := range []string{"ok", "error", "missing"} {
			FileHookAttach.WithLabelValues(h, r)
		}
	}

	ProcArgsDropped.WithLabelValues("stale_exec")
	ProcArgsDropped.WithLabelValues("argv0_mismatch")
}

// Global cardinality limiters for high-cardinality metrics.
// EventsTotal: limit pod (index 1) cardinality to prevent Prometheus OOM.
// AlertsTotal: limit namespace (index 2) cardinality.
var (
	eventsCardinalityLimiter = NewCardinalityLimiter(5000)  // 5K pod × 50 event types = conservative
	alertsCardinalityLimiter = NewCardinalityLimiter(10000) // 1K rule IDs × 10 namespaces
)

var (
	// EventsTotal counts all events by type and metadata.
	EventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_total",
			Help: "Total number of kernel events processed",
		},
		[]string{"type", "pod", "namespace", "node"},
	)

	// EventsDropped counts dropped events by collector and reason.
	EventsDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_dropped_total",
			Help: "Total number of events dropped by reason",
		},
		[]string{"collector", "reason"},
	)

	// EventsEmittedKernel counts events the kernel actually produced — a
	// successful bpf_ringbuf_reserve() on the shared `events` ring buffer —
	// by collector. This is the left-hand side of 5.9.6b's (№72) event
	// balance identity: emitted_kernel == events_total + Σdropped +
	// excluded + malformed. Without it, "how many events happened" could
	// only be inferred from events_total, which is measured downstream of
	// every filter and therefore cannot detect a filter eating events it
	// shouldn't.
	EventsEmittedKernel = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_emitted_kernel_total",
			Help: "Total number of events the kernel produced (successful ring-buffer reserve), by collector",
		},
		[]string{"collector"},
	)

	// EventsDroppedFraction is the share of events lost in the most recent
	// sampling window, per queue priority ("protected" / "bulk").
	//
	// P0-25: the absolute counter alone hid the problem. Run #4 dropped 24 426
	// network events — a number that reads as unremarkable next to 4 million
	// file events, while actually being 52% of all network traffic. The ratio
	// is the figure an alert rule can usefully threshold on.
	EventsDroppedFraction = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_events_dropped_fraction",
			Help: "Fraction of events dropped in the last window (0-1), by queue priority",
		},
		[]string{"priority"},
	)

	// EventsMalformed counts ring-buffer records that failed a wire-format
	// sanity check before being handed to a collector's normal parse path, by
	// collector and reason.
	//
	// Wave 5.9.2c (finding #40): a prior investigation (5.9.1f) diagnosed 13
	// empty-`comm` alerts as a torn read on the cgroup-escape path and shipped
	// a /proc fallback there — but every one of those 13 alerts was on the
	// syscall path, which cgroup-escape events never touch. This counter
	// exists to name the real source with evidence instead of guessing again:
	// "type_mismatch" (record's own Type field doesn't match the collector
	// reading it — the record is not what the parser assumes it is),
	// "nr_not_monitored" (syscall nr falls outside the in-kernel allowlist
	// that should have dropped it before it ever reached userspace), and
	// "empty_comm" (comm is a leading NUL after the first two hypotheses are
	// ruled out, i.e. a genuine kernel-side torn/unfilled read on this path).
	EventsMalformed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_events_malformed_total",
			Help: "Ring-buffer records that failed a wire-format sanity check, by collector and reason (type_mismatch, nr_not_monitored, empty_comm)",
		},
		[]string{"collector", "reason"},
	)

	// ProcArgsDropped counts execve records whose argv was fetched but then
	// discarded because the collector could not prove the record belongs to
	// the completed exec (6.0j/№210). Reasons:
	//   "stale_exec"      — primary path: proc_args_map holds an entry whose
	//                       exec_ts is not older than this record, i.e. this
	//                       is the sys_enter record of the execve;
	//   "argv0_mismatch"  — fallback path (/proc/PID/cmdline, or a kernel
	//                       object predating exec_ts): basename(argv[0]) does
	//                       not prefix comm, which is also what a spoofed
	//                       argv[0] and every login shell ("-bash") look like.
	// The second reason is the blindness finding №210 named, made measurable:
	// growth here is proc.args the fallback path threw away, and with it every
	// rule of that class that would have matched.
	ProcArgsDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_proc_args_dropped_total",
			Help: "execve records whose argv was discarded before enrichment, by reason (stale_exec, argv0_mismatch)",
		},
		[]string{"reason"},
	)

	// AlertsTotal counts generated alerts by rule, severity, namespace, pod, and node.
	// Pod and node are required for the fleet-wide Grafana dashboard to attribute
	// alerts to a specific pod/node without relying on Prometheus scrape relabeling.
	AlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_alerts_total",
			Help: "Total number of security alerts generated",
		},
		[]string{"rule_id", "severity", "namespace", "pod", "node"},
	)

	// AlertsFiltered counts alerts held back from AlertsTotal and the alert
	// store by store.min_severity (wave 5.1a). Labelled by rule_id and severity
	// so suppressed volume stays attributable: the point of filtering at the
	// intake is to shrink the counter, and without this metric that shrink
	// would be indistinguishable from detection silently stopping. Rules stay
	// loaded and keep firing — nothing is deleted, only kept out of the two
	// sinks whose volume the idle-rate criterion measures.
	AlertsFiltered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_alerts_filtered_total",
			Help: "Alerts excluded from ebpf_guard_alerts_total and the alert store by store.min_severity. The rule still fired; this is the suppressed volume, kept visible so filtering cannot be mistaken for lost detection.",
		},
		[]string{"rule_id", "severity"},
	)

	// ProfilerAnomalyScore tracks anomaly scores per process.
	ProfilerAnomalyScore = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_anomaly_score",
			Help: "Current anomaly score for each process",
		},
		[]string{"pid", "comm"},
	)

	// BPFMapEntries tracks the number of entries in BPF maps.
	BPFMapEntries = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_map_entries",
			Help: "Current number of entries in BPF maps",
		},
		[]string{"map_name"},
	)

	// BPFMapSize tracks the maximum capacity of BPF maps.
	BPFMapSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_map_size",
			Help: "Maximum capacity of BPF maps",
		},
		[]string{"map_name"},
	)

	// TrackedPIDs tracks the number of processes currently monitored by the profiler.
	TrackedPIDs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_tracked_pids_total",
			Help: "Number of PIDs currently tracked by the profiler.",
		},
	)

	// CollectorUp indicates whether each collector is successfully loaded (1) or in stub/failed state (0).
	CollectorUp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_collector_up",
			Help: "Whether the collector is up (1) or down/stub (0)",
		},
		[]string{"collector"},
	)

	// LogLinesTotal counts log lines by level.
	LogLinesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_log_lines_total",
			Help: "Total number of log lines by level",
		},
		[]string{"level"},
	)

	// BPFLostEvents counts events lost in the kernel ring buffer for the
	// collectors that back it with a real kernel-side counter (syscall,
	// network, fileaccess, privesc — the four sharing the events ring buffer
	// via reserve_event()/reserve_event_with_sampling(), see bpf/common.h's
	// ringbuf_full_counters and 5.9.6a in plan.md, №71). For every other
	// collector this series still reports the pre-5.9.6a meaning: events
	// dropped when the collector's own output channel was full — a
	// userspace hop, not a kernel one, already counted under
	// ebpf_guard_events_dropped_total{reason="ringbuf_to_router"}. That
	// double meaning is a known residual of 5.9.6a, not a design choice —
	// see plan.md 5.9.6a for which collectors are which.
	// Incremented by the watchdog drop-tracking loop every 10 seconds from
	// each collector's DropTracker.LostEvents().
	BPFLostEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_lost_events_total",
			Help: "Total number of events lost: kernel ring-buffer-full for syscall/network/fileaccess/privesc, consumer backpressure for other collectors (5.9.6a, see plan.md)",
		},
		[]string{"collector"},
	)

	// CorrelationDuration measures the latency of event correlation in seconds.
	CorrelationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ebpf_guard_correlation_duration_seconds",
			Help:    "Latency of event correlation in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{}, // No labels for now
	)

	// LearningProgress tracks the progress of the profiler learning phase (0.0-1.0).
	LearningProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_learning_progress",
			Help: "Progress of the behavioral learning phase (0.0-1.0)",
		},
	)

	// LearningComplete indicates whether the profiler learning phase has
	// finished (1) or is still in progress (0).
	LearningComplete = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_learning_complete",
			Help: "1 if the behavioral learning phase is complete, 0 if still learning",
		},
	)

	// LearningSecondsRemaining tracks the estimated time left in the profiler
	// learning phase. 0 once learning is complete.
	LearningSecondsRemaining = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_learning_seconds_remaining",
			Help: "Estimated seconds remaining in the behavioral learning phase",
		},
	)

	// ProfilerStateRestored indicates whether the EWMA profiler state was
	// successfully loaded from disk on startup (1) or the agent started fresh (0).
	// Use this to confirm that rolling DaemonSet updates preserve the learned baseline.
	ProfilerStateRestored = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_profiler_state_restored",
			Help: "1 if EWMA profiler state was loaded from disk on startup, 0 if fresh start",
		},
	)

	// RuleChecksumValid indicates whether the last rule checksum verification
	// passed (1) or failed (0). Only meaningful when rules.verify_checksums is true.
	RuleChecksumValid = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_rules_checksum_valid",
			Help: "1 if rule file checksums were verified successfully, 0 if verification failed or was not run",
		},
	)

	// BPFMapFull counts BPF map insert failures due to the map being at capacity.
	// Drained from the per-CPU map_full_counters BPF array by the watchdog loop.
	// A non-zero value means events are being silently dropped at the kernel level.
	BPFMapFull = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_map_full_total",
			Help: "Total BPF map insert failures due to map capacity limit, by map name",
		},
		[]string{"map_name"},
	)

	// CountingCanaryTotal counts fileaccess events whose path matches the
	// counting-control canary prefix (CountingCanaryPathPrefix), by pipeline
	// stage ("events" for events that reached the correlator, "dropped" for
	// events lost to output-channel backpressure before reaching it).
	//
	// plan.md 5.9.8b (№91): criterion 20's known-N counting control used to
	// read Δevents_total{type="file"} and Δevents_dropped_total{collector=
	// "fileaccess"} — both series count every file event on the host, not
	// just the canary's, so the residual after subtracting N was really
	// N-plus-whatever-background-happened-during-the-window. 5.9.7a
	// estimated that background with a separate null-mode run and subtracted
	// it; this series removes the need to estimate anything by only ever
	// counting events whose path IS the canary's, which no unrelated
	// background process on the host can produce. The path-prefix compare
	// happens once, in userspace, on the already-parsed event (see
	// IsCountingCanaryPath / cmd/ebpf-guard/main.go) — not in the BPF
	// fileaccess hot path, which runs at millions of events per ten minutes
	// and cannot absorb an unbudgeted string compare per event without risking
	// the throughput regression named as risk №3 of постановка №2.9.8.
	CountingCanaryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_counting_canary_total",
			Help: "Fileaccess events whose path matches the counting-control canary prefix, by pipeline stage (events, dropped)",
		},
		[]string{"stage"},
	)
)

// CountingCanaryPathPrefix is the path prefix run-all-attacks.sh's
// run_counting_control() uses for its generator files
// (/tmp/ebpf-guard-counting-canary-$TIMESTAMP-$mode). Any fileaccess event
// whose path starts with this prefix is, by construction, an artifact of
// that harness step and never of ordinary host activity — see
// CountingCanaryTotal.
const CountingCanaryPathPrefix = "/tmp/ebpf-guard-counting-canary-"

// IsCountingCanaryPath reports whether path was produced by the
// counting-control canary generator.
func IsCountingCanaryPath(path string) bool {
	return strings.HasPrefix(path, CountingCanaryPathPrefix)
}

// RecordCountingCanary increments CountingCanaryTotal for the given pipeline
// stage ("events" or "dropped").
func RecordCountingCanary(stage string) {
	CountingCanaryTotal.WithLabelValues(stage).Inc()
}

// RecordEvent increments the events counter for the given type.
// Deprecated: Use RecordEventWithLabels to provide proper pod/namespace/node labels.
func RecordEvent(eventType string) {
	EventsTotal.WithLabelValues(eventType, "", "", "").Inc()
}

// RecordEventWithLabels increments the events counter with proper K8s metadata.
// Under normal operation all of pod/namespace/node are recorded verbatim; if the
// series count ever exceeds the cardinality limit (e.g. pod churn, or a node
// label misconfigured to a per-pod value) pod, namespace, and node all collapse
// to "other" so total series stay bounded by the event type alone.
func RecordEventWithLabels(eventType, podName, namespace, node string) {
	labels := []string{eventType, podName, namespace, node}
	// Collapse pod(1)/namespace(2)/node(3) to "other" if the limit is exceeded.
	labels = eventsCardinalityLimiter.Normalize(labels, 1, 2, 3)
	EventsTotal.WithLabelValues(labels[0], labels[1], labels[2], labels[3]).Inc()
}

// EventTypeLabel converts an EventType to the short string used as the
// "type" label on ebpf_guard_events_total. Both TCP connect and close collapse
// to "network" so the metric groups connection lifecycle under one label; every
// other type defers to the canonical types.EventType.String() name. The switch
// enumerates every EventType explicitly (rather than a bare default) so the
// exhaustive linter catches new event types that need a label decision here.
func EventTypeLabel(t types.EventType) string {
	switch t {
	case types.EventTCPConnect, types.EventNetClose:
		return "network"
	case types.EventSyscall, types.EventFileAccess, types.EventTLS, types.EventDNS,
		types.EventPrivesc, types.EventKmodLoad, types.EventCgroupEsc, types.EventGPU,
		types.EventLSMAudit, types.EventSequence, types.EventCloudAudit, types.EventIOUring,
		types.EventBPFProgram:
		return t.String()
	default:
		return "other"
	}
}

// RecordDropped increments the dropped events counter with reason.
func RecordDropped(collector, reason string) {
	EventsDropped.WithLabelValues(collector, reason).Inc()
}

// RecordDroppedN adds n to the dropped events counter with reason. Used when
// the drop count is read as a periodic delta from a BPF counter (e.g. the
// P1-18b path-filter drop map) rather than observed one event at a time.
func RecordDroppedN(collector, reason string, n uint64) {
	EventsDropped.WithLabelValues(collector, reason).Add(float64(n))
}

// RecordEmittedKernelN adds n to the kernel-emitted events counter for
// collector. Used when the count is read as a periodic delta from a BPF
// counter (events_emitted_counters, 5.9.6b) rather than observed one event
// at a time.
func RecordEmittedKernelN(collector string, n uint64) {
	EventsEmittedKernel.WithLabelValues(collector).Add(float64(n))
}

// FileHookAttach counts attach outcomes of the file collector's chmod hooks
// (волна 6.2.1, слой 3), by tracepoint and result: "ok", "error" (the
// tracepoint exists but attach failed), "missing" (the program is absent from
// the loaded object — a kernel object built before the layer).
//
// Смысл счётчика — сделать «ноль алертов о смене прав» читаемым. Три правила
// переехали с syscall-оси на файловую; если хуки не привязались, они молчат,
// и без этой серии тишина неотличима от «chmod никто не звал» — то есть от
// успешного сужения.
var FileHookAttach = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ebpf_guard_file_hook_attach_total",
		Help: "File-collector hook attach outcomes, by tracepoint and result (ok, error, missing)",
	},
	[]string{"hook", "result"},
)

// ChmodUnresolved counts chmod file events whose target path could not be
// resolved — fchmod(2) on a descriptor opened before the agent started, or
// evicted from the fd→path LRU. Such events match no path-scoped rule, so
// this series is what separates "nothing changed permissions where it
// matters" from "we never learned which file it was" (волна 6.2.1, слой 3).
var ChmodUnresolved = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "ebpf_guard_file_chmod_unresolved_total",
		Help: "chmod file events delivered without a resolved target path (fchmod on a pre-agent or LRU-evicted descriptor)",
	},
)

// RecordChmodUnresolved counts one chmod event with an unresolved path.
func RecordChmodUnresolved() { ChmodUnresolved.Inc() }

// RecordFileHookAttach records one attach outcome for a file-collector hook.
func RecordFileHookAttach(hook, result string) {
	FileHookAttach.WithLabelValues(hook, result).Inc()
}

// RecordProcArgsDropped increments the proc.args drop counter with reason.
// See ProcArgsDropped for the reason vocabulary.
func RecordProcArgsDropped(reason string) {
	ProcArgsDropped.WithLabelValues(reason).Inc()
}

// RecordMalformed increments the malformed-record counter with reason. See
// EventsMalformed for the reason vocabulary.
func RecordMalformed(collector, reason string) {
	EventsMalformed.WithLabelValues(collector, reason).Inc()
}

// dropHop identifies which pipeline hop a drop happened at, paired with the
// collector name, for the per-hop/per-collector breakdown RecordEventDrop
// keeps alongside the Prometheus counter.
type dropHop struct {
	collector string
	hop       string
}

var (
	lastHighPriorityDropTime atomic.Int64 // UnixNano; 0 = never
	lastLowPriorityDropTime  atomic.Int64 // UnixNano; 0 = never

	// highPriorityDropTotal/lowPriorityDropTotal count every drop RecordEventDrop
	// sees, at either hop. Wave 5.9.9.F.3g (finding #139): the degradation-status
	// verdict (lastHighPriorityDropTime/lastLowPriorityDropTime, above) already
	// looked at both hops, but the caller in cmd/ebpf-guard/main.go fed
	// EventsDroppedFraction and the "visibility reduced" log line from a local
	// counter that only ever counted the router_to_queue hop — so a run losing
	// events only at ringbuf_to_router could log "degraded" next to
	// protected_dropped_in_window=0 and EventsDroppedFraction=0.0. These totals
	// give the caller a hop-agnostic numerator so the printed drop count can
	// never read zero while the verdict it sits next to says degraded.
	highPriorityDropTotal atomic.Int64
	lowPriorityDropTotal  atomic.Int64

	dropBreakdownMu sync.Mutex
	dropBreakdown   = map[dropHop]uint64{}
)

// RecordEventDrop records a dropped event at a named pipeline hop for a
// collector and marks the shared high/low-priority drop-time watcher that
// degradation-status computation reads.
//
// Wave 5.9.2a (finding #38): before this function existed, only the
// router_to_queue hop (PriorityEventCollector's internal hand-off channel)
// fed the watcher — the earlier ringbuf_to_router hop, where every one of the
// ten collectors' readLoops drops events when their own output channel is
// full, updated only the Prometheus counter. A collector could lose every
// event at that hop and /health would still report healthy, because the
// watcher never heard about it. Both hops now call this one function, using
// the same priority classification (see defaultEventPriority) so a drop is
// never invisible to degradation status depending on which hop it happened
// at.
func RecordEventDrop(collector, hop string, highPriority bool) {
	EventsDropped.WithLabelValues(collector, hop).Inc()

	now := time.Now().UnixNano()
	if highPriority {
		lastHighPriorityDropTime.Store(now)
		highPriorityDropTotal.Add(1)
	} else {
		lastLowPriorityDropTime.Store(now)
		lowPriorityDropTotal.Add(1)
	}

	dropBreakdownMu.Lock()
	dropBreakdown[dropHop{collector, hop}]++
	dropBreakdownMu.Unlock()
}

// HighPriorityDropTotal returns the cumulative count of high-priority
// (protected-queue) drops recorded via RecordEventDrop at ANY hop —
// ringbuf_to_router and router_to_queue alike (see highPriorityDropTotal).
func HighPriorityDropTotal() int64 { return highPriorityDropTotal.Load() }

// LowPriorityDropTotal returns the cumulative count of low-priority
// (bulk-queue) drops recorded via RecordEventDrop at ANY hop — see
// HighPriorityDropTotal.
func LowPriorityDropTotal() int64 { return lowPriorityDropTotal.Load() }

// LastHighPriorityDropTime returns the UnixNano timestamp of the most recent
// high-priority (protected-queue) drop recorded via RecordEventDrop, or 0 if
// none has happened yet.
func LastHighPriorityDropTime() int64 { return lastHighPriorityDropTime.Load() }

// LastLowPriorityDropTime returns the UnixNano timestamp of the most recent
// low-priority (bulk-queue) drop recorded via RecordEventDrop, or 0 if none
// has happened yet.
func LastLowPriorityDropTime() int64 { return lastLowPriorityDropTime.Load() }

// DropBreakdownSnapshot returns a point-in-time copy of cumulative drops per
// (collector, hop), keyed as "collector/hop", for use in the degraded-status
// log line — so an operator can tell "losing fim signal" (fileaccess/
// ringbuf_to_router) from "shedding file noise" (a different collector or
// hop) instead of seeing only the aggregate protected/bulk counters.
func DropBreakdownSnapshot() map[string]uint64 {
	dropBreakdownMu.Lock()
	defer dropBreakdownMu.Unlock()
	out := make(map[string]uint64, len(dropBreakdown))
	for k, v := range dropBreakdown {
		out[k.collector+"/"+k.hop] = v
	}
	return out
}

// RecordAlert increments the alerts counter for the given rule, severity,
// namespace, pod, and node. Under normal operation all labels are recorded
// verbatim; if the series count exceeds the cardinality limit, namespace, pod,
// and node all collapse to "other" so total series stay bounded by
// rule_id × severity (rule_id and severity are inherently low-cardinality).
func RecordAlert(ruleID, severity, namespace, podName, node string) {
	labels := []string{ruleID, severity, namespace, podName, node}
	// Collapse namespace(2)/pod(3)/node(4) to "other" if the limit is exceeded.
	labels = alertsCardinalityLimiter.Normalize(labels, 2, 3, 4)
	AlertsTotal.WithLabelValues(labels[0], labels[1], labels[2], labels[3], labels[4]).Inc()
}

// RecordAlertFiltered increments the suppressed-alert counter for an alert held
// back by store.min_severity. Labels are rule_id and severity only: both are
// bounded by the ruleset, so unlike RecordAlert this needs no cardinality guard.
func RecordAlertFiltered(ruleID, severity string) {
	AlertsFiltered.WithLabelValues(ruleID, severity).Inc()
}

// FilterAlertsForIntake splits alerts into those admitted to
// ebpf_guard_alerts_total and the alert store, and those held back by
// minSeverity, recording each held-back alert in ebpf_guard_alerts_filtered_total
// (wave 5.1a).
//
// Why this exists at all: wave 5.1 downgraded the seven-rule daemon cluster to
// info and the idle alert rate did not move (4986/hour against a <1000 target).
// alerts_total counts every alert regardless of severity, so a severity change
// alone cannot reduce volume — the tier has to be kept out of the intake, not
// merely relabelled. Rules stay loaded and keep firing; their output moves to
// the filtered counter rather than disappearing (порядок работы, п. 8).
//
// A minSeverity of "info" (the default) admits everything and returns the input
// slice unchanged, so the pre-5.1a path allocates nothing.
func FilterAlertsForIntake(alerts []types.Alert, minSeverity types.Severity) []types.Alert {
	if minSeverity == types.SeverityInfo || len(alerts) == 0 {
		return alerts
	}
	admitted := make([]types.Alert, 0, len(alerts))
	for _, a := range alerts {
		if types.SeverityAtLeast(a.Severity, minSeverity) {
			admitted = append(admitted, a)
			continue
		}
		RecordAlertFiltered(a.RuleID, string(a.Severity))
	}
	return admitted
}

// SetBPFMapEntries sets the entry count for a BPF map.
func SetBPFMapEntries(mapName string, count float64) {
	BPFMapEntries.WithLabelValues(mapName).Set(count)
}

// SetBPFMapSize sets the maximum capacity for a BPF map.
func SetBPFMapSize(mapName string, size float64) {
	BPFMapSize.WithLabelValues(mapName).Set(size)
}

// SetTrackedPIDs sets the number of currently tracked PIDs.
func SetTrackedPIDs(n float64) {
	TrackedPIDs.Set(n)
}

// RecordBPFMapFull increments the map-full counter by delta for the given map name.
// Called by the watchdog/collector drain loop after reading map_full_counters from BPF.
func RecordBPFMapFull(mapName string, delta uint64) {
	if delta > 0 {
		BPFMapFull.WithLabelValues(mapName).Add(float64(delta))
	}
}

// SetCollectorUp sets the collector up/down status (1 = up, 0 = down/stub).
func SetCollectorUp(collector string, up bool) {
	value := float64(0)
	if up {
		value = 1
	}
	CollectorUp.WithLabelValues(collector).Set(value)
}

// CollectorStatusReporter implements collector.StatusReporter using the global
// Prometheus CollectorUp gauge. Collectors should accept this interface rather
// than importing the exporter package directly.
type CollectorStatusReporter struct{}

// SetUp sets the named collector's up/down Prometheus gauge.
func (CollectorStatusReporter) SetUp(name string, up bool) {
	SetCollectorUp(name, up)
}

// RecordLogLine increments the log lines counter for the given level.
func RecordLogLine(level string) {
	LogLinesTotal.WithLabelValues(level).Inc()
}

// RecordCorrelationDuration records the duration of correlation processing.
func RecordCorrelationDuration(duration float64) {
	CorrelationDuration.WithLabelValues().Observe(duration)
}

// SetLearningProgress sets the learning progress gauge (0.0-1.0).
func SetLearningProgress(progress float64) {
	LearningProgress.Set(progress)
}

// SetLearningComplete sets the learning-complete gauge: 1 if the behavioral
// learning phase has finished, 0 if still learning.
func SetLearningComplete(complete bool) {
	if complete {
		LearningComplete.Set(1)
	} else {
		LearningComplete.Set(0)
	}
}

// SetLearningSecondsRemaining sets the estimated seconds remaining in the
// behavioral learning phase.
func SetLearningSecondsRemaining(remaining time.Duration) {
	LearningSecondsRemaining.Set(remaining.Seconds())
}

// SetProfilerStateRestored sets the state-restored gauge: 1 if EWMA state was
// loaded from disk, 0 if the agent started fresh.
func SetProfilerStateRestored(restored bool) {
	if restored {
		ProfilerStateRestored.Set(1)
	} else {
		ProfilerStateRestored.Set(0)
	}
}

// SetRuleChecksumValid sets the checksum validation gauge: 1 if verification
// passed, 0 if it failed or was not performed.
func SetRuleChecksumValid(valid bool) {
	if valid {
		RuleChecksumValid.Set(1)
	} else {
		RuleChecksumValid.Set(0)
	}
}

// AddBPFLost increments the BPF ring buffer lost events counter for a collector.
func AddBPFLost(collector string, n uint64) {
	BPFLostEvents.WithLabelValues(collector).Add(float64(n))
}

var (
	// EventQueueDepth tracks the current number of events waiting in the
	// in-process channel between collectors and the correlation engine.
	EventQueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_event_queue_depth",
			Help: "Current number of events buffered in the correlation engine input queue",
		},
	)

	// EventQueueCapacity tracks the maximum capacity of the event queue channel.
	EventQueueCapacity = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_event_queue_capacity",
			Help: "Maximum capacity of the correlation engine input queue",
		},
	)

	// EventQueueOverflow counts events dropped because the queue was full.
	EventQueueOverflow = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_guard_event_queue_dropped_total",
			Help: "Total number of events dropped due to event queue overflow",
		},
	)

	// GoroutinePoolActive tracks the number of goroutines actively processing
	// events in the bounded worker pool.
	GoroutinePoolActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_goroutine_pool_active",
			Help: "Number of goroutines currently processing events in the worker pool",
		},
	)
)

// RecordQueueDepth updates the event queue depth and capacity gauges.
func RecordQueueDepth(depth, capacity int) {
	EventQueueDepth.Set(float64(depth))
	EventQueueCapacity.Set(float64(capacity))
}

// RecordQueueOverflow increments the overflow counter (event dropped due to full queue).
func RecordQueueOverflow() {
	EventQueueOverflow.Inc()
}

// SetGoroutinePoolActive sets the active worker count gauge.
func SetGoroutinePoolActive(n int64) {
	GoroutinePoolActive.Set(float64(n))
}

// RecordAnomaly increments the anomalies counter.
func RecordAnomaly() {
	AnomaliesTotal.Inc()
}

var (
	// GPUEventsTotal counts GPU/CUDA events by operation type.
	GPUEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_gpu_events_total",
			Help: "Total number of GPU/CUDA events processed, by operation type",
		},
		[]string{"op"},
	)
)

// RecordGPUEvent increments the GPU events counter for the given operation name.
func RecordGPUEvent(op string) {
	GPUEventsTotal.WithLabelValues(op).Inc()
}

// ── Kubernetes enricher metrics ───────────────────────────────────────────────

var (
	// K8sEnricherCachePods tracks the number of unique pods in the watcher cache.
	K8sEnricherCachePods = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_k8s_enricher_cache_pods",
			Help: "Number of unique pods currently tracked in the Kubernetes enricher cache",
		},
		[]string{"node"},
	)

	// K8sEnricherCacheStaleness tracks seconds elapsed since the last watcher sync.
	K8sEnricherCacheStaleness = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_k8s_enricher_cache_staleness_seconds",
			Help: "Seconds elapsed since the Kubernetes enricher last received data from the API server",
		},
		[]string{"node"},
	)

	// K8sEnricherLastSync records the Unix timestamp of the last successful watcher sync.
	K8sEnricherLastSync = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_guard_k8s_enricher_last_sync_timestamp_seconds",
			Help: "Unix timestamp of the last successful Kubernetes enricher sync",
		},
		[]string{"node"},
	)

	// K8sEnricherMissTotal counts enrichment lookups that found no matching pod.
	K8sEnricherMissTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_guard_k8s_enricher_miss_total",
			Help: "Total number of event enrichment lookups that found no matching pod in the cache",
		},
		[]string{"node"},
	)

	// AnomaliesTotal counts the total number of behavioral anomalies detected.
	AnomaliesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_guard_anomalies_total",
			Help: "Total number of behavioral anomalies detected by the profiler",
		},
	)
)
