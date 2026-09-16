// Package collector provides eBPF event collection for DNS monitoring.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// The DNS wire-format parsing logic (decodeDNSEvent, parseDNSWireMessage,
// decodeDNSName, decodeDNSAnswerIPs and the qtype/rcode string helpers) lives
// in dns_parse.go. It is kernel-independent and unit-tested directly; this file
// holds only the eBPF load/attach/read glue.

// DNSCollector collects DNS events via eBPF tracepoints.
type DNSCollector struct {
	objs       *bpf.DNSObjects
	links      []link.Link
	reader     *ringbuf.Reader
	metrics    *dnsMetrics
	enabled    bool
	dropLogger *dropLogger
	strategy   BackpressureStrategy
	lostTotal  atomic.Uint64
	// eventsSeen counts records read from the ring buffer. Published by the
	// read loop and consumed by watchForStaleness, which cannot observe the
	// loop directly because reader.Read() blocks exactly when there is nothing
	// to see (P0-26).
	eventsSeen atomic.Uint64
	// lastEventUnixNano is the wall-clock time (UnixNano) the last event was
	// read, or zero before the first event. watchForStaleness compares against
	// this directly instead of a once-per-tick snapshot — see 5.7d.
	lastEventUnixNano atomic.Int64
	// decodeErrorLoggers holds one rate-limited hex-dump logger per
	// dnsDecodeReason* value (5.9.5c), mirroring the syscall collector's
	// malformedLoggers (5.9.2c) — the counter alone says a reason fired, the
	// sample is what lets a human confirm which of the three №64/№65
	// hypotheses (stand silence, parse regression, or collector regression)
	// it actually is.
	decodeErrorLoggers map[string]*malformedLogger
	// minEventsPerStaleWindow is the floor watchForStaleness enforces on
	// events accumulated over the trailing dnsStaleThreshold window, on top
	// of the pre-existing zero-events check. 0 (the default) disables it —
	// see the doc comment on watchForStaleness for why a universal non-zero
	// default would be a guess this package has no basis for.
	minEventsPerStaleWindow int
	// stale mirrors metrics.stale without requiring a Prometheus registry
	// read — SetCollectorStale (open question 4, №328) polls this directly
	// so per-collector staleness reaches GET /health, not only /metrics.
	stale atomic.Bool
}

// dnsMetrics holds Prometheus metrics for DNS collection.
type dnsMetrics struct {
	queriesTotal  *prometheus.CounterVec
	eventsDropped prometheus.Counter
	// decodeErrors separates "the collector saw nothing" from "the collector
	// saw traffic it could not parse" — P0-26 could not distinguish these.
	// Labelled by reason (wave 5.9.5c, findings №64/№65): a single unlabelled
	// counter could not tell "molecular silence" (rules never seeing traffic)
	// apart from "traffic arrives but decodeDNSEvent rejects it", which is
	// exactly the ambiguity that left four DNS rules silent on №2.9.4 without
	// anyone being able to say which of those it was.
	decodeErrors *prometheus.CounterVec
	// stale is 1 while the collector has produced no events for staleThreshold
	// despite being enabled and attached. This is the metric that would have
	// surfaced P0-26 (7 events for an entire run, reported as healthy:true).
	stale prometheus.Gauge
	// staleTransitions counts entries into the stale state. 5.7d: the stale
	// gauge alone can only be checked at snapshot time, which misses a window
	// of transient stale periods that recovered before the snapshot was taken
	// (the exact failure the idle-hour gate needs to catch). A monotonic
	// counter lets the gate require zero over the whole window instead.
	staleTransitions prometheus.Counter
	// socketMapBackfilled counts dns_socket_map entries seeded at startup
	// from sockets already connect()ed to port 53 (№328) — the mechanism
	// that closes the coredns-persistent-upstream-socket blind spot. Zero
	// is a legitimate reading (no pre-connected DNS sockets existed at
	// startup); this metric exists so 6.3.0 can tell "the mechanism ran
	// and found nothing" apart from "the mechanism didn't run".
	socketMapBackfilled prometheus.Counter
	// socketMapBackfillCandidates counts connected-to-:53 socket inodes
	// found across all network namespaces BEFORE matching them against
	// process fds (№341) — backfilled alone cannot tell "nothing to seed"
	// (candidates==0) apart from "found sockets but the fd match/insert
	// step lost them" (candidates>0, backfilled<candidates).
	socketMapBackfillCandidates prometheus.Counter
}

// NewDNSCollector creates a new DNS collector.
func NewDNSCollector(enabled bool) (*DNSCollector, error) {
	if !enabled {
		return &DNSCollector{enabled: false, dropLogger: newDropLogger(5 * time.Second)}, nil
	}

	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("dns: remove memlock: %w", err)
	}

	metrics := &dnsMetrics{
		queriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_queries_total",
			Help: "Total number of DNS queries by QTYPE and RCODE",
		}, []string{"qtype", "rcode"}),
		eventsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_events_dropped_total",
			Help: "Total number of dropped DNS events due to ring buffer overflow",
		}),
		decodeErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_decode_errors_total",
			Help: "Total number of DNS event decode errors, by reason (too_short, not_a_query, bad_qname, payload_too_large, truncated_payload, compression_loop, bad_header, unparseable)",
		}, []string{"reason"}),
		stale: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_dns_collector_stale",
			Help: "1 when the DNS collector has seen no events for an extended period despite being attached",
		}),
		staleTransitions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_collector_stale_transitions_total",
			Help: "Total number of times the DNS collector transitioned into the stale state. A gate can require zero over a window without depending on the state at snapshot time.",
		}),
		socketMapBackfilled: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_socket_map_backfilled_total",
			Help: "Total number of dns_socket_map entries seeded at startup from UDP sockets already connected to port 53 (sockets a resolver opened before the agent started, which trace_connect alone would never see).",
		}),
		socketMapBackfillCandidates: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_dns_socket_map_backfill_candidates_total",
			Help: "Total number of UDP sockets connected to port 53 found across all network namespaces at startup, before matching them to process file descriptors. Compare against ebpf_guard_dns_socket_map_backfilled_total: candidates==0 means nothing to seed, candidates>backfilled means sockets were found but not all could be matched/inserted.",
		}),
	}

	decodeErrorLoggers := make(map[string]*malformedLogger, len(dnsDecodeReasons))
	for _, reason := range dnsDecodeReasons {
		decodeErrorLoggers[reason] = newMalformedLogger(5 * time.Second)
	}

	return &DNSCollector{
		enabled:            enabled,
		metrics:            metrics,
		dropLogger:         newDropLogger(5 * time.Second),
		strategy:           StrategyDrop,
		decodeErrorLoggers: decodeErrorLoggers,
	}, nil
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *DNSCollector) WithBackpressureStrategy(s BackpressureStrategy) *DNSCollector {
	c.strategy = s
	return c
}

// WithMinEventsPerStaleWindow sets the minimum number of events
// watchForStaleness requires over the trailing dnsStaleThreshold window
// before it stops treating the collector as stale-by-rate (№328, item 4 of
// wave 6.3's Фаза 0). n <= 0 disables the check, which is also the
// zero-value default — this package has no basis for guessing a universal
// "plausible DNS rate" floor across deployments; an operator who knows
// their node's traffic sets it via collectors.dns.min_events_per_stale_window.
func (c *DNSCollector) WithMinEventsPerStaleWindow(n int) *DNSCollector {
	c.minEventsPerStaleWindow = n
	return c
}

// Stale reports the collector's current staleness state — the same value
// published as ebpf_guard_dns_collector_stale, but readable without a
// Prometheus registry so GET /health can surface it per-collector (open
// question 4). Safe to call concurrently; false before the first
// watchForStaleness tick.
func (c *DNSCollector) Stale() bool {
	return c.stale.Load()
}

// RegisterMetrics registers Prometheus metrics.
func (c *DNSCollector) RegisterMetrics(reg prometheus.Registerer) error {
	if !c.enabled || c.metrics == nil {
		return nil
	}
	if err := reg.Register(c.metrics.queriesTotal); err != nil {
		return err
	}
	if err := reg.Register(c.metrics.eventsDropped); err != nil {
		return err
	}
	if err := reg.Register(c.metrics.decodeErrors); err != nil {
		return err
	}
	// Materialise every reason at zero so the series exist in /metrics from
	// the first scrape, the same way enforcer.RegisterMetrics primes its
	// action labels. Without this a clean run publishes no
	// ebpf_guard_dns_decode_errors_total lines at all, and the 5.9.5c gate
	// section cannot tell "no decode errors happened" — which is the answer
	// finding №65 is asking for — from "this binary predates the reason
	// label". A CounterVec with no observations is silence, not a zero.
	for _, reason := range dnsDecodeReasons {
		c.metrics.decodeErrors.WithLabelValues(reason)
	}
	if err := reg.Register(c.metrics.stale); err != nil {
		return err
	}
	if err := reg.Register(c.metrics.staleTransitions); err != nil {
		return err
	}
	if err := reg.Register(c.metrics.socketMapBackfilled); err != nil {
		return err
	}
	return reg.Register(c.metrics.socketMapBackfillCandidates)
}

// Start begins collecting DNS events.
func (c *DNSCollector) Start(ctx context.Context, out chan<- types.Event) error {
	if !c.enabled {
		slog.Info("dns: collector disabled, skipping")
		return nil
	}

	// The "limitations" note is deliberately part of the startup line: P0-26
	// showed that a collector which starts cleanly and reports healthy reads as
	// working, so its blind spots have to be stated where they will be seen.
	slog.Info("dns: starting collector",
		slog.String("strategy", string(c.strategy)),
		slog.String("visibility", "AF_INET (IPv4) UDP port 53 only"),
		slog.String("blind_spots", "IPv6 and TCP DNS; resolution via systemd-resolved's AF_UNIX varlink path (nss-resolve); sockets connected before the agent started"),
	)

	objs := &bpf.DNSObjects{}
	if err := bpf.LoadDNSObjects(objs, nil); err != nil {
		// The default Error() string only includes the last line or two of
		// the verifier log. %+v with no width prints every line the kernel
		// returned, which is what we need to see what's actually pushing
		// trace_sendmsg past the instruction limit.
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			if werr := os.WriteFile("/tmp/dns_verifier.log", []byte(fmt.Sprintf("%+v", verr)), 0644); werr != nil {
				slog.Error("dns: failed to write verifier log", slog.Any("error", werr))
			} else {
				slog.Error("dns: wrote full verifier log to /tmp/dns_verifier.log")
			}
		}
		return fmt.Errorf("dns: load objects: %w", err)
	}
	c.objs = objs

	// №328/plan.md §6.3: seed dns_socket_map with sockets already
	// connect()ed to port 53 before trace_connect could see them — see
	// backfillDNSSocketMap's doc comment (dns_backfill.go) for why this
	// exists. Best-effort: a failure here is a narrower blind spot
	// (falls back to the pre-existing "sockets connected before start are
	// invisible" behaviour), not a reason to abort startup.
	if candidates, n, err := backfillDNSSocketMap(c.objs.DnsSocketMap); err != nil {
		slog.Warn("dns: dns_socket_map backfill failed — sockets connected before agent start will stay invisible until they reconnect", slog.Any("error", err))
	} else {
		slog.Info("dns: dns_socket_map backfilled from all network namespaces' /proc/<pid>/net/udp", slog.Int("candidates", candidates), slog.Int("sockets", n))
		if c.metrics != nil {
			c.metrics.socketMapBackfillCandidates.Add(float64(candidates))
			c.metrics.socketMapBackfilled.Add(float64(n))
		}
	}

	links, err := c.attachTracepoints()
	if err != nil {
		c.objs.Close()
		return fmt.Errorf("dns: attach tracepoints: %w", err)
	}
	c.links = links

	reader, err := ringbuf.NewReader(c.objs.DnsEvents)
	if err != nil {
		c.Close()
		return fmt.Errorf("dns: create ringbuf reader: %w", err)
	}
	c.reader = reader

	readLoopDone := runReadLoop(func() { c.readLoop(ctx, out) })

	// Wait for context cancellation, then for readLoop to actually stop
	// sending (5.8d) — Close() unblocks the ring buffer Read() readLoop may
	// be parked in, and Close() runs after ctx is already done.
	<-ctx.Done()
	<-readLoopDone
	return nil
}

// attachTracepoints attaches eBPF programs to tracepoints.
//
// sendmsg/sendto cover callers that pass an explicit destination address.
// connect/close plus sendmmsg/recvmsg/write/writev/read/recvfrom cover the
// glibc stub resolver pattern (confirmed via strace against real `dig`):
// connect() a UDP socket once, then sendmmsg()/recvmsg() (or plain
// write()/read()) on it with no destination address in the syscall args
// for BPF to filter on (see the dns_socket_map comment in dns.bpf.c).
func (c *DNSCollector) attachTracepoints() ([]link.Link, error) {
	specs := []struct {
		category string
		name     string
		prog     *ebpf.Program
	}{
		{"syscalls", "sys_enter_sendmsg", c.objs.TraceSendmsg},
		{"syscalls", "sys_enter_sendto", c.objs.TraceSendto},
		{"syscalls", "sys_enter_connect", c.objs.TraceConnect},
		{"syscalls", "sys_enter_close", c.objs.TraceClose},
		{"syscalls", "sys_enter_sendmmsg", c.objs.TraceSendmmsg},
		{"syscalls", "sys_enter_write", c.objs.TraceWrite},
		{"syscalls", "sys_enter_writev", c.objs.TraceWritev},
		{"syscalls", "sys_enter_recvmsg", c.objs.TraceRecvmsgEnter},
		{"syscalls", "sys_exit_recvmsg", c.objs.TraceRecvmsgExit},
		{"syscalls", "sys_enter_read", c.objs.TraceReadEnter},
		{"syscalls", "sys_exit_read", c.objs.TraceReadExit},
		{"syscalls", "sys_enter_recvfrom", c.objs.TraceRecvfromEnter},
		{"syscalls", "sys_exit_recvfrom", c.objs.TraceRecvfromExit},
	}

	var links []link.Link
	for _, s := range specs {
		l, err := link.Tracepoint(s.category, s.name, s.prog, nil)
		if err != nil {
			for _, prev := range links {
				prev.Close()
			}
			return nil, fmt.Errorf("attach %s tracepoint: %w", s.name, err)
		}
		links = append(links, l)
	}

	return links, nil
}

// readLoop reads events from the ring buffer.
func (c *DNSCollector) readLoop(ctx context.Context, out chan<- types.Event) {
	if c.reader == nil {
		slog.Warn("dns: no ring buffer reader, read loop exiting")
		return
	}

	defer c.reader.Close()

	// P0-26: watch for silence on a timer of its own.
	//
	// A staleness check placed inside this loop can never fire, because
	// reader.Read() blocks while no events arrive — the exact condition it is
	// meant to report. That is how the DNS collector delivered 7 events for a
	// whole run while reporting healthy:true. The watchdog therefore runs in a
	// separate goroutine and reads a counter this loop publishes.
	go c.watchForStaleness(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("dns: read loop exiting", slog.Uint64("total_events_seen", c.eventsSeen.Load()))
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			// Graceful shutdown: the ring buffer is closed either by Close()
			// or as the context is cancelled. Both race with this blocking
			// Read, so neither is an error worth an ERROR log line.
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			slog.Error("dns: read from ringbuf", slog.Any("error", err))
			continue
		}

		c.eventsSeen.Add(1)
		c.lastEventUnixNano.Store(time.Now().UnixNano())
		event, reason := decodeDNSEvent(record.RawSample)
		if event == nil {
			c.metrics.decodeErrors.WithLabelValues(reason).Inc()
			if logger := c.decodeErrorLoggers[reason]; logger != nil {
				// malformedLogger keeps only the first 48 bytes of what it's
				// given (collector.go), and the fixed dns_event header alone
				// (type+timestamp+pid+tgid+uid+comm+ppid+parent_comm+
				// direction+payload_len) is dnsRawEventFixedLen=63 bytes —
				// logging record.RawSample as-is can never reach the DNS
				// payload/qname bytes that actually failed to decode, only
				// ever showing header fields (pid/comm/parent_comm). Found
				// while investigating plan.md 5.9.6e/№74: the one "bad_qname"
				// sample_hex captured for the grafana idle event decoded
				// entirely to header fields, not a single payload byte.
				// too_short/unparseable mean the header itself didn't parse
				// (or wasn't a DNS event at all), so there is no reliable
				// payload offset to slice at — keep the raw dump for those.
				sample := record.RawSample
				var extra []slog.Attr
				if reason != dnsDecodeReasonTooShort && reason != dnsDecodeReasonUnparseable &&
					len(sample) > dnsRawEventFixedLen {
					sample = sample[dnsRawEventFixedLen:]
					// 5.9.6g: direction/payload_len distinguish the three
					// №65 hypotheses (sport-53 response, TCP-DNS/mDNS,
					// DNS_MAX_PAYLOAD truncation) without a human re-parsing
					// the hex dump by hand — see dnsHeaderDiagFields.
					if dir, plen, ok := dnsHeaderDiagFields(record.RawSample); ok {
						dirStr := "query"
						if dir == 1 {
							dirStr = "response"
						}
						extra = []slog.Attr{
							slog.String("direction", dirStr),
							slog.Int("payload_len", int(plen)),
							slog.Bool("at_dns_max_payload", int(plen) >= dnsMaxPayload),
						}
					}
				}
				logger.record(slog.Default().With(slog.String("collector", "dns")), reason, sample, extra...)
			}
			continue
		}

		// Update metrics
		c.metrics.queriesTotal.WithLabelValues(
			qtypeToString(event.DNS.QType),
			rcodeToString(event.DNS.RCode),
		).Inc()

		sendEvent(ctx, out, *event, c.strategy, func() {
			c.metrics.eventsDropped.Inc()
			exporter.RecordEventDrop("dns", "ringbuf_to_router", defaultEventPriority(event.Type))
			c.dropLogger.record(slog.Default().With(slog.String("collector", "dns")), "ringbuf_to_router")
			c.lostTotal.Add(1)
		})
	}
}

// dnsStaleThreshold is how long the collector may see zero events before it
// reports itself stale. Long enough that a quiet host does not flap, short
// enough that a whole attack run cannot pass unnoticed as it did in run #4.
//
// 5.9.9.F.4h (finding #150): the previous value, 5 minutes, was measured
// live to be SHORTER than the natural inter-burst gap on a quiet host —
// journal-agent-2.9.9.F.3.log showed 59 WARN/recovered pairs over an 11.5h
// idle run, every one of them exactly 312s apart, on a machine whose DNS
// bursts (~8 events) land roughly every 5 minutes. A threshold picked
// without margin above that cadence flags every single quiet gap as
// degraded visibility, which is the false-positive class this collector
// exists to avoid (P0-26). Raised to comfortably clear the observed 312s
// gap rather than sit just under it; still well inside "an attack run
// cannot pass unnoticed" (run #4's regression was on the order of the
// whole idle window, not a single burst gap).
const dnsStaleThreshold = 10 * time.Minute

// dnsStalePollInterval is how often watchForStaleness checks elapsed time
// since the last event. 5.7d: the previous design compared event counts once
// per dnsStaleThreshold tick, which measures events-per-tick-window, not
// elapsed-time-since-last-event — any tick boundary that happened to land
// between two events declared staleness even with a live collector, and
// "silent_for" was always exactly the threshold because it was the tick
// period, not a measurement. Polling well inside the threshold and comparing
// against the actual last-event timestamp makes staleness reflect real
// silence instead of tick alignment.
const dnsStalePollInterval = 30 * time.Second

// dnsRateStale reports whether the events-per-window rate check fires,
// pulled out of watchForStaleness's ticker loop so the decision is
// testable without waiting on real wall-clock time. minEventsPerStaleWindow
// <= 0 always returns false (disabled); windowFull is false until the
// trailing-window history buffer has accumulated dnsStaleThreshold worth of
// samples, before which there is no complete window to judge yet.
func dnsRateStale(minEventsPerStaleWindow int, windowFull bool, windowEvents uint64) bool {
	return minEventsPerStaleWindow > 0 && windowFull && windowEvents < uint64(minEventsPerStaleWindow)
}

// watchForStaleness reports "attached but seeing nothing" as a distinct state.
//
// P0-26's real defect was not that DNS saw no traffic — it may legitimately see
// none when systemd-resolved answers over AF_UNIX. The defect was that silence
// was indistinguishable from success: the collector logged "starting", reported
// healthy:true, and never said otherwise. Staleness is deliberately NOT
// unhealthy — the collector is not broken — but it must be visible.
//
// №328, item 4 of wave 6.3's Фаза 0: absolute silence is not the only shape
// degraded visibility takes. A node running coredns that reports 8 DNS
// events every 10 minutes forever never crosses silentFor — it is not
// silent, it is producing events at a rate implausible for that resolver
// (the mechanism turned out to be exactly the blind spot backfillDNSSocketMap
// closes, dns_backfill.go — but nss-resolve/AF_UNIX, TCP-DNS and IPv6
// remain, see the startup log's blind_spots field). The optional rate check
// below adds a second, independent trigger for the same stale state:
// events accumulated over the trailing dnsStaleThreshold window falling
// under minEventsPerStaleWindow. It stays off by default (0) because this
// package has no basis for guessing a "plausible" DNS rate for every
// deployment — an operator who knows their node's traffic sets the floor
// via collectors.dns.min_events_per_stale_window.
func (c *DNSCollector) watchForStaleness(ctx context.Context) {
	ticker := time.NewTicker(dnsStalePollInterval)
	defer ticker.Stop()

	start := time.Now()
	var reportedStale bool

	// windowTicks polls span dnsStaleThreshold; history holds one eventsSeen
	// snapshot per tick so windowEvents = current - history[0] once full is
	// "events seen in the trailing dnsStaleThreshold window". Unused (and
	// left empty) when minEventsPerStaleWindow is 0.
	windowTicks := int(dnsStaleThreshold / dnsStalePollInterval)
	history := make([]uint64, 0, windowTicks)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := c.eventsSeen.Load()

			lastEvent := c.lastEventUnixNano.Load()
			var silentFor time.Duration
			if lastEvent == 0 {
				// No event since startup: measure from process start, not
				// from the zero value, so silentFor is meaningful in logs.
				silentFor = time.Since(start)
			} else {
				silentFor = time.Since(time.Unix(0, lastEvent))
			}

			history = append(history, count)
			if len(history) > windowTicks {
				history = history[1:]
			}
			var windowEvents uint64
			if len(history) == windowTicks {
				windowEvents = count - history[0]
			}
			rateStale := dnsRateStale(c.minEventsPerStaleWindow, len(history) == windowTicks, windowEvents)

			if silentFor < dnsStaleThreshold && !rateStale {
				if reportedStale {
					slog.Info("dns: collector recovered, events flowing again",
						slog.Uint64("events_total", count))
					reportedStale = false
					c.metrics.stale.Set(0)
					c.stale.Store(false)
				}
				continue
			}

			if !reportedStale {
				reportedStale = true
				c.metrics.stale.Set(1)
				c.metrics.staleTransitions.Inc()
				c.stale.Store(true)

				// Rate-triggered and silence-triggered are reported with
				// different messages: "no new events" would be false (and
				// confusing to a human debugging it) for a collector that
				// IS producing events, just too few of them.
				if silentFor < dnsStaleThreshold {
					slog.Warn("dns: events arriving far below the configured floor — visibility into DNS may be partially absent",
						slog.Uint64("events_in_window", windowEvents),
						slog.Int("min_events_per_stale_window", c.minEventsPerStaleWindow),
						slog.Duration("window", dnsStaleThreshold),
						slog.Uint64("events_total", count),
						slog.String("likely_causes", "systemd-resolved answering over AF_UNIX (nss-resolve/varlink), IPv6 or TCP DNS, or resolver sockets connected before the agent started"),
						slog.String("verify", "run `dig example.com @8.8.8.8` repeatedly and compare ebpf_guard_dns_queries_total growth against the resolver's own query log"))
					continue
				}

				var lastSeenMsg string
				if lastEvent == 0 {
					lastSeenMsg = "never"
				} else {
					lastSeenMsg = time.Unix(0, lastEvent).Format(time.RFC3339)
				}
				// 5.8c: the old text ("has seen no events") contradicted its own
				// events_total field once the collector had already seen traffic —
				// this state is "no NEW events since last_seen", not "never saw any".
				slog.Warn("dns: no new events for silent_for — visibility into DNS may be absent, or the host may simply be quiet",
					slog.Duration("silent_for", silentFor.Round(time.Second)),
					slog.String("last_seen", lastSeenMsg),
					slog.Uint64("events_total", count),
					slog.String("likely_causes", "systemd-resolved answering over AF_UNIX (nss-resolve/varlink), IPv6 or TCP DNS, or resolver sockets connected before the agent started — or the host has genuinely not resolved anything in dnsStaleThreshold"),
					slog.String("verify", "run `dig example.com @8.8.8.8` and re-check ebpf_guard_events_total{type=\"dns\"}"))
			}
		}
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *DNSCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// Name returns the collector name.
func (c *DNSCollector) Name() string {
	return "dns"
}

// Close releases all eBPF resources.
func (c *DNSCollector) Close() error {
	for _, l := range c.links {
		l.Close()
	}
	if c.reader != nil {
		c.reader.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
	return nil
}

// Compile-time check that DNSCollector implements Collector interface.
var _ Collector = (*DNSCollector)(nil)
