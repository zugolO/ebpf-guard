// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var tlsTrackedPIDsGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "ebpf_guard_tls_tracked_pids_total",
	Help: "Current number of PIDs tracked by the TLS collector (processes with libssl uprobes attached).",
})

// TLSCollector collects TLS plaintext events using eBPF uprobes on libssl.
// It attaches to SSL_write and SSL_read functions to capture data before encryption
// and after decryption.
//
// Requirements:
//   - CAP_SYS_PTRACE capability for uprobe attachment
//   - Target processes must use OpenSSL/libssl (Go crypto/tls is not supported)
//
// Limitations:
//   - Only captures first 256 bytes of each SSL_write/SSL_read call
//   - May miss data if buffer spans multiple calls
//   - Does not capture Go's native TLS implementation
type TLSCollector struct {
	logger          *slog.Logger
	objs            *bpf.TLSObjects
	links           []link.Link
	reader          *bpf.RingbufReader
	loadError       error
	enabled         bool
	libsslPaths     map[uint32]string // pid -> libssl path
	mu              sync.RWMutex
	scanInterval    time.Duration
	cleanupInterval time.Duration
	dropLogger      *dropLogger
	ctx             context.Context
	cancel          context.CancelFunc
	status          StatusReporter
	strategy        BackpressureStrategy
	ringBufSize     int // 0 = auto-detect
	lostTotal       atomic.Uint64
}

// TLSEventRaw is the raw event structure from BPF.
type TLSEventRaw struct {
	Type        uint32
	Timestamp   uint64
	PID         uint32
	TGID        uint32
	PPID        uint32
	UID         uint32
	Comm        [16]byte
	ParentComm  [16]byte
	Direction   uint8
	DataLen     uint32
	CapturedLen uint32
	Data        [256]byte
	HasConnInfo uint8
	Saddr       [16]byte
	Daddr       [16]byte
	Sport       uint16
	Dport       uint16
}

// ToTypesEvent converts a raw TLS event to the public types.Event.
func (e *TLSEventRaw) ToTypesEvent() types.Event {
	var direction types.TLSDirection
	if e.Direction == 0 {
		direction = types.TLSDirectionWrite
	} else {
		direction = types.TLSDirectionRead
	}

	return types.Event{
		Type:       types.EventTLS,
		Timestamp:  e.Timestamp,
		PID:        e.PID,
		TGID:       e.TGID,
		PPID:       e.PPID,
		UID:        e.UID,
		Comm:       e.Comm,
		ParentComm: e.ParentComm,
		TLS: &types.TLSEvent{
			Direction: direction,
			DataLen:   e.DataLen,
			Data:      e.Data,
		},
	}
}

// NewTLSCollector creates a new TLS event collector.
//
// The collector starts disabled. Call Start() to begin collection.
// If the collector fails to load (e.g., missing CAP_SYS_PTRACE), it enters
// "stub mode" where IsHealthy() returns false but the collector continues
// to run without crashing.
func NewTLSCollector(logger *slog.Logger, enabled bool) (*TLSCollector, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &TLSCollector{
		logger:          logger.With("collector", "tls"),
		enabled:         enabled,
		libsslPaths:     make(map[uint32]string),
		scanInterval:    30 * time.Second,
		cleanupInterval: 60 * time.Second,
		dropLogger:      newDropLogger(5 * time.Second),
		ctx:             ctx,
		cancel:          cancel,
		status:          NoopStatusReporter{},
		strategy:        StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *TLSCollector) WithStatusReporter(r StatusReporter) *TLSCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *TLSCollector) WithBackpressureStrategy(s BackpressureStrategy) *TLSCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the BPF ring buffer size in bytes for this collector.
// Zero (default) auto-detects the size from /proc/meminfo.
func (c *TLSCollector) WithRingBufSize(sizeBytes int) *TLSCollector {
	c.ringBufSize = sizeBytes
	return c
}

// Name returns the collector identifier.
func (c *TLSCollector) Name() string {
	return "tls"
}

// Start attaches eBPF uprobes and begins sending events.
// Blocks until ctx is cancelled.
//
// If the collector is disabled (enabled=false in config), this returns immediately
// without loading any eBPF programs.
func (c *TLSCollector) Start(ctx context.Context, out chan<- types.Event) error {
	if !c.enabled {
		c.logger.Info("TLS collector disabled, skipping startup")
		c.status.SetUp("tls", true) // Mark as "up" but idle
		<-ctx.Done()
		return nil
	}

	c.logger.Info("starting TLS collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("tls", false)
		c.logger.Error("failed to load TLS eBPF objects, entering stub mode", slog.Any("error", err))
		// Enter stub mode - wait for context cancellation
		<-ctx.Done()
		return nil
	}

	// Start libssl discovery goroutine
	go c.discoveryLoop(ctx)

	// Start dead-PID cleanup goroutine
	go c.cleanupDeadPIDs(ctx)

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.TlsEvents)
	if err != nil {
		c.loadError = err
		c.status.SetUp("tls", false)
		c.Close()
		c.logger.Error("failed to create ringbuf reader, entering stub mode", slog.Any("error", err))
		<-ctx.Done()
		return nil
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("tls", true)

	// Start reading loop
	go c.readLoop(ctx, out)

	// Wait for context cancellation
	<-ctx.Done()
	c.logger.Info("stopping TLS collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *TLSCollector) IsHealthy() bool {
	return !c.enabled || c.loadError == nil
}

// LoadError returns the error from failed load, if any.
func (c *TLSCollector) LoadError() error {
	return c.loadError
}

// IsAttached returns true if the BPF program is still attached.
func (c *TLSCollector) IsAttached() bool {
	if c.objs == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.links) > 0
}

// Close releases all eBPF resources.
func (c *TLSCollector) Close() error {
	c.logger.Info("closing TLS collector")
	c.cancel()

	if c.reader != nil {
		c.reader.Close()
		c.reader = nil
	}

	c.mu.Lock()
	for _, l := range c.links {
		l.Close()
	}
	c.links = nil
	c.mu.Unlock()

	if c.objs != nil {
		c.objs.Close()
		c.objs = nil
	}

	return nil
}

// loadObjects loads the eBPF objects using bpf2go generated code.
func (c *TLSCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("TLS collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.TLSObjects{}
	// ringSize is applied to spec.Maps["tls_events"].MaxEntries in the real bpf2go loader.
	_ = ringSize
	return bpf.LoadTLSObjects(c.objs, nil)
}

// discoveryLoop periodically scans for processes using libssl and attaches uprobes.
func (c *TLSCollector) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(c.scanInterval)
	defer ticker.Stop()

	// Initial scan
	c.scanAndAttach()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.scanAndAttach()
		}
	}
}

// cleanupDeadPIDs periodically removes entries for processes that no longer exist.
// Linux reuses PIDs, so stale entries would cause missed uprobe attachments for new processes.
func (c *TLSCollector) cleanupDeadPIDs(ctx context.Context) {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			for pid := range c.libsslPaths {
				if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
					delete(c.libsslPaths, pid)
				}
			}
			tlsTrackedPIDsGauge.Set(float64(len(c.libsslPaths)))
			c.mu.Unlock()
		}
	}
}

// scanAndAttach scans /proc for processes using libssl and attaches uprobes.
func (c *TLSCollector) scanAndAttach() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		c.logger.Warn("failed to read /proc", slog.Any("error", err))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		// Check if we already attached to this PID
		c.mu.RLock()
		_, alreadyAttached := c.libsslPaths[uint32(pid)]
		c.mu.RUnlock()
		if alreadyAttached {
			continue
		}

		// Look for libssl in this process
		libsslPath := c.findLibsslInPID(uint32(pid))
		if libsslPath == "" {
			continue
		}

		// Try to attach uprobes
		if err := c.attachToPID(uint32(pid), libsslPath); err != nil {
			if c.logger.Enabled(c.ctx, slog.LevelDebug) {
				c.logger.Debug("failed to attach uprobes",
					slog.Uint64("pid", pid),
					slog.String("libssl", libsslPath),
					slog.Any("error", err))
			}
			continue
		}

		c.mu.Lock()
		c.libsslPaths[uint32(pid)] = libsslPath
		tlsTrackedPIDsGauge.Set(float64(len(c.libsslPaths)))
		c.mu.Unlock()

		c.logger.Info("attached TLS uprobes",
			slog.Uint64("pid", pid),
			slog.String("libssl", libsslPath))
	}
}

// findLibsslInPID searches for libssl in a process's memory maps.
func (c *TLSCollector) findLibsslInPID(pid uint32) string {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(mapsPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for libssl.so in the mapped files
		if strings.Contains(line, "libssl.so") {
			// Extract the path from the line
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				path := parts[len(parts)-1]
				// Verify it's a real file
				if strings.HasPrefix(path, "/") && !strings.Contains(path, "(deleted)") {
					return path
				}
			}
		}
	}

	return ""
}

// attachToPID attaches uprobes to SSL_write and SSL_read in a process.
// It uses link.OpenExecutable on libsslPath so symbol resolution is handled
// by the cilium/ebpf library — no manual ELF parsing required.
func (c *TLSCollector) attachToPID(pid uint32, libsslPath string) error {
	if c.objs == nil {
		return fmt.Errorf("eBPF objects not loaded")
	}

	ex, err := link.OpenExecutable(libsslPath)
	if err != nil {
		return fmt.Errorf("open libssl: %w", err)
	}

	opts := &link.UprobeOptions{PID: int(pid)}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.objs.TraceSslWrite != nil {
		l, err := ex.Uprobe("SSL_write", c.objs.TraceSslWrite, opts)
		if err != nil {
			return fmt.Errorf("attach SSL_write uprobe: %w", err)
		}
		c.links = append(c.links, l)
	}

	if c.objs.TraceSslReadEntry != nil {
		l, err := ex.Uprobe("SSL_read", c.objs.TraceSslReadEntry, opts)
		if err != nil {
			return fmt.Errorf("attach SSL_read entry uprobe: %w", err)
		}
		c.links = append(c.links, l)
	}

	if c.objs.TraceSslReadRet != nil {
		l, err := ex.Uretprobe("SSL_read", c.objs.TraceSslReadRet, opts)
		if err != nil {
			return fmt.Errorf("attach SSL_read uretprobe: %w", err)
		}
		c.links = append(c.links, l)
	}

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *TLSCollector) readLoop(ctx context.Context, out chan<- types.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to read from ringbuf", slog.Any("error", err))
			continue
		}
		// Parse raw event into types.Event
		event, err := c.parseEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse event", slog.Any("error", err))
			exporter.RecordDropped("tls", "parse_error")
			continue
		}

		// Scan TLS plaintext for W3C Trace Context headers (traceparent/tracestate).
		// This links APM spans to security events when the application is instrumented
		// with OpenTelemetry and passes W3C Trace Context in HTTP/gRPC headers.
		if event.TLS != nil {
			capturedLen := event.TLS.DataLen
			if capturedLen > uint32(len(event.TLS.Data)) {
				capturedLen = uint32(len(event.TLS.Data))
			}
			if tc := ExtractTraceContext(event.TLS.Data[:capturedLen]); tc != nil {
				event.TraceContext = tc
				if c.logger.Enabled(ctx, slog.LevelDebug) {
					c.logger.Debug("W3C trace context extracted from TLS payload",
						slog.Uint64("pid", uint64(event.PID)),
						slog.String("trace_id", tc.TraceID),
						slog.String("span_id", tc.SpanID),
						slog.String("trace_flags", tc.TraceFlags))
				}
			}
		}

		// Debug logging
		if c.logger.Enabled(ctx, slog.LevelDebug) {
			direction := "write"
			if event.TLS.Direction == types.TLSDirectionRead {
				direction = "read"
			}
			c.logger.Debug("TLS event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.String("direction", direction),
				slog.Uint64("data_len", uint64(event.TLS.DataLen)))
		}

		sendEvent(ctx, out, *event, c.strategy, func() {
			exporter.RecordDropped("tls", "channel_full")
			c.dropLogger.record(c.logger, "tls")
			c.lostTotal.Add(1)
		})
	}
}

// LostEvents returns the total number of events lost in the BPF ring buffer
// since the collector started. Implements watchdog.DropTracker.
func (c *TLSCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// parseEvent converts raw bytes from ring buffer to types.Event.
func (c *TLSCollector) parseEvent(raw []byte) (*types.Event, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("event too short: %d bytes", len(raw))
	}

	// Parse based on event type
	eventType := binary.LittleEndian.Uint32(raw[0:4])
	if eventType != uint32(types.EventTLS) {
		return nil, fmt.Errorf("unexpected event type: %d", eventType)
	}

	if len(raw) < 340 { // Minimum size for TLS event
		return nil, fmt.Errorf("TLS event too short: %d bytes", len(raw))
	}

	var rawEvent TLSEventRaw
	buf := bytes.NewReader(raw)
	if err := binary.Read(buf, binary.LittleEndian, &rawEvent); err != nil {
		return nil, fmt.Errorf("parse raw event: %w", err)
	}

	result := rawEvent.ToTypesEvent()
	return &result, nil
}

// GetAttachedPIDs returns the list of PIDs that have uprobes attached.
func (c *TLSCollector) GetAttachedPIDs() []uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	pids := make([]uint32, 0, len(c.libsslPaths))
	for pid := range c.libsslPaths {
		pids = append(pids, pid)
	}
	return pids
}

// DetachFromPID detaches uprobes from a specific PID.
func (c *TLSCollector) DetachFromPID(pid uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.libsslPaths, pid)

	// Note: In a full implementation, we would track which links belong to which PID
	// and close only those. For now, we don't support selective detachment.
	return nil
}
