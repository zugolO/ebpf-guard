// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/ja3"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TLSFingerprintCollector captures TLS ClientHello messages at the socket
// level via a kprobe on sendto, parses them to extract TLS handshake fields,
// computes JA3 and JA4 fingerprints, and emits enriched TLS events for C2
// framework detection (Cobalt Strike, Sliver, Mythic, etc.).
type TLSFingerprintCollector struct {
	logger      *slog.Logger
	objs        *bpf.TlsClientHelloObjects
	links       []link.Link
	reader      *ringbuf.Reader
	loadError   error
	dropLogger  *dropLogger
	status      StatusReporter
	strategy    BackpressureStrategy
	ringBufSize int
	lostTotal   atomic.Uint64
}

// NewTLSFingerprintCollector creates a new TLS fingerprint collector.
func NewTLSFingerprintCollector(logger *slog.Logger) (*TLSFingerprintCollector, error) {
	return &TLSFingerprintCollector{
		logger:     logger.With("collector", "tlsfingerprint"),
		dropLogger: newDropLogger(5 * time.Second),
		status:     NoopStatusReporter{},
		strategy:   StrategyDrop,
	}, nil
}

// WithStatusReporter sets the StatusReporter used to signal up/down state.
func (c *TLSFingerprintCollector) WithStatusReporter(r StatusReporter) *TLSFingerprintCollector {
	c.status = r
	return c
}

// WithBackpressureStrategy sets the backpressure strategy for the event channel.
func (c *TLSFingerprintCollector) WithBackpressureStrategy(s BackpressureStrategy) *TLSFingerprintCollector {
	c.strategy = s
	return c
}

// WithRingBufSize sets the ring buffer size for the eBPF program.
func (c *TLSFingerprintCollector) WithRingBufSize(sizeBytes int) *TLSFingerprintCollector {
	c.ringBufSize = sizeBytes
	return c
}

// Name returns the collector identifier.
func (c *TLSFingerprintCollector) Name() string {
	return "tlsfingerprint"
}

// Start attaches eBPF programs and begins sending events.
func (c *TLSFingerprintCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting tlsfingerprint collector")

	if err := c.loadObjects(); err != nil {
		c.loadError = err
		c.status.SetUp("tlsfingerprint", false)
		return fmt.Errorf("collector/tlsfingerprint: load eBPF objects: %w", err)
	}

	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		c.status.SetUp("tlsfingerprint", false)
		c.Close()
		return fmt.Errorf("collector/tlsfingerprint: attach programs: %w", err)
	}

	reader, err := ringbuf.NewReader(c.objs.TlsClienthelloEvents)
	if err != nil {
		c.loadError = err
		c.status.SetUp("tlsfingerprint", false)
		c.Close()
		return fmt.Errorf("collector/tlsfingerprint: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	c.status.SetUp("tlsfingerprint", true)

	go c.readLoop(ctx, out)

	<-ctx.Done()
	c.logger.Info("stopping tlsfingerprint collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *TLSFingerprintCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *TLSFingerprintCollector) LoadError() error {
	return c.loadError
}

// GetPrograms returns the loaded BPF programs for attestation.
func (c *TLSFingerprintCollector) GetPrograms() map[string]*ebpf.Program {
	if c.objs == nil {
		return nil
	}
	return map[string]*ebpf.Program{
		"trace_sendto": c.objs.TraceSendto,
	}
}

// IsAttached returns true if the BPF programs are still attached.
func (c *TLSFingerprintCollector) IsAttached() bool {
	return len(c.links) > 0
}

// Reload attempts to reload the BPF programs.
func (c *TLSFingerprintCollector) Reload() error {
	c.logger.Info("reloading tlsfingerprint collector")
	if err := c.Close(); err != nil {
		c.logger.Warn("error closing during reload", slog.Any("error", err))
	}
	if err := c.loadObjects(); err != nil {
		return fmt.Errorf("reload objects: %w", err)
	}
	if err := c.attachPrograms(); err != nil {
		c.Close()
		return fmt.Errorf("re-attach programs: %w", err)
	}
	c.logger.Info("tlsfingerprint collector reloaded successfully")
	return nil
}

// Close releases all eBPF resources.
func (c *TLSFingerprintCollector) Close() error {
	c.logger.Info("closing tlsfingerprint collector")
	if c.reader != nil {
		c.reader.Close()
	}
	for _, l := range c.links {
		l.Close()
	}
	c.links = nil
	if c.objs != nil {
		c.objs.Close()
		c.objs = nil
	}
	return nil
}

// LostEvents returns the total number of events lost in the BPF ring buffer.
func (c *TLSFingerprintCollector) LostEvents() uint64 {
	return c.lostTotal.Load()
}

// loadObjects loads the eBPF objects using bpf2go generated code.
func (c *TLSFingerprintCollector) loadObjects() error {
	ringSize := bpf.ComputeRingBufSize(bpf.RingBufSizeConfig{SizeBytes: c.ringBufSize})
	c.logger.Info("tlsfingerprint collector ring buffer size", slog.Int("bytes", ringSize))
	c.objs = &bpf.TlsClientHelloObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "",
		},
	}
	_ = ringSize
	if err := bpf.LoadTlsClientHelloObjects(c.objs, opts); err != nil {
		return fmt.Errorf("load tls_clienthello objects: %w", err)
	}
	return nil
}

// attachPrograms attaches a kprobe to __x64_sys_sendto.
func (c *TLSFingerprintCollector) attachPrograms() error {
	lnk, err := link.Kprobe("__x64_sys_sendto", c.objs.TraceSendto, nil)
	if err != nil {
		return fmt.Errorf("attach kprobe __x64_sys_sendto: %w", err)
	}
	c.links = append(c.links, lnk)
	return nil
}

// readLoop reads events from the ring buffer, parses ClientHello data,
// computes JA3/JA4 fingerprints, and sends enriched TLS events to the
// output channel.
func (c *TLSFingerprintCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			c.logger.Error("failed to read from tlsfingerprint ringbuf", "error", err)
			continue
		}

		rawEvt, err := bpf.ParseTlsClientHelloEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse tlsfingerprint event", "error", err)
			exporter.RecordDropped("tlsfingerprint", "parse_error")
			continue
		}

		event := rawEvt.ToTypesEvent()

		// Compute JA3 and JA4 from the captured ClientHello data.
		chData := rawEvt.Data[:rawEvt.CapturedLen]
		if ja3Hash, ja3Err := ja3.ComputeJA3(chData); ja3Err == nil {
			event.TLS.JA3 = ja3Hash
		}
		if ja4Hash, ja4Err := ja3.ComputeJA4(chData); ja4Err == nil {
			event.TLS.JA4 = ja4Hash
		}

		if c.logger.Enabled(ctx, slog.LevelDebug) {
			c.logger.Debug("tlsfingerprint event",
				slog.Uint64("pid", uint64(event.PID)),
				slog.String("ja3", event.TLS.JA3),
				slog.String("ja4", event.TLS.JA4),
			)
		}

		sendEvent(ctx, out, event, c.strategy, func() {
			exporter.RecordDropped("tlsfingerprint", "channel_full")
			c.dropLogger.record(c.logger, "tlsfingerprint")
			c.lostTotal.Add(1)
		})
	}
}
