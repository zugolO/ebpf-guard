// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ebpf-guard/ebpf-guard/internal/bpf"
	"github.com/ebpf-guard/ebpf-guard/internal/exporter"
	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// NetworkCollector collects TCP connection events using eBPF kprobes.
type NetworkCollector struct {
	logger    *slog.Logger
	objs      *bpf.NetworkObjects
	links     []link.Link
	reader    *bpf.RingbufReader
	loadError error // Tracks if the collector failed to load (stub mode)
}

// NewNetworkCollector creates a new network event collector.
func NewNetworkCollector(logger *slog.Logger) (*NetworkCollector, error) {
	return &NetworkCollector{
		logger: logger.With("collector", "network"),
	}, nil
}

// Name returns the collector identifier.
func (c *NetworkCollector) Name() string {
	return "network"
}

// Start attaches eBPF programs and begins sending events.
// Blocks until ctx is cancelled.
func (c *NetworkCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting network collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		exporter.SetCollectorUp("network", false)
		return fmt.Errorf("collector/network: load eBPF objects: %w", err)
	}

	// Attach kprobes
	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		exporter.SetCollectorUp("network", false)
		c.Close()
		return fmt.Errorf("collector/network: attach programs: %w", err)
	}

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		exporter.SetCollectorUp("network", false)
		c.Close()
		return fmt.Errorf("collector/network: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	exporter.SetCollectorUp("network", true)

	// Start reading loop
	go c.readLoop(ctx, out)

	// Wait for context cancellation
	<-ctx.Done()
	c.logger.Info("stopping network collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *NetworkCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *NetworkCollector) LoadError() error {
	return c.loadError
}

// Close releases all eBPF resources.
func (c *NetworkCollector) Close() error {
	c.logger.Info("closing network collector")

	if c.reader != nil {
		c.reader.Close()
		c.reader = nil
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

// loadObjects loads the eBPF objects using bpf2go generated code.
func (c *NetworkCollector) loadObjects() error {
	c.objs = &bpf.NetworkObjects{}
	if err := bpf.LoadNetworkObjects(c.objs, &ebpf.CollectionOptions{}); err != nil {
		return err
	}
	return nil
}

// attachPrograms attaches the eBPF programs to kprobes.
func (c *NetworkCollector) attachPrograms() error {
	// Attach tcp_connect kprobe
	l, err := link.Kprobe("tcp_connect", c.objs.TraceTCPConnect, nil)
	if err != nil {
		return fmt.Errorf("attach tcp_connect kprobe: %w", err)
	}
	c.links = append(c.links, l)

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *NetworkCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			c.logger.Error("failed to read from ringbuf", "error", err)
			continue
		}

		// Parse raw event into types.Event
		event, err := c.parseEvent(record.RawSample)
		if err != nil {
			c.logger.Error("failed to parse event", "error", err)
			exporter.RecordDropped("network", "parse_error")
			continue
		}

		// Send event (non-blocking)
		select {
		case out <- *event:
		default:
			c.logger.Warn("event channel full, dropping event")
			exporter.RecordDropped("network", "channel_full")
		}
	}
}

// parseEvent converts raw bytes from ring buffer to types.Event.
func (c *NetworkCollector) parseEvent(raw []byte) (*types.Event, error) {
	evt, err := bpf.ParseNetworkEvent(raw)
	if err != nil {
		return nil, err
	}
	result := evt.ToTypesEvent()
	return &result, nil
}
