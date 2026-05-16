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

// FileaccessCollector collects file access events using eBPF kprobes.
type FileaccessCollector struct {
	logger    *slog.Logger
	objs      *bpf.FileaccessObjects
	links     []link.Link
	reader    *bpf.RingbufReader
	loadError error // Tracks if the collector failed to load (stub mode)
}

// NewFileaccessCollector creates a new file access event collector.
func NewFileaccessCollector(logger *slog.Logger) (*FileaccessCollector, error) {
	return &FileaccessCollector{
		logger: logger.With("collector", "fileaccess"),
	}, nil
}

// Name returns the collector identifier.
func (c *FileaccessCollector) Name() string {
	return "fileaccess"
}

// Start attaches eBPF programs and begins sending events.
// Blocks until ctx is cancelled.
func (c *FileaccessCollector) Start(ctx context.Context, out chan<- types.Event) error {
	c.logger.Info("starting fileaccess collector")

	// Load eBPF objects
	if err := c.loadObjects(); err != nil {
		c.loadError = err
		exporter.SetCollectorUp("fileaccess", false)
		return fmt.Errorf("collector/fileaccess: load eBPF objects: %w", err)
	}

	// Attach kprobes
	if err := c.attachPrograms(); err != nil {
		c.loadError = err
		exporter.SetCollectorUp("fileaccess", false)
		c.Close()
		return fmt.Errorf("collector/fileaccess: attach programs: %w", err)
	}

	// Create ring buffer reader
	reader, err := bpf.NewRingbufReader(c.objs.Events)
	if err != nil {
		c.loadError = err
		exporter.SetCollectorUp("fileaccess", false)
		c.Close()
		return fmt.Errorf("collector/fileaccess: create ringbuf reader: %w", err)
	}
	c.reader = reader
	c.loadError = nil
	exporter.SetCollectorUp("fileaccess", true)

	// Start reading loop
	go c.readLoop(ctx, out)

	// Wait for context cancellation
	<-ctx.Done()
	c.logger.Info("stopping fileaccess collector")
	return nil
}

// IsHealthy returns true if the collector loaded successfully.
func (c *FileaccessCollector) IsHealthy() bool {
	return c.loadError == nil && c.objs != nil
}

// LoadError returns the error from failed load, if any.
func (c *FileaccessCollector) LoadError() error {
	return c.loadError
}

// Close releases all eBPF resources.
func (c *FileaccessCollector) Close() error {
	c.logger.Info("closing fileaccess collector")

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
func (c *FileaccessCollector) loadObjects() error {
	c.objs = &bpf.FileaccessObjects{}
	if err := bpf.LoadFileaccessObjects(c.objs, &ebpf.CollectionOptions{}); err != nil {
		return err
	}
	return nil
}

// attachPrograms attaches the eBPF programs to kprobes.
func (c *FileaccessCollector) attachPrograms() error {
	// Attach do_sys_openat2 kprobe (modern replacement for do_sys_open)
	l1, err := link.Kprobe("do_sys_openat2", c.objs.TraceOpen, nil)
	if err != nil {
		// Fallback to older kernel interface
		l1, err = link.Kprobe("do_sys_open", c.objs.TraceOpen, nil)
		if err != nil {
			return fmt.Errorf("attach open kprobe: %w", err)
		}
	}
	c.links = append(c.links, l1)

	// Attach vfs_read kprobe
	l2, err := link.Kprobe("vfs_read", c.objs.TraceRead, nil)
	if err != nil {
		c.logger.Warn("failed to attach vfs_read kprobe, continuing without read tracking", "error", err)
	} else {
		c.links = append(c.links, l2)
	}

	// Attach vfs_write kprobe
	l3, err := link.Kprobe("vfs_write", c.objs.TraceWrite, nil)
	if err != nil {
		c.logger.Warn("failed to attach vfs_write kprobe, continuing without write tracking", "error", err)
	} else {
		c.links = append(c.links, l3)
	}

	return nil
}

// readLoop reads events from the ring buffer and sends them to the output channel.
func (c *FileaccessCollector) readLoop(ctx context.Context, out chan<- types.Event) {
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
			exporter.RecordDropped("fileaccess", "parse_error")
			continue
		}

		// Send event (non-blocking)
		select {
		case out <- *event:
		default:
			c.logger.Warn("event channel full, dropping event")
			exporter.RecordDropped("fileaccess", "channel_full")
		}
	}
}

// parseEvent converts raw bytes from ring buffer to types.Event.
func (c *FileaccessCollector) parseEvent(raw []byte) (*types.Event, error) {
	evt, err := bpf.ParseFileaccessEvent(raw)
	if err != nil {
		return nil, err
	}
	result := evt.ToTypesEvent()
	return &result, nil
}
