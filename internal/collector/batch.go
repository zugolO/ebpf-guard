// Package collector provides batching optimizations for ring buffer reading.
package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// Ensure ringbuf.Reader implements SetDeadline method
// This is available in github.com/cilium/ebpf v0.16+
// Note: SetDeadline returns nothing, not error
var _ interface {
	SetDeadline(t time.Time)
} = (*ringbuf.Reader)(nil)

// BatchConfig configures batch reading behavior.
type BatchConfig struct {
	// BatchSize is the maximum number of events to read in one batch
	BatchSize int
	// BatchTimeout is the maximum time to wait for a full batch
	BatchTimeout time.Duration
	// MinEvents is the minimum number of events before sending (0 = send immediately)
	MinEvents int
}

// DefaultBatchConfig returns a default batch configuration optimized for throughput.
func DefaultBatchConfig() BatchConfig {
	return BatchConfig{
		BatchSize:    100,
		BatchTimeout: 10 * time.Millisecond,
		MinEvents:    1,
	}
}

// BatchReader wraps a ringbuf.Reader with batching capabilities.
type BatchReader struct {
	reader  *ringbuf.Reader
	config  BatchConfig
	logger  *slog.Logger
	metrics *BatchMetrics
}

// BatchMetrics tracks batch reading performance.
type BatchMetrics struct {
	BatchesRead   uint64
	EventsRead    uint64
	EventsDropped uint64
	AvgBatchSize  float64
	MaxBatchSize  int
	TotalWaitTime time.Duration
}

// NewBatchReader creates a new batch reader.
func NewBatchReader(reader *ringbuf.Reader, config BatchConfig, logger *slog.Logger) *BatchReader {
	return &BatchReader{
		reader:  reader,
		config:  config,
		logger:  logger,
		metrics: &BatchMetrics{},
	}
}

// ReadBatch reads a batch of events from the ring buffer.
// Returns when batch is full, timeout expires, or context is cancelled.
func (b *BatchReader) ReadBatch(ctx context.Context) ([]ringbuf.Record, error) {
	batch := make([]ringbuf.Record, 0, b.config.BatchSize)
	startTime := time.Now()
	deadline := startTime.Add(b.config.BatchTimeout)

	for len(batch) < b.config.BatchSize {
		// Check context
		select {
		case <-ctx.Done():
			return batch, ctx.Err()
		default:
		}

		// Calculate remaining timeout
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}

		// Try to read with timeout
		record, err := b.readWithTimeout(remaining)
		if err != nil {
			if err == context.DeadlineExceeded {
				// Timeout, return what we have
				break
			}
			// Check context cancellation after every Read() to avoid blocking shutdown.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return batch, ctxErr
			}
			return batch, err
		}

		// Check context again after a successful read — shutdown may have been
		// signalled while we were blocked in Read().
		if err := ctx.Err(); err != nil {
			return batch, err
		}

		batch = append(batch, record)
	}

	// Update metrics
	b.updateMetrics(len(batch), time.Since(startTime))

	return batch, nil
}

// readWithTimeout attempts to read from ring buffer with a timeout.
// Uses ringbuf.Reader.SetDeadline() for efficient timeout handling without goroutines.
func (b *BatchReader) readWithTimeout(timeout time.Duration) (ringbuf.Record, error) {
	// Set deadline on the reader - this is more efficient than spawning goroutines
	b.reader.SetDeadline(time.Now().Add(timeout))

	record, err := b.reader.Read()
	if err != nil {
		// Check if it's a timeout error
		if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
			return ringbuf.Record{}, context.DeadlineExceeded
		}
		return ringbuf.Record{}, err
	}

	return record, nil
}

// updateMetrics updates batch metrics.
func (b *BatchReader) updateMetrics(batchSize int, waitTime time.Duration) {
	b.metrics.BatchesRead++
	b.metrics.EventsRead += uint64(batchSize)
	b.metrics.TotalWaitTime += waitTime

	// Update average batch size
	b.metrics.AvgBatchSize = float64(b.metrics.EventsRead) / float64(b.metrics.BatchesRead)

	if batchSize > b.metrics.MaxBatchSize {
		b.metrics.MaxBatchSize = batchSize
	}
}

// GetMetrics returns current batch metrics.
func (b *BatchReader) GetMetrics() BatchMetrics {
	return *b.metrics
}

// Note: EventBatcher and BufferedCollector have been removed as they were
// unreachable dead code with no production call sites. The BatchReader type
// above is the primary batching mechanism used in production.
