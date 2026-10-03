package collector

import (
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/exporter"
)

// newEventRingReader opens the reader for a collector's events ring and wires
// the wave 8.1 item 6 toggle: netpoll=false is the blocking epoll_wait path
// cilium/ebpf has always used, netpoll=true parks on the Go runtime poller
// instead (see internal/bpf/ringbuf_netpoll.go for the sysmon mechanism this
// removes).
//
// The mode gauge is set from reader.Mode(), i.e. from what the reader ENDED UP
// doing, not from the flag that was asked for: a dup or a poller registration
// that the kernel refuses downgrades the reader silently as far as the stream
// is concerned, and an A/B that read the request instead of the result would
// label an OFF window as ON ([[entry-guard-must-read-runtime-not-config]]).
func newEventRingReader(logger *slog.Logger, name string, m *ebpf.Map, netpoll bool) (*bpf.RingbufReader, error) {
	reader, err := bpf.NewRingbufReaderWithOptions(m, bpf.RingbufReaderOptions{
		Name:    name,
		Netpoll: netpoll,
		OnWait: func() {
			exporter.RecordRingbufNetpollPark(name)
		},
		OnFallback: func(reason, detail string) {
			exporter.RecordRingbufNetpollFallback(name, reason)
			logger.Warn("ring buffer netpoll wait unavailable, using the blocking path",
				slog.String("collector", name),
				slog.String("reason", reason),
				slog.String("detail", detail))
		},
	})
	if err != nil {
		return nil, err
	}

	exporter.SetRingbufWaitMode(name, reader.Mode())
	logger.Info("ring buffer wait path",
		slog.String("collector", name),
		slog.String("mode", reader.Mode()))
	return reader, nil
}
