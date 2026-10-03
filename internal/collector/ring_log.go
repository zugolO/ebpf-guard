package collector

import (
	"log/slog"

	"github.com/cilium/ebpf"
)

// logLoadedRing reports the size of the "events" ring AS LOADED, read from the
// kernel map, not computed from config. For the syscall/fileaccess/network
// collectors the size is fixed by the BPF object (the generated loader has no
// resize hook), so bpf.ring_buf_size does not reach them; the old pre-load log
// printed the computed 32 MiB for a ring that was in fact 4 MiB (wave 8.1
// item 14). A configured value that differs from the loaded one is called out
// instead of being silently ignored.
func logLoadedRing(logger *slog.Logger, name string, m *ebpf.Map, configured int) {
	if m == nil {
		return
	}
	loaded := int(m.MaxEntries())
	logger.Info(name+" collector ring buffer size", slog.Int("bytes", loaded))
	if configured > 0 && configured != loaded {
		logger.Warn(name+" collector: bpf.ring_buf_size is not applied to this ring (size fixed by the BPF object)",
			slog.Int("configured_bytes", configured), slog.Int("loaded_bytes", loaded))
	}
}
