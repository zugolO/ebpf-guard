package collector

import (
	"fmt"

	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// decodeNetworkEvent converts a raw ring-buffer sample into a types.Event by
// routing on the event-type field stored in the first four bytes (little-endian
// uint32). It has no kernel dependencies — only byte parsing — and is therefore
// exercised directly by unit tests without a running eBPF program.
func decodeNetworkEvent(raw []byte) (types.Event, error) {
	if len(raw) < 4 {
		return types.Event{}, fmt.Errorf("raw sample too short: %d bytes", len(raw))
	}
	// Read event type from the first 4 bytes (little-endian uint32).
	evtType := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24

	//nolint:exhaustive // only net_close needs special handling; the default branch covers tcp_connect and every other event type.
	switch types.EventType(evtType) {
	case types.EventNetClose:
		evt, err := bpf.ParseNetworkCloseEvent(raw)
		if err != nil {
			return types.Event{}, err
		}
		return evt.ToTypesEvent(), nil
	default:
		// EventTCPConnect and any unknown network events.
		evt, err := bpf.ParseNetworkEvent(raw)
		if err != nil {
			return types.Event{}, err
		}
		return evt.ToTypesEvent(), nil
	}
}
