package collector

import (
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/ja3"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// decodeTLSClientHello parses a raw ring-buffer ClientHello sample into a
// types.Event and enriches it with JA3/JA4 fingerprints computed from the
// captured handshake bytes. Fingerprint computation is best-effort: an
// unparseable handshake still yields a valid event with empty JA3/JA4 fields.
//
// The function has no kernel dependencies — it only decodes bytes and runs the
// pure-Go ja3 hashing — so it is unit-tested directly without a running probe.
func decodeTLSClientHello(raw []byte) (types.Event, error) {
	var rawEvt bpf.TlsClientHelloRawEvent
	if err := bpf.ParseTlsClientHelloEventInto(raw, &rawEvt); err != nil {
		return types.Event{}, err
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

	return event, nil
}
