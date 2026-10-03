package collector

import (
	"bytes"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ReadInto reuses the Record buffer (wave 8.1 item 12): whatever parseEvent
// returns must not alias raw, or the next record rewrites a queued event.
func TestParseEvent_DoesNotAliasRawSample(t *testing.T) {
	raw := make([]byte, 4096)
	for i := range raw {
		raw[i] = 'a'
	}
	// type field: leave 'a' bytes; parsers either reject or decode. Only the
	// decoded-successfully case is meaningful.
	fc := &FileaccessCollector{}
	var ev types.Event
	if err := fc.parseEvent(raw, &ev); err != nil {
		t.Skipf("synthetic sample not accepted by parser: %v", err)
	}
	if ev.File == nil {
		t.Skip("no file payload decoded")
	}
	before := ev.File.FDPath
	comm := ev.Comm
	for i := range raw {
		raw[i] = 'z'
	}
	if ev.File.FDPath != before || !bytes.Equal(ev.Comm[:], comm[:]) {
		t.Fatal("parsed event aliases the ring-buffer sample")
	}
}
