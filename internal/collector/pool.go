package collector

import (
	"sync"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// eventPool recycles *types.Event allocations across ring-buffer reads.
// Collectors call Get() before parsing a raw BPF sample and Put() after
// sendEvent has copied the value into the output channel. The event must
// be Reset() before Put() to release inner struct pointers.
var eventPool = sync.Pool{
	New: func() any { return new(types.Event) },
}
