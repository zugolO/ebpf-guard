package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// labelValuesOfSyscallNR returns the label values currently materialized on
// ebpf_guard_syscall_events_by_nr_total together with their counts.
func labelValuesOfSyscallNR(t *testing.T) map[string]float64 {
	t.Helper()

	ch := make(chan prometheus.Metric, 1024)
	go func() {
		SyscallEventsByNR.Collect(ch)
		close(ch)
	}()

	out := make(map[string]float64)
	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))
		for _, l := range pb.GetLabel() {
			if l.GetName() == "nr" {
				out[l.GetValue()] = pb.GetCounter().GetValue()
			}
		}
	}
	return out
}

func resetSyscallNRAxis(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SyscallEventsByNR.Reset()
		SetSyscallNRAxis(nil)
	})
	SyscallEventsByNR.Reset()
	SetSyscallNRAxis(nil)
}

func syscallEvent(nr int64) types.Event {
	return types.Event{Type: types.EventSyscall, Syscall: &types.SyscallEvent{Nr: nr}}
}

// An undeclared axis must not read as "this syscall never happened": every
// event lands in the explicit nr="unset" bucket instead.
func TestSyscallNRAxisUndeclaredCountsUnset(t *testing.T) {
	resetSyscallNRAxis(t)

	e := syscallEvent(59)
	RecordSyscallNR(&e)

	got := labelValuesOfSyscallNR(t)
	assert.Equal(t, float64(1), got[SyscallNRLabelUnset])
	assert.NotContains(t, got, "59")
}

// Declaring the axis materializes one series per allowed number plus "other",
// so a zero on an opened number is a reading and not an absent series.
func TestSyscallNRAxisDeclarationMaterializesEveryAllowedNumber(t *testing.T) {
	resetSyscallNRAxis(t)

	SetSyscallNRAxis([]int{59, 101, 162})

	got := labelValuesOfSyscallNR(t)
	for _, want := range []string{"59", "101", "162", SyscallNRLabelOther} {
		require.Contains(t, got, want, "series must exist before any event")
		assert.Equal(t, float64(0), got[want])
	}
}

func TestSyscallNRAxisAllowedNumberGetsItsOwnValue(t *testing.T) {
	resetSyscallNRAxis(t)
	SetSyscallNRAxis([]int{59, 162})

	for i := 0; i < 3; i++ {
		e := syscallEvent(162)
		RecordSyscallNR(&e)
	}
	e := syscallEvent(59)
	RecordSyscallNR(&e)

	got := labelValuesOfSyscallNR(t)
	assert.Equal(t, float64(3), got["162"])
	assert.Equal(t, float64(1), got["59"])
	assert.Equal(t, float64(0), got[SyscallNRLabelOther])
}

// The cardinality of the series is bounded by the DECLARATION, never by what
// the kernel sends: a number outside the allowlist collapses into "other".
func TestSyscallNRAxisIsBoundedByDeclaration(t *testing.T) {
	resetSyscallNRAxis(t)
	SetSyscallNRAxis([]int{59, 162})

	for nr := int64(0); nr < 400; nr++ {
		e := syscallEvent(nr)
		RecordSyscallNR(&e)
	}

	got := labelValuesOfSyscallNR(t)
	assert.Len(t, got, 3, "declared numbers + other, whatever the kernel sends")
	assert.Equal(t, float64(398), got[SyscallNRLabelOther])
	assert.Equal(t, float64(1), got["59"])
	assert.Equal(t, float64(1), got["162"])
}

func TestRecordSyscallNRIgnoresOtherEventTypes(t *testing.T) {
	resetSyscallNRAxis(t)
	SetSyscallNRAxis([]int{59})

	file := types.Event{Type: types.EventFileAccess}
	RecordSyscallNR(&file)
	// A syscall event whose payload never parsed carries no number to count.
	bare := types.Event{Type: types.EventSyscall}
	RecordSyscallNR(&bare)
	RecordSyscallNR(nil)

	got := labelValuesOfSyscallNR(t)
	assert.Equal(t, float64(0), got["59"])
	assert.Equal(t, float64(0), got[SyscallNRLabelOther])
}
