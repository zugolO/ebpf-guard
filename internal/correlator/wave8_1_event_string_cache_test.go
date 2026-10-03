package correlator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Wave 8.1, item 3.
//
// getFieldValue used to call util.BytesToString on Comm / ParentComm /
// File.Filename once per condition — and a rule is evaluated once per rule, so
// the same bytes were re-materialised for every rule in byType and again for
// every condition inside a condition group. The night-#3 heap profile put 42.1%
// of allocated bytes and 56.8% of objects in BytesToString doing exactly this
// (~49 strings per event on an unloaded agent).
//
// The correction threads one eventFieldCache through a whole rule pass:
// matchesTypedCached / evaluateConditionGroup / evaluateCondition ->
// getFieldValueCached, with the cache materialising each field at most once.
// These tests pin that invariant, and the content equality of the cached and
// uncached paths. (The acceptance criterion for the wave is still an A/B run of
// the same binary on the stand; this file only guards the mechanism.)

// wave8_1SyscallEvent returns a syscall event with non-empty Comm/ParentComm.
func wave8_1SyscallEvent() types.Event {
	var e types.Event
	e.Type = types.EventSyscall
	copy(e.Comm[:], "curl")
	copy(e.ParentComm[:], "bash")
	e.PID = 4242
	e.PPID = 1
	e.Syscall = &types.SyscallEvent{Nr: 59} // execve
	return e
}

// TestWave8_1_EventFieldStringsMaterialisedOncePerEvent proves the cache, not
// the number of lookups, determines the allocation count: 40 reads of the same
// field on one event cost the same as 4.
func TestWave8_1_EventFieldStringsMaterialisedOncePerEvent(t *testing.T) {
	re := NewRuleEngine(nil)
	e := wave8_1SyscallEvent()

	allocsFew := testing.AllocsPerRun(200, func() {
		c := &eventFieldCache{}
		for i := 0; i < 4; i++ {
			_ = re.getFieldValueCached(e, "comm", nil, c)
		}
	})
	allocsMany := testing.AllocsPerRun(200, func() {
		c := &eventFieldCache{}
		for i := 0; i < 40; i++ {
			_ = re.getFieldValueCached(e, "comm", nil, c)
		}
	})

	require.Equal(t, allocsFew, allocsMany,
		"10× more lookups on the same event must not allocate more: 4 lookups=%v, 40 lookups=%v",
		allocsFew, allocsMany)
}

// TestWave8_1_EvaluateIntoAllocatesIndependentlyOfRuleCount is the end-to-end
// form: EvaluateInto on an event that matches N rules reading Comm must not
// allocate N times the strings. The rules deliberately do not match, so the
// alert-construction path stays out of the measurement.
func TestWave8_1_EvaluateIntoAllocatesIndependentlyOfRuleCount(t *testing.T) {
	event := wave8_1SyscallEvent()

	makeEngine := func(n int) *RuleEngine {
		rules := make([]Rule, n)
		for i := range rules {
			rules[i] = Rule{
				ID:        fmt.Sprintf("wave8_1_rule_%d", i),
				Name:      "wave 8.1 allocation probe",
				EventType: types.EventSyscall,
				// Reads Comm but never matches: no alert is built.
				Condition: RuleCondition{Field: "comm", Op: OpEquals, Values: []string{"no-such-process"}},
				Severity:  types.SeverityWarning,
				Action:    ActionAlert,
			}
		}
		return NewRuleEngine(rules)
	}

	one := makeEngine(1)
	many := makeEngine(32)

	allocsOne := testing.AllocsPerRun(200, func() {
		one.EvaluateInto(event, func(types.Alert) {})
	})
	allocsMany := testing.AllocsPerRun(200, func() {
		many.EvaluateInto(event, func(types.Alert) {})
	})

	require.Equal(t, allocsOne, allocsMany,
		"per-event string cache must make the condition path independent of rule count: 1 rule=%v allocs, 32 rules=%v allocs",
		allocsOne, allocsMany)
}

// TestWave8_1_EventFieldCacheMatchesUncached pins that caching does not change
// any value: byte-array fields (comm, parent_comm, filename, and the derived
// directory/extension) must read identically with and without a cache.
func TestWave8_1_EventFieldCacheMatchesUncached(t *testing.T) {
	re := NewRuleEngine(nil)

	syscall := wave8_1SyscallEvent()
	var file types.Event
	file.Type = types.EventFileAccess
	file.File = &types.FileEvent{}
	copy(file.File.Filename[:], "/usr/local/bin/evil.sh")

	syscallFields := []string{"comm", "parent_comm"}
	fileFields := []string{"filename", "directory", "extension"}

	for _, f := range syscallFields {
		c := &eventFieldCache{}
		require.Equal(t, re.getFieldValue(syscall, f, nil), re.getFieldValueCached(syscall, f, nil, c), "syscall field %q", f)
	}
	for _, f := range fileFields {
		c := &eventFieldCache{}
		require.Equal(t, re.getFieldValue(file, f, nil), re.getFieldValueCached(file, f, nil, c), "file field %q", f)
	}

	// The derived fields share the same cached filename, so they must still be
	// self-consistent when read from one cache.
	c := &eventFieldCache{}
	assert.Equal(t, "/usr/local/bin", re.getFieldValueCached(file, "directory", nil, c))
	assert.Equal(t, ".sh", re.getFieldValueCached(file, "extension", nil, c))
	assert.Equal(t, "/usr/local/bin/evil.sh", re.getFieldValueCached(file, "filename", nil, c))
}
