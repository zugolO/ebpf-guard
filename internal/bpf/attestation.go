package bpf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

// AttestationViolation is returned when a BPF program's kernel tag no longer
// matches the tag recorded on first load — indicating possible replacement.
// Tag is the hex-encoded truncated SHA-256 of the xlated BPF instructions
// as returned by cilium/ebpf ProgramInfo.Tag.
type AttestationViolation struct {
	Program     string
	ExpectedTag string
	ActualTag   string
}

func (v AttestationViolation) Error() string {
	return fmt.Sprintf("BPF program %q tag mismatch: expected %s, got %s",
		v.Program, v.ExpectedTag, v.ActualTag)
}

// IsAttestationViolation reports whether err wraps an AttestationViolation.
func IsAttestationViolation(err error) bool {
	var v AttestationViolation
	return errors.As(err, &v)
}

// Attestor records BPF program kernel tags on first observation and verifies
// them on every subsequent call.  The first observation happens immediately
// after the agent loads its programs, before any attacker can replace them,
// so it is treated as the trusted baseline.
//
// The kernel tag (ProgramInfo.Tag) is a hex-encoded truncated SHA-256 of the
// translated (xlated) BPF instructions.  A change to the tag means the kernel
// is executing different instructions than what the agent loaded.
type Attestor struct {
	mu       sync.RWMutex
	expected map[string]string // program name → first-observed tag (hex string)
}

// NewAttestor returns a ready-to-use Attestor.
func NewAttestor() *Attestor {
	return &Attestor{
		expected: make(map[string]string),
	}
}

// VerifyProgram checks prog's kernel tag against the previously recorded value.
//   - First call for name: records the tag and returns nil.
//   - Subsequent calls: returns AttestationViolation if the tag changed.
//   - prog == nil or Info() failure (stub/test mode): no-op, returns nil.
func (a *Attestor) VerifyProgram(name string, prog *ebpf.Program) error {
	if prog == nil {
		return nil
	}
	info, err := prog.Info()
	if err != nil {
		// Stub mode or insufficient privileges — skip silently.
		return nil
	}
	return a.verifyTag(name, info.Tag)
}

// verifyTag is the core comparison logic shared by VerifyProgram and tests.
// First call for name records tag and returns nil; subsequent calls check it.
func (a *Attestor) verifyTag(name string, tag string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if expected, recorded := a.expected[name]; !recorded {
		a.expected[name] = tag
		return nil
	} else if expected != tag {
		return AttestationViolation{
			Program:     name,
			ExpectedTag: expected,
			ActualTag:   tag,
		}
	}
	return nil
}

// VerifyAll calls VerifyProgram for every entry in programs.
// Returns the first violation encountered, or nil.
func (a *Attestor) VerifyAll(programs map[string]*ebpf.Program) error {
	for name, prog := range programs {
		if err := a.VerifyProgram(name, prog); err != nil {
			return err
		}
	}
	return nil
}

// RecordedCount returns how many program tags have been recorded so far.
// Useful for health-check / metrics.
func (a *Attestor) RecordedCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.expected)
}
