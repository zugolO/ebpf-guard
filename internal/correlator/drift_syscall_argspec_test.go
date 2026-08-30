package correlator

import (
	"strconv"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestDriftSyscallRulesHaveArgSpecs is the standing gate against the second
// blind spot measurement №6.0 found.
//
// A class: drift syscall rule is suppressed until its (rule, target) signature
// is novel for the workload. For syscalls that carry no proc.args the target
// is built solely from the register arguments named in
// profiler.driftSyscallArgSpecs. A syscall listed in such a rule WITHOUT a
// spec collapses to a single signature — one decimal number — so the first
// call a workload makes during learning becomes its baseline and every later
// call is suppressed as "known", including the escape the rule exists to
// catch. On №6.0 that was drift_dangerous_syscall: 416 suppressed matches, 0
// alerts, indistinguishable from a quiet host.
//
// Adding a syscall to a drift rule is a one-line edit; adding its spec is a
// separate file. This test is what connects them.
func TestDriftSyscallRulesHaveArgSpecs(t *testing.T) {
	rules, err := LoadRulesFromFile("../../rules/drift-rules.yaml")
	if err != nil {
		t.Fatalf("load drift rules: %v", err)
	}

	checked := 0
	for i := range rules {
		r := &rules[i]
		if r.EffectiveClass() != ClassDrift || r.EventType != types.EventSyscall {
			continue
		}
		for _, cond := range getAllConditions(r) {
			if cond.Field != "nr" {
				continue
			}
			// The loader has already normalised syscall names to numbers.
			for _, v := range cond.Values {
				nr, convErr := strconv.ParseInt(v, 10, 64)
				if convErr != nil {
					t.Errorf("rule %s: nr value %q is not a number after loading — normaliseSyscallNrValues did not run", r.ID, v)
					continue
				}
				checked++
				// execve/execveat carry proc.args, which is the discriminator
				// for exec rules; they need no register-argument spec.
				if nr == 59 || nr == 322 {
					continue
				}
				if !profiler.DriftSyscallHasArgSpec(nr) {
					t.Errorf("rule %s matches syscall %d, which has no entry in profiler.driftSyscallArgSpecs: "+
						"its drift signature is the bare syscall number, so the first such call during learning "+
						"silences this rule for that workload forever. Add a spec in "+
						"internal/profiler/driftsyscallargs.go, or move the syscall to a class: threat rule if "+
						"none of its arguments is a scalar (see escape_pivot_root).", r.ID, nr)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no class: drift syscall rule with an nr condition was found — the gate is checking nothing")
	}
}
