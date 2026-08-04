# P1-17 Implementation: Agent Self-Exclusion from Alerting

## Summary

Implemented P1-17: "Агент алертит на самого себя" — Agent generates 6293 false alerts on its own activity during 9-hour idle run. The fix extends the existing exception mechanism to exclude the agent's own PID from rules that commonly trigger on its legitimate operations.

## Changes Made

### 1. Canary Manager Self-PID Exception

**File:** `internal/canary/canary.go`

- Added `selfPID uint32` field to `Manager` struct
- Modified `New()` to capture `os.Getpid()` at initialization
- Updated `Rules()` to generate `ebpf-guard-self` exception with PID-based condition:
  ```go
  Exceptions: []correlator.RuleException{
      {
          Name: "ebpf-guard-self",
          Condition: correlator.RuleCondition{
              Field:  "pid",
              Op:     correlator.OpEquals,
              Values: []string{strconv.FormatUint(uint64(m.selfPID), 10)},
          },
      },
  },
  ```

**Rationale:** Canary verification loop reads canary files every 60 seconds, triggering canary rules. PID-based exception at event-matching level (not post-factum filtering) prevents these false positives.

### 2. Extended PID Field Support

**File:** `internal/correlator/rule_loader.go`

- Added `"pid": true` to `validSyscallFields` map
- Added `"pid": true` to `validFileFields` map

**File:** `internal/correlator/rules.go`

- Added PID field handling in `getFieldValue()` for `EventFileAccess` and `EventSyscall` cases:
  ```go
  case "pid":
      return strconv.FormatUint(uint64(e.PID), 10)
  ```

**Rationale:** Enables PID-based exception matching for file and syscall events.

### 3. Sigma Rules with ebpf-guard-self Exception

Added `ebpf-guard-self` exception to the following rules that generated false positives:

**File:** `rules/sigma-linux.yaml`

- `sigma_cpu_info_access` (1554 alerts) — reads `/proc/cpuinfo` for hardware profile/watchdog
- `sigma_sensitive_file_chmod` (228 alerts) — sets permissions on canary/state files
- `sigma_sensitive_dir_listing` — creates canary files in sensitive directories

**File:** `rules/credential-access.yaml`

- `cred_proc_maps_mass_read` (1439 alerts) — scans `/proc/*/maps` for integrity scan

**File:** `rules/mitre-additional.yaml`

- `mitre_sandbox_detect_proc_read` (478 alerts) — reads `/proc/*`

**File:** `rules/container-escape.yaml`

- `container_escape_init_proc` (475 alerts) — reads `/proc/1/*`

**File:** `rules/owasp-web.yaml`

- `owasp_web_sensitive_file_read` (268 alerts) — reads `/etc/*`

**File:** `rules/drift-rules.yaml`

- `drift_new_file_dir_sensitive` — creates files in sensitive directories

**Exception format — `comm` AND path, never `comm` alone:**
```yaml
exceptions:
  - name: ebpf-guard-self
    condition_group:
      operator: and
      conditions:
        - field: proc.comm
          op: eq
          values: [ebpf-guard]
        - field: filename          # the specific path the agent really touches
          op: suffix
          values: [".canary"]
```

**Rationale:** The existing `ebpf-guard-self` exception (previously only for `sigma_memory_proc_dump`) is now extended to all rules that commonly trigger on the agent's own activity.

**Why the path bind is mandatory.** `comm` is attacker-controlled — any process can
call `prctl(PR_SET_NAME, "ebpf-guard")`. A `comm`-only exception on
`owasp_web_sensitive_file_read` would therefore make reading the real `/etc/shadow`
completely invisible. Binding each exception to the narrow path the agent actually
touches keeps the attacker primitives on the same rule visible:

| Rule | Suppressed (agent's real access) | Still alerts |
|---|---|---|
| `sigma_cpu_info_access` | `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version` | `/proc/sys/kernel/*` |
| `cred_proc_maps_mass_read` | `/proc/<pid>/maps` | `/proc/<pid>/mem`, `/environ` |
| `mitre_sandbox_detect_proc_read` | `/proc/self/cgroup`, `/proc/uptime` | `/proc/1/environ`, `/proc/1/status` |
| `container_escape_init_proc` | `/proc/1/{cgroup,stat,status}` | `/proc/1/environ`, `/proc/1/mem` |
| `owasp_web_sensitive_file_read` | `*.canary` | real `/etc/shadow`, `/etc/passwd` |
| `sigma_sensitive_file_chmod` | `*.canary` | `/etc/sudoers`, `/etc/pam.d/` |
| `sigma_sensitive_dir_listing` | `*.canary` | real `/root/.ssh/id_rsa` |
| `drift_new_file_dir_sensitive` | `*.canary` | `/etc/cron.d/*`, `/etc/systemd/system/*` |

The canary rules use `pid` rather than `comm`, which is strictly stronger — a
process cannot spoof the agent's PID.

### 4. Regression Tests

**File:** `internal/canary/self_exclusion_test.go`

- `TestCanarySelfPIDException` — verifies canary rules have PID-based exception
- `TestCanaryManagerCapturesSelfPID` — verifies PID is captured at init
- `TestCanaryRuleValidatesPIDField` — verifies PID field is valid for file rules
- `TestCanaryExceptionBlocksSelfPIDEvents` — verifies exception blocks self-PID events

**File:** `internal/correlator/p1_17_self_exclusion_test.go`

- `TestP1_17_SelfExclusion` — comprehensive regression test for all modified rules
- `TestP1_17_PIDFieldAvailable` — verifies PID field is available for exception matching
- `TestP1_17_CanarySelfPIDException` — verifies canary PID exception
- `BenchmarkP1_17_ExceptionEvaluation` — benchmarks performance impact

**Note:** These tests are pure rule-engine logic and need no kernel, so they carry
no build tag and run on every platform. An earlier revision tagged them
`// +build !windows`; because the paired `//go:build` line was missing the files
were excluded everywhere and their compile errors went unnoticed.

Each rule is asserted three ways, not one:

1. the agent's own access is suppressed;
2. the same access from a foreign process **still alerts** (the rule was narrowed, not disabled);
3. a process spoofing `comm == "ebpf-guard"` **still alerts** on the attacker path.

Assertion 3 is what mechanically prevents a regression back to a `comm`-only exception.

## Acceptance Criteria

✅ **Criterion 1:** Exclude agent's PID from `/proc/*`, `/etc/*`, and canary rules
- Implemented via PID-based exception in canary rules
- Extended `ebpf-guard-self` exception to all affected sigma rules

✅ **Criterion 2:** Exception at event-matching level, not post-factum filtering
- Canary rules use PID condition directly in exception
- Evaluation happens in `matchesTyped()` before alert generation

✅ **Criterion 3:** Regression test for idle host
- Added comprehensive tests in `p1_17_self_exclusion_test.go`
- Tests verify no alerts generated for ebpf-guard's own PID

## Performance Impact

- PID field extraction is O(1) — already available in `Event.PID`
- Exception evaluation uses existing exception matching code path
- Benchmark added to measure hot path impact
- Expected impact: negligible (< 10ns per event)

## Testing

To run the regression tests:
```bash
go test ./internal/canary/... -run "TestCanary.*"
go test ./internal/correlator/... -run "TestP1_17.*"
go test ./internal/correlator/... -bench="BenchmarkP1_17_*"

# Detection-integrity guard for the whole of Stage 1 — asserts the allowlists
# did not trade detection for silence.
go test ./internal/correlator/... -run "TestStage1.*"
```

To verify the fix on a live system:
```bash
# Start agent with canary enabled
ebpf-guard --config config.yaml

# Generate agent activity (canary verification will run automatically)
sleep 120

# Check for ebpf-guard alerts (should be zero for P1-17-covered rules)
curl -s http://localhost:9090/api/v1/alerts | jq '.[] | select(.process.comm == "ebpf-guard")'
```

## Follow-up Items

1. **Verify on actual system** — Run idle-while-agent test to confirm 6293 alerts reduced to zero
2. **Extend to other rules** — Monitor for additional rules that may need `ebpf-guard-self` exception
3. **Document best practices** — Update operator guide with self-exclusion pattern for custom rules

## References

- Issue: P1-17 in `ISSUES-attack-run-2026-08-03.md`
- Related: P1-6 (Baseline noise from system daemons)
- Related: P1-13 (False confirmed attacks — affected by self-exception)
- Related: P2-12 (open-vs-write flag confusion — part of self-activity noise)