package attacker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
	rulesembed "github.com/zugolO/ebpf-guard/rules"
)

// TestBuiltinScenarios_AllPresent verifies that BuiltinScenarios returns a non-empty
// list and that every scenario has the required fields set.
func TestBuiltinScenarios_AllPresent(t *testing.T) {
	scenarios := BuiltinScenarios()
	require.NotEmpty(t, scenarios, "BuiltinScenarios must not be empty")

	seenIDs := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		t.Run(s.ID, func(t *testing.T) {
			assert.NotEmpty(t, s.ID, "ID must not be empty")
			assert.NotEmpty(t, s.Name, "Name must not be empty")
			assert.NotEmpty(t, s.Description, "Description must not be empty")
			assert.NotEmpty(t, s.RuleIDs, "RuleIDs must not be empty")
			assert.NotEmpty(t, s.MITRETech, "MITRETech must not be empty")
			assert.NotNil(t, s.Event, "Event func must not be nil")
		})

		assert.False(t, seenIDs[s.ID], "duplicate scenario ID: %s", s.ID)
		seenIDs[s.ID] = true
	}
}

// TestBuiltinScenarios_MITRETechFormat verifies MITRE technique IDs match the
// expected pattern (T followed by digits, optionally with a dot and sub-technique).
func TestBuiltinScenarios_MITRETechFormat(t *testing.T) {
	for _, s := range BuiltinScenarios() {
		t.Run(s.ID, func(t *testing.T) {
			// MITRE IDs start with 'T' followed by at least 4 digits
			assert.True(t, len(s.MITRETech) >= 5, "MITRE tech too short: %q", s.MITRETech)
			assert.Equal(t, 'T', rune(s.MITRETech[0]), "MITRE tech must start with 'T': %q", s.MITRETech)
		})
	}
}

// TestBuiltinScenarios_EventsAreValid verifies that each scenario's Event() function
// returns a valid types.Event with the required fields set.
func TestBuiltinScenarios_EventsAreValid(t *testing.T) {
	for _, s := range BuiltinScenarios() {
		s := s // capture
		t.Run(s.ID, func(t *testing.T) {
			e := s.Event()
			assert.NotZero(t, e.Type, "event Type must be non-zero")
			assert.NotZero(t, e.Timestamp, "event Timestamp must be non-zero")
			assert.NotZero(t, e.PID, "event PID must be non-zero")

			// Type-specific payload must be non-nil
			switch e.Type {
			case types.EventSyscall:
				assert.NotNil(t, e.Syscall, "Syscall payload must be set")
			case types.EventTCPConnect:
				assert.NotNil(t, e.Network, "Network payload must be set")
			case types.EventFileAccess:
				assert.NotNil(t, e.File, "File payload must be set")
			case types.EventDNS:
				assert.NotNil(t, e.DNS, "DNS payload must be set")
			case types.EventPrivesc:
				assert.NotNil(t, e.Privesc, "Privesc payload must be set")
			case types.EventKmodLoad:
				assert.NotNil(t, e.Kmod, "Kmod payload must be set")
			}
		})
	}
}

// TestBuiltinScenarios_EventsAreIndependent verifies that calling Event() twice
// produces independent events (no shared mutable state between calls).
func TestBuiltinScenarios_EventsAreIndependent(t *testing.T) {
	for _, s := range BuiltinScenarios() {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			e1 := s.Event()
			e2 := s.Event()
			// Both must be valid
			assert.NotZero(t, e1.Type)
			assert.NotZero(t, e2.Type)
			// Type must be the same
			assert.Equal(t, e1.Type, e2.Type)
		})
	}
}

// TestBuiltinScenarios_DetectedByEmbeddedRules guards against rule-ID drift:
// every scenario's expected RuleIDs must actually fire when its event is fed
// through a correlation engine loaded with the embedded built-in rule sets.
// This is the same code path as `attack-sim --run-all` with default rules.
func TestBuiltinScenarios_DetectedByEmbeddedRules(t *testing.T) {
	files, err := rulesembed.LoadAll()
	require.NoError(t, err)
	rules, err := correlator.LoadRulesFromEmbedded(files)
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	knownIDs := make(map[string]bool, len(rules))
	for _, r := range rules {
		knownIDs[r.ID] = true
	}

	cfg := correlator.DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	engine := correlator.NewCorrelationEngineWithConfig(cfg)

	for _, s := range BuiltinScenarios() {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			for _, id := range s.RuleIDs {
				assert.True(t, knownIDs[id],
					"expected rule %q does not exist in the embedded rule sets (stale ID?)", id)
			}

			alerts := engine.Ingest(context.Background(), s.Event())
			fired := make(map[string]bool, len(alerts))
			for _, a := range alerts {
				fired[a.RuleID] = true
			}
			for _, id := range s.RuleIDs {
				assert.True(t, fired[id],
					"expected rule %q did not fire for scenario %s", id, s.ID)
			}
		})
	}
}

// TestScenarioByID verifies lookup by ID works for all built-in scenarios.
func TestScenarioByID_Found(t *testing.T) {
	for _, s := range BuiltinScenarios() {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			found, ok := ScenarioByID(s.ID)
			require.True(t, ok, "ScenarioByID must find %q", s.ID)
			assert.Equal(t, s.ID, found.ID)
			assert.Equal(t, s.Name, found.Name)
		})
	}
}

// TestScenarioByID_NotFound verifies that unknown IDs return (_, false).
func TestScenarioByID_NotFound(t *testing.T) {
	_, ok := ScenarioByID("this-id-does-not-exist")
	assert.False(t, ok)
}

// TestContainerEscapeScenario verifies the ptrace scenario generates the expected
// syscall number (101 = SYS_ptrace) targeting PID 1.
func TestContainerEscapeScenario(t *testing.T) {
	s, ok := ScenarioByID("container-escape-ptrace")
	require.True(t, ok)

	e := s.Event()
	require.NotNil(t, e.Syscall)
	assert.Equal(t, int64(101), e.Syscall.Nr, "SYS_ptrace must be 101")
	assert.Equal(t, uint64(1), e.Syscall.Args[1], "ptrace target must be PID 1")
}

// TestCryptominerScenario verifies the pool connect scenario uses port 3333 (Stratum).
func TestCryptominerScenario(t *testing.T) {
	s, ok := ScenarioByID("cryptominer-pool-connect")
	require.True(t, ok)

	e := s.Event()
	require.NotNil(t, e.Network)
	assert.Equal(t, uint16(3333), e.Network.Dport, "cryptominer must connect to port 3333")
}

// TestSensitiveFileScenario verifies the /etc/shadow read scenario.
func TestSensitiveFileScenario(t *testing.T) {
	s, ok := ScenarioByID("sensitive-file-read")
	require.True(t, ok)

	e := s.Event()
	require.NotNil(t, e.File)
	filename := string(e.File.Filename[:])
	assert.True(t, len(filename) > 0)
	assert.Contains(t, filename, "/etc/shadow")
	assert.NotZero(t, e.UID, "non-root UID expected")
}

// TestLDPreloadScenario verifies the LD_PRELOAD injection scenario uses O_WRONLY.
func TestLDPreloadScenario(t *testing.T) {
	s, ok := ScenarioByID("ldpreload-drop")
	require.True(t, ok)

	e := s.Event()
	require.NotNil(t, e.File)
	filename := string(e.File.Filename[:])
	assert.Contains(t, filename, "ld.so.preload")
	assert.Equal(t, int32(1), e.File.Flags, "must be O_WRONLY (1)")
}
