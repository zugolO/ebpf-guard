package attacker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const testRulesPath = "../../rules/container-escape.yaml"

func TestRunner_RunSynthetic(t *testing.T) {
	r := NewRunner(nil, quietLogger())
	require.Len(t, r.Scenarios(), len(BuiltinScenarios()))

	results, err := r.RunSynthetic(context.Background(), testRulesPath)
	require.NoError(t, err)
	require.Len(t, results, len(BuiltinScenarios()))

	// Every scenario must report a populated Scenario and a measured duration.
	for _, res := range results {
		assert.NotEmpty(t, res.Scenario.ID)
		assert.GreaterOrEqual(t, res.Duration.Nanoseconds(), int64(0))
	}

	// PrintResults renders a summary without panicking.
	var buf bytes.Buffer
	PrintResults(results, &buf)
	assert.Contains(t, buf.String(), "Attack Simulation Results")
}

func TestRunner_RunSynthetic_BadRulesPath(t *testing.T) {
	r := NewRunner(nil, quietLogger())
	_, err := r.RunSynthetic(context.Background(), "/nonexistent/rules.yaml")
	require.Error(t, err)
}

// TestRunner_Verify_PollsVersionedAlertsAPI asserts that --verify mode polls
// the agent's real endpoint (/api/v1/alerts) with a duration-format "since"
// parameter — the only formats the API actually serves and parses.
func TestRunner_Verify_PollsVersionedAlertsAPI(t *testing.T) {
	sc := BuiltinScenarios()[0]

	var polled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/alerts", r.URL.Path,
			"verify must poll the versioned alerts endpoint")
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		since := r.URL.Query().Get("since")
		_, err := time.ParseDuration(since)
		require.NoError(t, err, "since must be a Go duration (api parses it with time.ParseDuration), got %q", since)

		polled.Store(true)
		alerts := make([]types.Alert, 0, len(sc.RuleIDs))
		for _, id := range sc.RuleIDs {
			alerts = append(alerts, types.Alert{RuleID: id})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alerts) //nolint:errcheck
	}))
	defer srv.Close()

	r := NewRunner(nil, quietLogger())
	res, err := r.Verify(context.Background(), sc.ID, srv.URL, "test-token", 10*time.Second)
	require.NoError(t, err)
	assert.True(t, polled.Load(), "agent API must have been polled")
	assert.True(t, res.Passed, "expected rules served by the agent must satisfy verify: missing=%v", res.Missing)
	assert.ElementsMatch(t, sc.RuleIDs, res.Fired)
}

func TestRunner_RunScenarioSynthetic(t *testing.T) {
	r := NewRunner(nil, quietLogger())

	id := BuiltinScenarios()[0].ID
	res, err := r.RunScenarioSynthetic(context.Background(), id, testRulesPath)
	require.NoError(t, err)
	assert.Equal(t, id, res.Scenario.ID)

	// Unknown scenario ID is an error.
	_, err = r.RunScenarioSynthetic(context.Background(), "does-not-exist", testRulesPath)
	require.Error(t, err)

	// Known ID but unreadable rules file is an error.
	_, err = r.RunScenarioSynthetic(context.Background(), id, "/nope.yaml")
	require.Error(t, err)
}
