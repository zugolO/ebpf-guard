package attacker

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
