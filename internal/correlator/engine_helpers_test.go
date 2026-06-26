package correlator

import (
	"strings"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAlertID(t *testing.T) {
	id := buildAlertID("rule", 100, 42, 7)
	assert.Equal(t, "rule-100-42-7", id)
}

func TestGetDetailsMap(t *testing.T) {
	m := getDetailsMap()
	require.NotNil(t, m)
	m["k"] = "v"
	assert.Equal(t, "v", m["k"])
}

func TestFormatAnomalyDescription(t *testing.T) {
	// No contributions → generic message.
	assert.Equal(t, "Anomalous behavior detected",
		formatAnomalyDescription(&profiler.AnomalyResult{}))

	desc := formatAnomalyDescription(&profiler.AnomalyResult{
		Contributions: []profiler.AnomalyContribution{
			{Field: "dport", Value: "4444"},
			{Field: "directory", Value: "/tmp"},
		},
	})
	assert.True(t, strings.HasPrefix(desc, "Anomalous behavior detected: "))
	assert.Contains(t, desc, "dport=4444")
	assert.Contains(t, desc, "directory=/tmp")
}

func TestBuildRemoteSpanContext(t *testing.T) {
	sc, err := buildRemoteSpanContext("0123456789abcdef0123456789abcdef", "0123456789abcdef")
	require.NoError(t, err)
	assert.True(t, sc.IsValid())

	// Wrong trace ID length.
	_, err = buildRemoteSpanContext("short", "0123456789abcdef")
	require.Error(t, err)

	// Non-hex trace ID.
	_, err = buildRemoteSpanContext(strings.Repeat("z", 32), "0123456789abcdef")
	require.Error(t, err)
}
