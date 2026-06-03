// Package e2e provides end-to-end integration tests.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnomalyAlertReachesAlertmanager verifies that anomaly alerts generated
// by the CorrelationEngine are properly enriched and sent to Alertmanager.
// This test addresses Bug 8 - ensuring anomaly alerts flow through the
// engine.Ingest path and reach Alertmanager.
func TestAnomalyAlertReachesAlertmanager(t *testing.T) {
	// Create mock Alertmanager server
	var receivedAlerts []types.AlertPayload
	alertServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Logf("failed to read body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var alerts []types.AlertPayload
		if err := json.Unmarshal(body, &alerts); err != nil {
			t.Logf("failed to unmarshal alerts: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receivedAlerts = append(receivedAlerts, alerts...)
		w.WriteHeader(http.StatusOK)
	}))
	defer alertServer.Close()

	// Create correlation engine with anomaly detection enabled
	engineConfig := correlator.CorrelationEngineConfig{
		Rules:              []correlator.Rule{},
		BufferSize:         100,
		EnableAnomaly:      true,
		AnomalyThreshold:   0.1, // Low threshold to trigger anomaly quickly
		LearningPeriod:     100 * time.Millisecond,
		MinLearningSamples: 5,
		EWMAWeight:         0.3,
		EnableRateLimit:    false,
		RateLimitWindow:    time.Minute,
		MaxAlertsPerWindow: 100,
	}
	engine := correlator.NewCorrelationEngineWithConfig(engineConfig)

	// Create Alertmanager client pointing to mock server
	alertClient := exporter.NewAlertmanagerClient(
		alertServer.URL,
		"http://ebpf-guard:9090",
		10,                    // batch size
		100,                   // batch timeout in milliseconds
		5,                     // circuit breaker threshold
	)
	defer alertClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send events that will trigger anomaly detection
	// First, send baseline events to establish normal behavior
	for i := 0; i < 10; i++ {
		event := types.Event{
			Type:      types.EventTCPConnect,
			Timestamp: uint64(time.Now().UnixNano()),
			PID:       1234,
			TGID:      1234,
			UID:       1000,
			Comm:      [16]byte{'t', 'e', 's', 't'},
			Network: &types.NetworkEvent{
				Dport: 80,
				Daddr: [16]byte{192, 168, 1, 1},
				Sport: 12345,
				Saddr: [16]byte{10, 0, 0, 1},
				Proto: 6, // TCP
			},
		}
		engine.Ingest(ctx, event)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for learning phase to complete
	time.Sleep(200 * time.Millisecond)

	// Now send anomalous events (different port)
	for i := 0; i < 5; i++ {
		event := types.Event{
			Type:      types.EventTCPConnect,
			Timestamp: uint64(time.Now().UnixNano()),
			PID:       1234,
			TGID:      1234,
			UID:       1000,
			Comm:      [16]byte{'t', 'e', 's', 't'},
			Network: &types.NetworkEvent{
				Dport: 9999, // Anomalous port
				Daddr: [16]byte{192, 168, 1, 1},
				Sport: 12345,
				Saddr: [16]byte{10, 0, 0, 1},
				Proto: 6,
			},
		}
		alerts := engine.Ingest(ctx, event)

		// Send any anomaly alerts to Alertmanager
		for _, alert := range alerts {
			if alert.RuleID == "anomaly_detection" {
				alertClient.SendAlert(ctx, alert)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Flush alerts to ensure they're sent
	alertClient.Flush()
	time.Sleep(200 * time.Millisecond)

	// Verify that at least one anomaly alert was received
	require.NotEmpty(t, receivedAlerts, "expected at least one anomaly alert to reach Alertmanager")

	// Find anomaly alert
	var anomalyAlert *types.AlertPayload
	for i := range receivedAlerts {
		if receivedAlerts[i].Labels.RuleID == "anomaly_detection" {
			anomalyAlert = &receivedAlerts[i]
			break
		}
	}

	require.NotNil(t, anomalyAlert, "expected to find anomaly_detection alert in received alerts")
	assert.Equal(t, "warning", anomalyAlert.Labels.Severity)
	assert.Contains(t, anomalyAlert.Annotations.Summary, "Anomaly")
}

// TestAnomalyAlertWithK8sEnrichment verifies that anomaly alerts include
// Kubernetes metadata when enrichment is available.
func TestAnomalyAlertWithK8sEnrichment(t *testing.T) {
	// Create correlation engine
	engineConfig := correlator.CorrelationEngineConfig{
		Rules:              []correlator.Rule{},
		BufferSize:         100,
		EnableAnomaly:      true,
		AnomalyThreshold:   0.1,
		LearningPeriod:     100 * time.Millisecond,
		MinLearningSamples: 5,
		EWMAWeight:         0.3,
		EnableRateLimit:    false,
		RateLimitWindow:    time.Minute,
		MaxAlertsPerWindow: 100,
	}
	engine := correlator.NewCorrelationEngineWithConfig(engineConfig)

	ctx := context.Background()

	// Shared enrichment: all events from the same pod carry the same metadata.
	// Baseline and anomalous events must use the same workload key so they
	// score against the same behavioral profile.
	podEnrichment := &types.EnrichmentInfo{
		PodName:     "test-pod-abc123",
		Namespace:   "test-namespace",
		ContainerID: "container123",
	}

	// Send baseline events
	for i := 0; i < 10; i++ {
		event := types.Event{
			Type:      types.EventFileAccess,
			Timestamp: uint64(time.Now().UnixNano()),
			PID:       5678,
			TGID:      5678,
			UID:       1000,
			Comm:      [16]byte{'a', 'p', 'p'},
			Enrichment: podEnrichment,
			File: &types.FileEvent{
				// Baseline: app normally reads its own log directory.
				Filename: [256]byte{'/', 'v', 'a', 'r', '/', 'l', 'o', 'g', '/', 'a', 'p', 'p', '.', 'l', 'o', 'g'},
				Flags:    0,
				Mode:     0644,
				Op:       0,
			},
		}
		engine.Ingest(ctx, event)
	}

	// Wait for learning
	time.Sleep(200 * time.Millisecond)

	// Send anomalous event with the same K8s enrichment so it scores against
	// the baseline profile established above.
	event := types.Event{
		Type:      types.EventFileAccess,
		Timestamp: uint64(time.Now().UnixNano()),
		PID:       5678,
		TGID:      5678,
		UID:       1000,
		Comm:      [16]byte{'a', 'p', 'p'},
		Enrichment: podEnrichment,
		File: &types.FileEvent{
			Filename: [256]byte{'/', 'e', 't', 'c', '/', 's', 'h', 'a', 'd', 'o', 'w'},
			Flags:    0,
			Mode:     0644,
			Op:       0,
		},
	}

	alerts := engine.Ingest(ctx, event)

	// Find anomaly alert
	var anomalyAlert *types.Alert
	for i := range alerts {
		if alerts[i].RuleID == "anomaly_detection" {
			anomalyAlert = &alerts[i]
			break
		}
	}

	require.NotNil(t, anomalyAlert, "expected anomaly alert")
	assert.Equal(t, "test-pod-abc123", anomalyAlert.Enrichment.PodName)
	assert.Equal(t, "test-namespace", anomalyAlert.Enrichment.Namespace)
}

// TestDryRunModeAnomalyDetection verifies anomaly detection works in dry-run mode.
func TestDryRunModeAnomalyDetection(t *testing.T) {
	// This test simulates the dry-run mode behavior where synthetic events
	// are generated and processed through the correlation engine.

	cfg := &config.Config{
		Profiler: config.ProfilerConfig{
			Enabled:          true,
			AnomalyThreshold: 0.1,
			EWMAWeight:       0.3,
		},
	}

	// Create engine with anomaly detection
	engineConfig := correlator.CorrelationEngineConfig{
		Rules:              []correlator.Rule{},
		BufferSize:         1000,
		EnableAnomaly:      cfg.Profiler.Enabled,
		AnomalyThreshold:   cfg.Profiler.AnomalyThreshold,
		LearningPeriod:     100 * time.Millisecond,
		MinLearningSamples: 5,
		EWMAWeight:         cfg.Profiler.EWMAWeight,
		EnableRateLimit:    false,
		RateLimitWindow:    time.Minute,
		MaxAlertsPerWindow: 100,
	}
	engine := correlator.NewCorrelationEngineWithConfig(engineConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Simulate synthetic events (like dry-run mode)
	baselinePort := uint16(443)
	anomalousPort := uint16(31337)

	// Send baseline events
	for i := 0; i < 20; i++ {
		event := types.Event{
			Type:      types.EventTCPConnect,
			Timestamp: uint64(time.Now().UnixNano()),
			PID:       9999,
			TGID:      9999,
			UID:       0,
			Comm:      [16]byte{'s', 'y', 'n', 't', 'h', 'e', 't', 'i', 'c'},
			Network: &types.NetworkEvent{
				Dport: baselinePort,
				Daddr: [16]byte{1, 1, 1, 1},
				Sport: 54321,
				Saddr: [16]byte{127, 0, 0, 1},
				Proto: 6,
			},
		}
		engine.Ingest(ctx, event)
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for learning phase
	time.Sleep(150 * time.Millisecond)

	// Send anomalous events
	alertCount := 0
	for i := 0; i < 10; i++ {
		event := types.Event{
			Type:      types.EventTCPConnect,
			Timestamp: uint64(time.Now().UnixNano()),
			PID:       9999,
			TGID:      9999,
			UID:       0,
			Comm:      [16]byte{'s', 'y', 'n', 't', 'h', 'e', 't', 'i', 'c'},
			Network: &types.NetworkEvent{
				Dport: anomalousPort,
				Daddr: [16]byte{1, 1, 1, 1},
				Sport: 54321,
				Saddr: [16]byte{127, 0, 0, 1},
				Proto: 6,
			},
		}
		alerts := engine.Ingest(ctx, event)
		for _, alert := range alerts {
			if alert.RuleID == "anomaly_detection" {
				alertCount++
			}
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Should have generated anomaly alerts
	assert.Greater(t, alertCount, 0, "expected at least one anomaly alert in dry-run mode")
}
