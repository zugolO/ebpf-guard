package exporter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestAlertmanager_ConcurrentSendAlert tests for race conditions in SendAlert
func TestAlertmanager_ConcurrentSendAlert(t *testing.T) {
	client := NewAlertmanagerClient("http://localhost:9093", "http://localhost:9090", 100, 1, 5)
	ctx := context.Background()

	var wg sync.WaitGroup
	numGoroutines := 50
	numAlerts := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numAlerts; j++ {
				alert := types.Alert{
					RuleID:   "rule_001",
					RuleName: "Test Rule",
					Severity: types.SeverityCritical,
				}
				client.SendAlert(ctx, alert)
			}
		}(i)
	}

	wg.Wait()

	// Flush remaining alerts
	client.Flush()
}

// TestAlertmanager_ConcurrentSendAndClose tests for race between SendAlert and Close
func TestAlertmanager_ConcurrentSendAndClose(t *testing.T) {
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		client := NewAlertmanagerClient("http://localhost:9093", "http://localhost:9090", 1000, 1, 5)

		var wg sync.WaitGroup

		// Send alerts continuously
		for j := 0; j < 10; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 100; k++ {
					alert := types.Alert{
						RuleID:   "rule_001",
						RuleName: "Test Rule",
						Severity: types.SeverityCritical,
					}
					client.SendAlert(ctx, alert)
					time.Sleep(time.Microsecond)
				}
			}()
		}

		// Close while sending
		time.Sleep(5 * time.Millisecond)
		err := client.Close()
		assert.NoError(t, err)

		wg.Wait()
	}
}

// TestAlertmanager_TimerRace tests for timer-related race conditions
func TestAlertmanager_TimerRace(t *testing.T) {
	client := NewAlertmanagerClient("http://localhost:9093", "http://localhost:9090", 1000, 1, 5)
	ctx := context.Background()

	var wg sync.WaitGroup
	numIterations := 100

	// Rapid send and flush to trigger timer races
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				alert := types.Alert{
					RuleID:   "rule_001",
					RuleName: "Test Rule",
					Severity: types.SeverityCritical,
				}
				client.SendAlert(ctx, alert)

				// Occasionally flush
				if j%10 == 0 {
					client.Flush()
				}
			}
		}()
	}

	wg.Wait()
	client.Close()
}

// TestAlertmanager_CloseIdempotent tests that Close can be called multiple times safely
func TestAlertmanager_CloseIdempotent(t *testing.T) {
	client := NewAlertmanagerClient("http://localhost:9093", "http://localhost:9090", 100, 1, 5)
	ctx := context.Background()

	// Add some alerts
	for i := 0; i < 10; i++ {
		client.SendAlert(ctx, types.Alert{
			RuleID:   "rule_001",
			RuleName: "Test Rule",
			Severity: types.SeverityCritical,
		})
	}

	// Close multiple times should not panic
	err := client.Close()
	assert.NoError(t, err)

	// After close, SendAlert should be a no-op (not panic)
	client.SendAlert(ctx, types.Alert{
		RuleID:   "rule_001",
		RuleName: "Test Rule",
		Severity: types.SeverityCritical,
	})
}

// TestAlertmanager_SendAfterClose tests SendAlert after Close is safe
func TestAlertmanager_SendAfterClose(t *testing.T) {
	client := NewAlertmanagerClient("http://localhost:9093", "http://localhost:9090", 100, 1, 5)
	ctx := context.Background()

	// Close first
	err := client.Close()
	assert.NoError(t, err)

	// Send after close should not panic or cause races
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				client.SendAlert(ctx, types.Alert{
					RuleID:   "rule_001",
					RuleName: "Test Rule",
					Severity: types.SeverityCritical,
				})
			}
		}()
	}
	wg.Wait()
}
