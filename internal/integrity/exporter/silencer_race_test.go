package exporter

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestSilencer_ConcurrentIsSilenced tests for race conditions in IsSilenced
func TestSilencer_ConcurrentIsSilenced(t *testing.T) {
	silencer := NewAlertSilencer()
	
	// Pre-populate with some silences
	silencer.Silence("rule_001:critical", 1*time.Hour, "test")
	silencer.Silence("rule_002:warning", 1*time.Minute, "test")
	
	var wg sync.WaitGroup
	numGoroutines := 100
	numIterations := 100
	
	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				alert := types.Alert{
					RuleID:   "rule_001",
					Severity: types.SeverityCritical,
				}
				_ = silencer.IsSilenced(alert)
			}
		}(i)
	}
	
	// Concurrent writes (expired silence cleanup)
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				alert := types.Alert{
					RuleID:   "rule_002",
					Severity: types.SeverityWarning,
				}
				// This will trigger cleanup of expired window
				silencer.IsSilenced(alert)
			}
		}(i)
	}
	
	wg.Wait()
}

// TestSilencer_ConcurrentSilenceAndIsSilenced tests concurrent Silence and IsSilenced
func TestSilencer_ConcurrentSilenceAndIsSilenced(t *testing.T) {
	silencer := NewAlertSilencer()
	
	var wg sync.WaitGroup
	numGoroutines := 50
	numIterations := 100
	
	// Concurrent Silence calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				key := fmt.Sprintf("rule_%d:critical", id%10)
				silencer.Silence(key, time.Hour, "test")
			}
		}(i)
	}
	
	// Concurrent IsSilenced calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				alert := types.Alert{
					RuleID:   fmt.Sprintf("rule_%d", id%10),
					Severity: types.SeverityCritical,
				}
				_ = silencer.IsSilenced(alert)
			}
		}(i)
	}
	
	wg.Wait()
}

// TestSilencer_ExpiredWindowCleanup tests that expired windows are properly cleaned up
func TestSilencer_ExpiredWindowCleanup(t *testing.T) {
	silencer := NewAlertSilencer()
	
	// Create a very short-lived silence
	silencer.Silence("rule_001:critical", 1*time.Millisecond, "test")
	
	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)
	
	alert := types.Alert{
		RuleID:   "rule_001",
		Severity: types.SeverityCritical,
	}
	
	// Should not be silenced and should clean up
	isSilenced := silencer.IsSilenced(alert)
	assert.False(t, isSilenced)
	
	// Verify cleanup
	silencer.mu.RLock()
	_, exists := silencer.windows["rule_001:critical"]
	silencer.mu.RUnlock()
	assert.False(t, exists, "expired window should be cleaned up")
}

// TestSilencer_CleanupConcurrentAccess tests Cleanup with concurrent access
func TestSilencer_CleanupConcurrentAccess(t *testing.T) {
	silencer := NewAlertSilencer()
	
	// Create mix of expired and active silences
	silencer.Silence("rule_001:critical", 1*time.Millisecond, "test")
	silencer.Silence("rule_002:critical", 1*time.Hour, "test")
	
	time.Sleep(10 * time.Millisecond)
	
	var wg sync.WaitGroup
	
	// Concurrent Cleanup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			silencer.Cleanup()
		}()
	}
	
	// Concurrent IsSilenced
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			alert := types.Alert{
				RuleID:   "rule_002",
				Severity: types.SeverityCritical,
			}
			_ = silencer.IsSilenced(alert)
		}()
	}
	
	wg.Wait()
}
