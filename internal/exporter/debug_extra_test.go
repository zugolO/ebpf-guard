package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSilenceProvider struct{ s []SilenceState }

func (f fakeSilenceProvider) GetActiveSilences() []SilenceState { return f.s }

type fakeEngineProvider struct{ s EngineStats }

func (f fakeEngineProvider) GetStats() EngineStats { return f.s }

type fakeProfilerProvider struct{ s ProfilerStats }

func (f fakeProfilerProvider) GetStats() ProfilerStats { return f.s }

type fakeEnricherProvider struct{ s EnrichmentStats }

func (f fakeEnricherProvider) GetStats() EnrichmentStats { return f.s }

func TestDebugHandler_ServeHTTP(t *testing.T) {
	h := NewDebugHandler("v1.2.3", nil)
	h.SetRules([]RuleState{{ID: "r1", Name: "rule one", EventType: "syscall", Severity: "critical", Action: "alert"}})
	h.SetSilenceProvider(fakeSilenceProvider{s: []SilenceState{{RuleID: "r1"}}})
	h.SetEngineProvider(fakeEngineProvider{s: EngineStats{TotalEvents: 10, TotalAlerts: 2, RulesLoaded: 1}})
	h.SetProfilerProvider(fakeProfilerProvider{s: ProfilerStats{LearningComplete: true, LearningProgress: 1.0, ProfilesActive: 3}})
	h.SetEnricherProvider(fakeEnricherProvider{s: EnrichmentStats{Enabled: true, CachedPods: 5}})
	h.SetHardwareProfile(HardwareProfileState{
		Profile: "lite", Source: "autodetect", Reason: "detected 1 CPU(s) / 1024MB RAM",
		CPUs: 1, MemTotalMB: 1024, EventsMap: 8192, ProcessesMap: 2048, ConnectionsMap: 4096,
		MaxTrackedPIDs: 256, SequenceEnabled: false, LineageEnabled: false,
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/debug/state", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var state DebugState
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &state))
	assert.Equal(t, "v1.2.3", state.Version)
	require.Len(t, state.Rules, 1)
	assert.Equal(t, "r1", state.Rules[0].ID)
	assert.Len(t, state.ActiveSilences, 1)
	assert.Equal(t, uint64(10), state.EngineStats.TotalEvents)
	assert.True(t, state.ProfilerStats.LearningComplete)
	assert.Equal(t, 5, state.EnrichmentStats.CachedPods)
	assert.Equal(t, "lite", state.HardwareProfile.Profile)
	assert.Equal(t, "autodetect", state.HardwareProfile.Source)
	assert.Equal(t, 8192, state.HardwareProfile.EventsMap)
}

func TestDebugHandler_ServeHTTP_NoProviders(t *testing.T) {
	// With no providers set, buildState must still produce valid JSON.
	h := NewDebugHandler("dev", nil)
	req := httptest.NewRequest(http.MethodGet, "/debug/state", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var state DebugState
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &state))
	assert.Equal(t, "dev", state.Version)
}
