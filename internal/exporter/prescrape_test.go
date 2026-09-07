package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A scrape must refresh on-demand counters before rendering: 5.9.6b's balance
// identity is only exact if both sides describe the same instant.
func TestMetricsHandler_RunsPreScrapeHook(t *testing.T) {
	called := 0
	RegisterPreScrapeHook(func() { called++ })
	t.Cleanup(func() {
		preScrapeMu.Lock()
		preScrapeHooks = nil
		preScrapeMu.Unlock()
	})

	rec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if called != 1 {
		t.Fatalf("pre-scrape hook ran %d times, want 1", called)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics scrape returned %d, want 200", rec.Code)
	}
}

// A broken hook must not take /metrics down — a stale counter beats no
// evidence at all.
func TestMetricsHandler_PanickingHookDoesNotBreakScrape(t *testing.T) {
	RegisterPreScrapeHook(func() { panic("boom") })
	t.Cleanup(func() {
		preScrapeMu.Lock()
		preScrapeHooks = nil
		preScrapeMu.Unlock()
	})

	rec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("metrics scrape returned %d after panicking hook, want 200", rec.Code)
	}
}

// №259: a scrape landing after graceful shutdown has disabled pre-scrape
// hooks must not run them — those hooks read BPF maps that the shutdown
// sequence closes right around the same time, and a hook that fires anyway
// logs "kernel_counter: failed to read counter ... bad file descriptor".
func TestMetricsHandler_DisabledHooksDoNotRun(t *testing.T) {
	called := 0
	RegisterPreScrapeHook(func() { called++ })
	t.Cleanup(func() {
		preScrapeMu.Lock()
		preScrapeHooks = nil
		preScrapeMu.Unlock()
		preScrapeDisabled.Store(false)
	})

	DisablePreScrapeHooks()

	rec := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if called != 0 {
		t.Fatalf("pre-scrape hook ran %d times after DisablePreScrapeHooks, want 0", called)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics scrape returned %d after disabling hooks, want 200", rec.Code)
	}
}
