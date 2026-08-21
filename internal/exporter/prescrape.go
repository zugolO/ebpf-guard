// Scrape-time hooks for metrics that are only readable on demand.
package exporter

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Pre-scrape hooks exist because two of the metrics this package publishes
// are not written by the code path that produces the underlying events: the
// kernel-side counters of 5.9.6a/5.9.6b (ringbuf_full_counters,
// events_emitted_counters) live in BPF per-CPU maps and reach Prometheus only
// when something drains them. Draining on a timer alone makes those series
// lag every other series by up to one tick, and 5.9.6b's balance identity
// subtracts a lagging left-hand side from an up-to-date right-hand side: on
// the stand the resulting residual was −7288 for fileaccess against the
// gate's ±500 floor, i.e. an apparent accounting hole that is purely an
// artefact of when the counters were read. Draining at scrape time removes
// the lag term: both sides of the identity then describe the same instant.
var (
	preScrapeMu    sync.RWMutex
	preScrapeHooks []func()
)

// RegisterPreScrapeHook adds fn to the set of callbacks run immediately
// before /metrics is rendered. Hooks must be cheap and non-blocking — they
// run inside the scrape request — and must be safe to call concurrently with
// their own periodic drain, since the timer-driven drain keeps running.
func RegisterPreScrapeHook(fn func()) {
	if fn == nil {
		return
	}
	preScrapeMu.Lock()
	preScrapeHooks = append(preScrapeHooks, fn)
	preScrapeMu.Unlock()
}

// runPreScrapeHooks executes every registered hook. A panicking hook must not
// take the metrics endpoint down with it: /metrics is the primary evidence
// channel of the whole agent, and a scrape that returns stale kernel counters
// is far better than a scrape that returns nothing.
func runPreScrapeHooks() {
	preScrapeMu.RLock()
	hooks := make([]func(), len(preScrapeHooks))
	copy(hooks, preScrapeHooks)
	preScrapeMu.RUnlock()

	for _, fn := range hooks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("exporter: pre-scrape hook panicked", slog.Any("panic", r))
				}
			}()
			fn()
		}()
	}
}

// MetricsHandler returns the Prometheus handler wrapped so that every scrape
// first refreshes counters that are only readable on demand (see above).
func MetricsHandler() http.Handler {
	inner := promhttp.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runPreScrapeHooks()
		inner.ServeHTTP(w, r)
	})
}
