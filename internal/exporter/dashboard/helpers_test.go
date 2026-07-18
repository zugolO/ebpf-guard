package dashboard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboardHelpers exercises the pure app.js helpers that back the newest
// dashboard features under Node, so the client-side logic is covered the same
// way the server-side handlers are:
//
//   - alertSortKey / durationBetween — alert aggregation feed ordering and the
//     "×N over a window" display (issue #307). These are exported from app.js
//     specifically for unit testing but were previously untested.
//   - buildFilterParams — the shared severity/rule/comm/since query builder;
//     comm must be forwarded so it is applied server-side against the full
//     alert set, not just the loaded page (issue #310).
//   - healthDegradedReason — the agent-health widget's degraded-visibility
//     sentence, so "no alerts" is distinguishable from "agent degraded"
//     (issue #309).
//
// The test skips when Node is unavailable so it never blocks a Go-only
// environment, matching escaping_test.go / fleet_test.go.
func TestDashboardHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping app.js helpers test")
	}

	appJS, err := filepath.Abs(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("resolve app.js path: %v", err)
	}

	harness := `
	globalThis.document = { addEventListener: function(){}, getElementById: function(){ return { addEventListener: function(){} }; } };
	globalThis.localStorage = { getItem: function(){ return ""; }, setItem: function(){}, removeItem: function(){} };
	const { alertSortKey, durationBetween, buildFilterParams, healthDegradedReason } = require(process.argv[2]);

	function must(cond, msg) { if (!cond) { console.error("FAIL: " + msg); process.exitCode = 1; } }

	// alertSortKey: an aggregated (still-firing) alert must sort on last_seen so
	// a storm stays at the top of the feed instead of sinking to first_seen.
	must(alertSortKey({ timestamp: "t0", last_seen: "t9" }) === "t9", "aggregated alert sorts on last_seen");
	must(alertSortKey({ timestamp: "t0" }) === "t0", "single alert falls back to timestamp");

	// durationBetween: compact h/m/s formatting of an aggregation window.
	must(durationBetween("2026-01-01T00:00:00Z", "2026-01-01T00:00:45Z") === "45s", "sub-minute -> Ns");
	must(durationBetween("2026-01-01T00:00:00Z", "2026-01-01T00:02:05Z") === "2m 5s", "minutes -> Nm Ns");
	must(durationBetween("2026-01-01T00:00:00Z", "2026-01-01T01:12:30Z") === "1h 12m", "hours -> Nh Nm");
	// A reversed pair (last_seen before first_seen) must clamp at 0, not go negative.
	must(durationBetween("2026-01-01T00:01:00Z", "2026-01-01T00:00:00Z") === "0s", "reversed span clamps to 0s");

	// buildFilterParams: only set fields are emitted, and comm is forwarded so
	// it is filtered server-side (issue #310).
	const full = buildFilterParams({ since: "1h", severity: "critical", rule_id: "r1", comm: "nginx" });
	must(full.get("comm") === "nginx", "comm forwarded to server");
	must(full.get("severity") === "critical", "severity forwarded");
	must(full.get("rule_id") === "r1", "rule_id forwarded");
	must(full.get("since") === "1h", "since forwarded");
	must(!full.has("limit"), "filter params carry no row limit");

	const empty = buildFilterParams({ since: "", severity: "", rule_id: "", comm: "" });
	must(empty.toString() === "", "empty filters emit no params");

	// healthDegradedReason: only speaks up when visibility is actually reduced.
	must(healthDegradedReason(null) === "", "no health -> empty reason");
	must(healthDegradedReason({ visibility_reduced: false }) === "", "healthy -> empty reason");
	const reason = healthDegradedReason({ visibility_reduced: true, cpu_pressure_level: 1, cpu_pressure_percent: 82.4 });
	must(reason.indexOf("Visibility reduced") === 0, "degraded reason leads with the headline: " + reason);
	must(reason.indexOf("file sampling reduced") !== -1, "degraded reason names the pressure level: " + reason);
	must(reason.indexOf("82%") !== -1, "degraded reason rounds the CPU percent: " + reason);

	if (process.exitCode !== 1) console.log("OK");
	`

	tmp := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(tmp, []byte(harness), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	out, err := exec.Command(node, tmp, appJS).CombinedOutput()
	if err != nil {
		t.Fatalf("node helper assertions failed:\n%s", out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("unexpected node output:\n%s", out)
	}
}
