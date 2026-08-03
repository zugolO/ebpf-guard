package dashboard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboardFleetHelpers exercises the fleet-view helpers added for
// issue #312 under Node: agent list persistence in localStorage, and that an
// unreachable/erroring agent resolves to {online:false} instead of rejecting
// the whole Promise.all — a single dead node must not blank out the rest of
// the fleet summary.
func TestDashboardFleetHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping app.js fleet test")
	}

	appJS, err := filepath.Abs(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("resolve app.js path: %v", err)
	}

	harness := `
	const store = {};
	globalThis.document = { addEventListener: function(){}, getElementById: function(){ return { addEventListener: function(){} }; } };
	globalThis.localStorage = {
	  getItem: function(k){ return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
	  setItem: function(k, v){ store[k] = v; },
	  removeItem: function(k){ delete store[k]; },
	};
	const { getFleetAgents, saveFleetAgents, fetchFleetNode } = require(process.argv[2]);

	function must(cond, msg) { if (!cond) { console.error("FAIL: " + msg); process.exitCode = 1; } }

	must(getFleetAgents().length === 0, "no agents initially");

	saveFleetAgents([{ id: "1", name: "vps-2", url: "https://vps-2.example.com", token: "tok" }]);
	const loaded = getFleetAgents();
	must(loaded.length === 1, "one agent persisted");
	must(loaded[0].name === "vps-2", "agent name round-trips");

	localStorage.setItem("ebpf-guard-fleet-agents", "not json");
	must(getFleetAgents().length === 0, "malformed localStorage value degrades to empty list, not a throw");

	(async () => {
	  globalThis.fetch = async () => { throw new Error("network error"); };
	  const result = await fetchFleetNode({ id: "1", name: "dead-node", url: "https://dead.example.com", token: "x" });
	  must(result.online === false, "unreachable agent resolves online:false");
	  must(result.agent.name === "dead-node", "agent identity is preserved on failure");
	  must(typeof result.error === "string" && result.error.length > 0, "error message is captured");

	  globalThis.fetch = async () => ({ ok: true, json: async () => ({ total: 3, by_severity: { critical: 1 } }) });
	  const ok = await fetchFleetNode({ id: "2", name: "live-node", url: "https://live.example.com", token: "x" });
	  must(ok.online === true, "reachable agent resolves online:true");
	  must(ok.summary.total === 3, "summary payload is passed through");

	  if (process.exitCode !== 1) console.log("OK");
	})();
	`

	tmp := filepath.Join(t.TempDir(), "fleet-harness.js")
	if err := os.WriteFile(tmp, []byte(harness), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	out, err := exec.Command(node, tmp, appJS).CombinedOutput()
	if err != nil {
		t.Fatalf("node fleet assertions failed:\n%s", out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("unexpected node output:\n%s", out)
	}
}
