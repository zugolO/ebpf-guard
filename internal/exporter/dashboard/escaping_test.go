package dashboard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboardEscaping exercises the real app.js escapeHTML/safeURL helpers
// under Node to lock the fix for #302: escapeHTML must escape BOTH quote
// characters (so attacker-controlled comm/message cannot break out of the
// title="…"/href="…" attributes they are interpolated into), and safeURL must
// reject non-http(s) schemes. The test skips when Node is unavailable so it
// never blocks a Go-only environment.
func TestDashboardEscaping(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping app.js escaping test")
	}

	appJS, err := filepath.Abs(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("resolve app.js path: %v", err)
	}

	harness := `
	globalThis.document = { addEventListener: function(){}, getElementById: function(){ return { addEventListener: function(){} }; } };
	globalThis.localStorage = { getItem: function(){ return ""; }, setItem: function(){}, removeItem: function(){} };
	const { escapeHTML, safeURL } = require(process.argv[2]);

	function must(cond, msg) { if (!cond) { console.error("FAIL: " + msg); process.exitCode = 1; } }

	// Quotes must be escaped — this is the core of the vulnerability.
	const attr = escapeHTML('x" onfoo="alert(1)');
	must(!attr.includes('"'), 'double quote must be escaped: ' + attr);
	must(attr.includes('&#34;'), 'expected &#34; entity: ' + attr);

	must(escapeHTML("'") === '&#39;', "single quote must be escaped");
	must(escapeHTML("<img src=x>") === '&lt;img src=x&gt;', "angle brackets must be escaped");
	must(escapeHTML("a&b") === 'a&amp;b', "ampersand must be escaped");
	must(escapeHTML(null) === '', "null must render as empty string");

	// A payload that closes the attribute and injects markup must be inert.
	const evil = escapeHTML('">' + '<img src=x onerror=alert(1)>');
	must(!evil.includes('">'), 'attribute break-out must be neutralised: ' + evil);

	// safeURL: only http/https survive.
	must(safeURL("https://attack.mitre.org/T1055") === "https://attack.mitre.org/T1055", "https url kept");
	must(safeURL("http://example.com") === "http://example.com", "http url kept");
	must(safeURL("javascript:alert(1)") === "#", "javascript: rejected");
	must(safeURL("data:text/html,<script>") === "#", "data: rejected");
	must(safeURL("  javascript:alert(1)") === "#", "leading-space javascript: rejected");
	must(safeURL(null) === "#", "null url rejected");

	if (process.exitCode !== 1) console.log("OK");
	`

	tmp := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(tmp, []byte(harness), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	out, err := exec.Command(node, tmp, appJS).CombinedOutput()
	if err != nil {
		t.Fatalf("node escaping assertions failed:\n%s", out)
	}
	if !strings.Contains(string(out), "OK") {
		t.Fatalf("unexpected node output:\n%s", out)
	}
}
