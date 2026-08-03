package dashboard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCSPForbidsInlineStyle documents why proportional sizing in app.js must go
// through a CSS class rather than element.style: the dashboard CSP sets
// style-src without 'unsafe-inline', and style-src-attr falls back to
// style-src, so assigning el.style.width/height is blocked by the browser. An
// earlier version of the dashboard did exactly that, which left the top-rules
// bars and the alert timeline rendering flat.
//
// If someone ever adds 'unsafe-inline' to relax this, that is a deliberate
// security decision and should fail here first.
func TestCSPForbidsInlineStyle(t *testing.T) {
	if !strings.Contains(csp, "style-src 'self'") {
		t.Fatalf("expected style-src 'self' in CSP, got: %s", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP unexpectedly allows inline styles: %s", csp)
	}
}

// TestNoInlineStyleAssignments guards against reintroducing sized-by-JS
// elements, which the CSP silently drops (no console error is surfaced to the
// operator — the chart just renders empty).
func TestNoInlineStyleAssignments(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	// Scan code only. The helper that replaced these assignments documents the
	// banned pattern in its own comment, which would otherwise self-trip.
	code := stripLineComments(string(src))
	for _, banned := range []string{".style.width", ".style.height", "style=\"width:", "style=\"height:"} {
		if strings.Contains(code, banned) {
			t.Errorf("app.js contains %q, which the dashboard CSP blocks; use pctClass() and a CSS class instead", banned)
		}
	}
}

// stripLineComments removes // line comments so source scans match real code
// rather than prose describing it. Deliberately simple: app.js has no string
// literal containing "//" other than URLs, which are irrelevant to these scans.
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			// Keep URLs like https:// intact — only strip a comment marker that
			// isn't preceded by a colon.
			if i == 0 || line[i-1] != ':' {
				line = line[:i]
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// TestPctClassEmitsOnlyDefinedClasses runs the real pctClass helper under Node
// across a wide range of inputs and asserts every class it can produce is
// actually defined in style.css. A class that exists in JS but not in CSS is
// the same silent-empty-chart failure as an inline style.
func TestPctClassEmitsOnlyDefinedClasses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping pctClass test")
	}

	appJS, err := filepath.Abs(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("resolve app.js path: %v", err)
	}

	harness := `
	globalThis.document = { addEventListener: function(){}, getElementById: function(){ return { addEventListener: function(){} }; } };
	globalThis.localStorage = { getItem: function(){ return ""; }, setItem: function(){}, removeItem: function(){} };
	const { pctClass } = require(process.argv[2]);

	const emitted = new Set();
	// Sweep proportions, plus the degenerate inputs a real payload can carry.
	for (let max = 1; max <= 40; max++) {
		for (let v = 0; v <= max; v++) emitted.add(pctClass(v, max));
	}
	for (const [v, m] of [[0,0], [5,0], [-3,10], [999,10], [1,3], [2,3]]) emitted.add(pctClass(v, m));
	console.log([...emitted].sort().join(" "));
	`

	tmp := filepath.Join(t.TempDir(), "harness.js")
	if err := os.WriteFile(tmp, []byte(harness), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	out, err := exec.Command(node, tmp, appJS).CombinedOutput()
	if err != nil {
		t.Fatalf("node pctClass harness failed:\n%s", out)
	}

	cssBytes, err := os.ReadFile(filepath.Join("static", "style.css"))
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	css := string(cssBytes)

	classes := strings.Fields(strings.TrimSpace(string(out)))
	if len(classes) == 0 {
		t.Fatal("pctClass produced no output")
	}
	for _, c := range classes {
		if !strings.HasPrefix(c, "pct-") {
			t.Errorf("pctClass returned unexpected class %q", c)
			continue
		}
		// Match the selector at a word boundary so pct-5 doesn't match pct-50.
		if !strings.Contains(css, fmt.Sprintf(".%s ", c)) && !strings.Contains(css, fmt.Sprintf(".%s{", c)) {
			t.Errorf("pctClass can emit %q but style.css defines no matching rule", c)
		}
	}

	// Sanity: clamping must keep out-of-range inputs inside the defined set.
	joined := " " + strings.Join(classes, " ") + " "
	if !strings.Contains(joined, " pct-100 ") || !strings.Contains(joined, " pct-0 ") {
		t.Errorf("expected both pct-0 and pct-100 to be reachable, got: %v", classes)
	}
}
