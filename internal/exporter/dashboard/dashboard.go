// Package dashboard provides an embedded, self-contained web UI for browsing
// alerts, rules, and summary statistics. Assets are embedded at build time —
// no CDN or external dependency is required, so the UI works fully offline.
package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/index.html static/app.js static/style.css
var assets embed.FS

// csp is the Content-Security-Policy applied to every dashboard response.
// Only same-origin resources are allowed; no inline scripts, no CDNs.
const csp = "default-src 'self'; " +
	"script-src 'self'; " +
	"connect-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'"

// Handler returns an http.Handler that serves the embedded dashboard assets
// under the /ui/ path prefix.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic("dashboard: embedded assets not found — ensure static/index.html, static/app.js, and static/style.css exist")
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.StripPrefix("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileServer.ServeHTTP(w, r)
	}))
}
