// Package swaggerui provides embedded Swagger UI assets for the API documentation.
// The swagger-ui-dist files are embedded at build time, eliminating the CDN dependency.
package swaggerui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed swagger-ui.css swagger-ui-bundle.js
var assets embed.FS

// Handler returns an http.Handler that serves the embedded Swagger UI assets
// under the /swaggerui/ path prefix.
func Handler() http.Handler {
	sub, err := fs.Sub(assets, ".")
	if err != nil {
		panic("swaggerui: embedded assets not found — ensure swagger-ui.css and swagger-ui-bundle.js exist in the swaggerui directory")
	}
	return http.StripPrefix("/swaggerui/", http.FileServer(http.FS(sub)))
}
