// vulnweb: a deliberately vulnerable minimal web app used as a realistic
// wave-6.1 attack target. Its request handler reads a user-controlled path
// with no sanitization (classic LFI). Compiled to a binary named "vulnweb",
// its OS threads carry comm="vulnweb" — OUTSIDE the Q9 web comm-list — so the
// LFI is caught by the container.id axis alone when containerized, and by
// nothing when run on the host (the wave-6.1 host/container discriminator).
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	addr := ":8091"
	if a := os.Getenv("ADDR"); a != "" {
		addr = a
	}
	http.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("path")
		if p == "" {
			p = "/etc/passwd"
		}
		b, err := os.ReadFile(p) // intentional LFI: no sanitization
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(b)
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	_ = http.ListenAndServe(addr, nil)
}
