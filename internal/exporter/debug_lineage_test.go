package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDebugLineageRoute(t *testing.T) {
	h := NewDebugHandler("test", nil)
	rec := httptest.NewRecorder()
	h.ServeLineage(rec, httptest.NewRequest(http.MethodGet, "/debug/lineage?pid=7", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("без провайдера ждали 404, got %d", rec.Code)
	}
	h.SetLineageProvider(func(pid uint32) any { return map[string]uint32{"pid": pid} })
	rec = httptest.NewRecorder()
	h.ServeLineage(rec, httptest.NewRequest(http.MethodGet, "/debug/lineage?pid=7", nil))
	if rec.Code != 200 || rec.Body.String() != "{\"pid\":7}\n" {
		t.Fatalf("code=%d body=%q", rec.Code, rec.Body.String())
	}
	for _, q := range []string{"", "?pid=x", "?pid=0"} {
		rec = httptest.NewRecorder()
		h.ServeLineage(rec, httptest.NewRequest(http.MethodGet, "/debug/lineage"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: ждали 400, got %d", q, rec.Code)
		}
	}
}
