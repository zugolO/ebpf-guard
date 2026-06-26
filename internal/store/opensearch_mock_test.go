package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockOpenSearch returns a store wired to an httptest server that emulates
// the OpenSearch REST endpoints used by the store.
func newMockOpenSearch(t *testing.T) *OpenSearchStore {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_cluster/health"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"green"}`))
		case strings.Contains(r.URL.Path, "/_doc/found-1"):
			_, _ = w.Write([]byte(`{"found":true,"_source":{"rule_id":"rule-x","severity":"critical","pid":42,"comm":"evil","message":"m"}}`))
		case strings.Contains(r.URL.Path, "/_doc/"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/_count"):
			_, _ = w.Write([]byte(`{"count":7}`))
		case strings.HasSuffix(r.URL.Path, "/_delete_by_query"):
			_, _ = w.Write([]byte(`{"deleted":3}`))
		case strings.HasSuffix(r.URL.Path, "/_search"):
			_, _ = w.Write([]byte(`{"hits":{"hits":[{"_id":"a1","_source":{"rule_id":"r","severity":"warning","pid":1,"comm":"c","message":"m"}}]}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)

	s, err := NewOpenSearchStore(OpenSearchConfig{
		Addresses:   []string{srv.URL},
		IndexPrefix: "ebpf-guard-test",
	})
	require.NoError(t, err)
	return s
}

func TestOpenSearchStore_MockedEndpoints(t *testing.T) {
	ctx := context.Background()
	s := newMockOpenSearch(t)

	t.Run("Healthy", func(t *testing.T) {
		assert.True(t, s.Healthy(ctx))
	})

	t.Run("QueryByID found", func(t *testing.T) {
		got, err := s.QueryByID(ctx, "found-1")
		require.NoError(t, err)
		assert.Equal(t, "found-1", got.ID)
		assert.Equal(t, "rule-x", got.RuleID)
		assert.Equal(t, uint32(42), got.PID)
	})

	t.Run("QueryByID not found", func(t *testing.T) {
		_, err := s.QueryByID(ctx, "missing")
		require.Error(t, err)
	})

	t.Run("Count", func(t *testing.T) {
		n, err := s.Count(ctx, QueryFilters{})
		require.NoError(t, err)
		assert.Equal(t, int64(7), n)
	})

	t.Run("Delete", func(t *testing.T) {
		n, err := s.Delete(ctx, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, int64(3), n)
	})

	t.Run("Query", func(t *testing.T) {
		results, err := s.Query(ctx, QueryFilters{})
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "r", results[0].RuleID)
	})

	t.Run("Flush and Close are no-ops", func(t *testing.T) {
		require.NoError(t, s.Flush(ctx))
		require.NoError(t, s.Close())
	})
}
