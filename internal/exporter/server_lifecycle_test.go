package exporter

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_SettersAndSetup(t *testing.T) {
	srv := NewServerWithOptions("127.0.0.1:0", "/metrics", "/health", false, true)

	// Debug handler is created when enableDebug=true.
	assert.NotNil(t, srv.GetDebugHandler())

	// Explainer setup + style selection.
	require.NoError(t, srv.SetupExplainer(""))
	srv.SetExplainerStyle("plain")
	srv.SetExplainerStyle("technical")
	srv.SetExplainerStyle("full")
	srv.SetExplainerStyle("bogus") // unknown → keeps current, no panic

	// Feedback manager setup (in-memory).
	require.NoError(t, srv.SetupFeedbackManager(""))

	// Misc setters.
	srv.SetBPFAttached(true)
	srv.SetCORSAllowedOrigins([]string{"https://example.com"})
	srv.RegisterGossipRoutes(http.NewServeMux())
	srv.SetHealthy(true)
	srv.SetReady(true)
	assert.True(t, srv.AllCollectorsHealthy())
}

func TestServer_StartShutdown(t *testing.T) {
	srv := NewServerWithOptions("127.0.0.1:0", "/metrics", "/health", false, false)

	ctx := context.Background()
	require.NoError(t, srv.Start(ctx))

	// Give the listener a moment to come up, then shut down gracefully.
	time.Sleep(20 * time.Millisecond)

	shutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	require.NoError(t, srv.Shutdown(shutCtx))
}
