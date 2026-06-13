//go:build rego

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/admission"
)

// newTestWebhookServer creates an in-process admission webhook server backed
// by the real Rego engine, using an httptest.Server so no real port is needed.
func newTestWebhookServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	cfg := admission.Config{
		Mode:        mode,
		WebhookPath: "/admission",
		RegoDir:     "../rules/rego",
	}
	srv, err := admission.NewServer(cfg, nil)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/admission", exportHandler(srv))
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// exportHandler extracts the admission handler from the Server.
// We add a thin shim so tests can call the handler without starting a real TLS listener.
func exportHandler(srv *admission.Server) http.HandlerFunc {
	return srv.HandleAdmission
}

func makeAdmissionReview(ns, operation string, podSpec map[string]interface{}) []byte {
	review := map[string]interface{}{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]interface{}{
			"uid":       "test-uid-1234",
			"namespace": ns,
			"operation": operation,
			"kind": map[string]interface{}{
				"group": "", "version": "v1", "kind": "Pod",
			},
			"resource": map[string]interface{}{
				"group": "", "version": "v1", "resource": "pods",
			},
			"object": map[string]interface{}{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata":   map[string]interface{}{"name": "test-pod", "namespace": ns},
				"spec":       podSpec,
			},
		},
	}
	data, _ := json.Marshal(review)
	return data
}

func doAdmissionRequest(t *testing.T, ts *httptest.Server, body []byte) *admission.AdmissionReview {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Post(ts.URL+"/admission", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var review admission.AdmissionReview
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&review))
	return &review
}

func TestAdmissionWebhook_AllowSafePod(t *testing.T) {
	ts := newTestWebhookServer(t, "enforce")
	podSpec := map[string]interface{}{
		"containers": []interface{}{
			map[string]interface{}{
				"name":  "app",
				"image": "nginx:1.25",
				"securityContext": map[string]interface{}{
					"privileged":               false,
					"allowPrivilegeEscalation": false,
					"runAsUser":                1000,
				},
			},
		},
	}
	review := doAdmissionRequest(t, ts, makeAdmissionReview("default", "CREATE", podSpec))
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "safe pod should be allowed")
	assert.Empty(t, review.Response.Warnings)
}

func TestAdmissionWebhook_DenyHostNetwork_EnforceMode(t *testing.T) {
	ts := newTestWebhookServer(t, "enforce")
	podSpec := map[string]interface{}{
		"hostNetwork": true,
		"containers": []interface{}{
			map[string]interface{}{"name": "app", "image": "nginx:1.25"},
		},
	}
	review := doAdmissionRequest(t, ts, makeAdmissionReview("default", "CREATE", podSpec))
	require.NotNil(t, review.Response)
	assert.False(t, review.Response.Allowed, "hostNetwork pod should be denied in enforce mode")
	assert.NotNil(t, review.Response.Result)
	assert.Contains(t, review.Response.Result.Message, "hostNetwork")
}

func TestAdmissionWebhook_WarnHostNetwork_WarnMode(t *testing.T) {
	ts := newTestWebhookServer(t, "warn")
	podSpec := map[string]interface{}{
		"hostNetwork": true,
		"containers": []interface{}{
			map[string]interface{}{"name": "app", "image": "nginx:1.25"},
		},
	}
	review := doAdmissionRequest(t, ts, makeAdmissionReview("default", "CREATE", podSpec))
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "warn mode should allow pod")
	assert.NotEmpty(t, review.Response.Warnings, "warn mode should surface warnings")
}

func TestAdmissionWebhook_AllowSystemNamespace(t *testing.T) {
	ts := newTestWebhookServer(t, "enforce")
	podSpec := map[string]interface{}{
		"hostNetwork": true,
		"containers": []interface{}{
			map[string]interface{}{"name": "app", "image": "nginx:1.25"},
		},
	}
	// kube-system is exempt from the hostNetwork deny rule
	review := doAdmissionRequest(t, ts, makeAdmissionReview("kube-system", "CREATE", podSpec))
	require.NotNil(t, review.Response)
	assert.True(t, review.Response.Allowed, "kube-system pods with hostNetwork should be allowed")
}

func TestAdmissionWebhook_PrivilegedContainerWarn(t *testing.T) {
	ts := newTestWebhookServer(t, "enforce")
	podSpec := map[string]interface{}{
		"containers": []interface{}{
			map[string]interface{}{
				"name":  "agent",
				"image": "myagent:latest",
				"securityContext": map[string]interface{}{
					"privileged": true,
				},
			},
		},
	}
	review := doAdmissionRequest(t, ts, makeAdmissionReview("default", "CREATE", podSpec))
	require.NotNil(t, review.Response)
	// Privileged container is a warn (not deny) rule — pod should still be allowed
	assert.True(t, review.Response.Allowed, "privileged container is a warning, not a denial")
	assert.NotEmpty(t, review.Response.Warnings)
}

func TestAdmissionWebhook_HealthEndpoint(t *testing.T) {
	cfg := admission.Config{
		Mode:        "warn",
		WebhookPath: "/admission",
		RegoDir:     "../rules/rego",
	}
	srv, err := admission.NewServer(cfg, nil)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.HandleHealth)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAdmissionWebhook_NonPodResource_AllowThrough(t *testing.T) {
	ts := newTestWebhookServer(t, "enforce")
	// Send a Deployment resource — webhook should allow through without evaluation
	review := map[string]interface{}{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]interface{}{
			"uid":       "test-uid-5678",
			"namespace": "default",
			"operation": "CREATE",
			"kind": map[string]interface{}{
				"group": "apps", "version": "v1", "kind": "Deployment",
			},
			"resource": map[string]interface{}{
				"group": "apps", "version": "v1", "resource": "deployments",
			},
			"object": map[string]interface{}{},
		},
	}
	body, _ := json.Marshal(review)
	result := doAdmissionRequest(t, ts, body)
	require.NotNil(t, result.Response)
	assert.True(t, result.Response.Allowed)
}

// Compile-time check: Server must expose the handler methods used by tests.
var _ = context.Background
