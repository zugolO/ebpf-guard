//go:build rego

package admission

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer creates an admission Server backed by an empty Rego policy dir
// (allows all). Suitable for testing handler plumbing without real policies.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	// Use a temp dir with no .rego files → allow-all engine
	dir := t.TempDir()
	cfg := Config{
		Mode:        "enforce",
		WebhookPath: "/admission",
		RegoDir:     dir,
	}
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)
	return srv
}

// makeAdmissionRequest builds and serialises an AdmissionReview POST body.
func makeAdmissionRequest(t *testing.T, uid, kind, op, namespace string, obj interface{}) *http.Request {
	t.Helper()

	objJSON, err := json.Marshal(obj)
	require.NoError(t, err)

	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       uid,
			Kind:      GroupVersionKind{Group: "", Version: "v1", Kind: kind},
			Resource:  GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Namespace: namespace,
			Operation: op,
			Object:    objJSON,
		},
	}
	body, err := json.Marshal(review)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/admission", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// ── NewServer ─────────────────────────────────────────────────────────────────

func TestNewServer_EmptyRegoDir(t *testing.T) {
	srv := newTestServer(t)
	assert.NotNil(t, srv)
}

func TestNewServer_NonExistentRegoDir(t *testing.T) {
	cfg := Config{
		RegoDir: "/this/path/does/not/exist",
	}
	srv, err := NewServer(cfg, nil)
	// Non-existent dir is treated as empty → allow all; must not error
	require.NoError(t, err)
	assert.NotNil(t, srv)
}

func TestNewServer_Defaults(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(Config{RegoDir: dir}, nil)
	require.NoError(t, err)
	assert.Equal(t, "/admission", srv.config.WebhookPath)
	assert.Equal(t, "warn", srv.config.Mode)
	assert.Equal(t, ":8443", srv.config.BindAddress)
}

// ── HandleAdmission ───────────────────────────────────────────────────────────

func TestHandleAdmission_WrongMethod(t *testing.T) {
	srv := newTestServer(t)

	req, _ := http.NewRequest("GET", "/admission", nil)
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestHandleAdmission_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)

	req, _ := http.NewRequest("POST", "/admission", bytes.NewReader([]byte(`{invalid}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleAdmission_MissingRequest(t *testing.T) {
	srv := newTestServer(t)

	review := AdmissionReview{APIVersion: "v1", Kind: "AdmissionReview"}
	body, _ := json.Marshal(review)
	req, _ := http.NewRequest("POST", "/admission", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleAdmission_PodCreateAllowed verifies that a Pod CREATE with no policy
// violations is allowed (empty Rego dir → allow all).
func TestHandleAdmission_PodCreateAllowed(t *testing.T) {
	srv := newTestServer(t)

	pod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]interface{}{"name": "nginx", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []map[string]interface{}{
				{"name": "nginx", "image": "nginx:latest"},
			},
		},
	}

	req := makeAdmissionRequest(t, "uid-1234", "Pod", "CREATE", "default", pod)
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp AdmissionReview
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	require.NotNil(t, resp.Response)
	assert.True(t, resp.Response.Allowed, "Pod CREATE should be allowed with empty policy")
	assert.Equal(t, "uid-1234", resp.Response.UID)
}

// TestHandleAdmission_NonPodAllowed verifies that non-Pod resources pass through.
func TestHandleAdmission_NonPodAllowed(t *testing.T) {
	srv := newTestServer(t)

	svc := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]interface{}{"name": "my-svc"},
		"spec":       map[string]interface{}{"type": "ClusterIP"},
	}

	req := makeAdmissionRequest(t, "uid-svc", "Service", "CREATE", "default", svc)
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp AdmissionReview
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Response.Allowed)
}

// TestHandleAdmission_PodUpdateAllowed verifies that Pod UPDATE passes through.
func TestHandleAdmission_PodUpdateAllowed(t *testing.T) {
	srv := newTestServer(t)

	pod := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "nginx", "namespace": "default"},
		"spec": map[string]interface{}{
			"containers": []map[string]interface{}{
				{"name": "nginx", "image": "nginx:1.21"},
			},
		},
	}

	req := makeAdmissionRequest(t, "uid-update", "Pod", "UPDATE", "default", pod)
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp AdmissionReview
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Response.Allowed)
}

// TestHandleAdmission_ResponseContainsContentType verifies the response has JSON content-type.
func TestHandleAdmission_ResponseContentType(t *testing.T) {
	srv := newTestServer(t)

	req := makeAdmissionRequest(t, "uid-ct", "Pod", "CREATE", "default", map[string]interface{}{})
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// TestHandleAdmission_Counters verifies that metrics counters are incremented.
func TestHandleAdmission_Counters(t *testing.T) {
	srv := newTestServer(t)

	pod := map[string]interface{}{"spec": map[string]interface{}{}}
	for i := 0; i < 3; i++ {
		req := makeAdmissionRequest(t, "uid-cnt", "Pod", "CREATE", "default", pod)
		rec := httptest.NewRecorder()
		srv.HandleAdmission(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
	}

	assert.Equal(t, uint64(3), srv.requestsTotal.Load())
	assert.Equal(t, uint64(3), srv.allowedTotal.Load())
	assert.Equal(t, uint64(0), srv.deniedTotal.Load())
}

// ── HandleHealth ──────────────────────────────────────────────────────────────

func TestHandleHealth_Healthy(t *testing.T) {
	srv := newTestServer(t)
	srv.healthy.Store(true)

	req, _ := http.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.HandleHealth(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleHealth_Unhealthy(t *testing.T) {
	srv := newTestServer(t)
	srv.healthy.Store(false)

	req, _ := http.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.HandleHealth(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ── Rego enforce mode ─────────────────────────────────────────────────────────

// TestHandleAdmission_EnforceMode_Deny verifies that enforce mode blocks pods
// that violate a loaded Rego policy.
func TestHandleAdmission_EnforceMode_Deny(t *testing.T) {
	// Write a Rego policy that denies all pods in the "blocked" namespace
	dir := t.TempDir()
	policy := `
package ebpf_guard.admission

deny[msg] {
	input.request.namespace == "blocked"
	msg := "namespace 'blocked' is not allowed"
}
`
	err := os.WriteFile(dir+"/test.rego", []byte(policy), 0o600)
	require.NoError(t, err)

	cfg := Config{
		Mode:        "enforce",
		WebhookPath: "/admission",
		RegoDir:     dir,
	}
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	pod := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "bad-pod", "namespace": "blocked"},
		"spec":     map[string]interface{}{},
	}
	req := makeAdmissionRequest(t, "uid-deny", "Pod", "CREATE", "blocked", pod)
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	require.NotNil(t, resp.Response)
	assert.False(t, resp.Response.Allowed, "Pod in blocked namespace must be denied")
	require.NotNil(t, resp.Response.Result)
	assert.Equal(t, int32(403), resp.Response.Result.Code)
	assert.Contains(t, resp.Response.Result.Message, "blocked")
}

// TestHandleAdmission_WarnMode_AllowWithWarnings verifies that warn mode allows
// the pod but includes the violation as a warning.
func TestHandleAdmission_WarnMode_AllowWithWarnings(t *testing.T) {
	dir := t.TempDir()
	policy := `
package ebpf_guard.admission

deny[msg] {
	input.request.namespace == "risky"
	msg := "risky namespace access"
}
`
	err := os.WriteFile(dir+"/warn.rego", []byte(policy), 0o600)
	require.NoError(t, err)

	cfg := Config{
		Mode:    "warn",
		RegoDir: dir,
	}
	srv, err := NewServer(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)

	pod := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "pod", "namespace": "risky"},
		"spec":     map[string]interface{}{},
	}
	req := makeAdmissionRequest(t, "uid-warn", "Pod", "CREATE", "risky", pod)
	rec := httptest.NewRecorder()
	srv.HandleAdmission(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	require.NotNil(t, resp.Response)
	assert.True(t, resp.Response.Allowed, "warn mode must allow the pod")
	assert.NotEmpty(t, resp.Response.Warnings, "warn mode must return warnings")
}
