package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ── parseGCPAuditLogEntry ─────────────────────────────────────────────────────

func gcpAuditLogEntryJSON(t *testing.T, insertID, service, method, principal, ip, region string) []byte {
	t.Helper()
	entry := map[string]interface{}{
		"logName":  "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
		"insertId": insertID,
		"resource": map[string]interface{}{
			"type":   "gce_instance",
			"labels": map[string]string{"location": region},
		},
		"timestamp": "2024-01-15T10:00:00Z",
		"protoPayload": map[string]interface{}{
			"@type":       "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName": service,
			"methodName":  method,
			"resourceName": "projects/my-project/instances/my-instance",
			"authenticationInfo": map[string]string{
				"principalEmail": principal,
			},
			"requestMetadata": map[string]string{
				"callerIp":               ip,
				"callerSuppliedUserAgent": "google-cloud-sdk/410.0.0",
			},
		},
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)
	return data
}

func TestParseGCPAuditLogEntry_Valid(t *testing.T) {
	data := gcpAuditLogEntryJSON(t,
		"insert-001",
		"compute.googleapis.com",
		"v1.compute.instances.list",
		"alice@example.com",
		"203.0.113.42",
		"us-central1",
	)

	e, err := parseGCPAuditLogEntry(data)
	require.NoError(t, err)

	assert.Equal(t, types.EventCloudAudit, e.Type)
	require.NotNil(t, e.CloudAudit)
	assert.Equal(t, "gcp", e.CloudAudit.Provider)
	assert.Equal(t, "compute.googleapis.com", e.CloudAudit.Service)
	assert.Equal(t, "v1.compute.instances.list", e.CloudAudit.Action)
	assert.Equal(t, "alice@example.com", e.CloudAudit.Principal)
	assert.Equal(t, "203.0.113.42", e.CloudAudit.SourceIP)
	assert.Equal(t, "us-central1", e.CloudAudit.Region)
	assert.Equal(t, "insert-001", e.CloudAudit.EventID)
	assert.NotZero(t, e.Timestamp)
}

func TestParseGCPAuditLogEntry_NoProtoPayload(t *testing.T) {
	data := []byte(`{"logName":"projects/x/logs/activity","insertId":"no-proto"}`)
	_, err := parseGCPAuditLogEntry(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "protoPayload")
}

func TestParseGCPAuditLogEntry_InvalidJSON(t *testing.T) {
	_, err := parseGCPAuditLogEntry([]byte(`{invalid`))
	require.Error(t, err)
}

func TestParseGCPAuditLogEntry_WithErrorStatus(t *testing.T) {
	entry := map[string]interface{}{
		"insertId": "err-entry",
		"resource": map[string]interface{}{
			"type":   "project",
			"labels": map[string]string{},
		},
		"protoPayload": map[string]interface{}{
			"@type":       "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName": "iam.googleapis.com",
			"methodName":  "google.iam.admin.v1.CreateServiceAccountKey",
			"authenticationInfo": map[string]string{"principalEmail": "attacker@evil.com"},
			"requestMetadata":    map[string]string{"callerIp": "1.2.3.4"},
			"status": map[string]interface{}{
				"code":    7,
				"message": "PERMISSION_DENIED",
			},
		},
	}
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	e, err := parseGCPAuditLogEntry(data)
	require.NoError(t, err)
	assert.Equal(t, "PERMISSION_DENIED", e.CloudAudit.ErrorCode)
}

func TestParseGCPAuditLogEntry_WithErrorStatusCodeOnly(t *testing.T) {
	entry := map[string]interface{}{
		"insertId": "code-only",
		"resource": map[string]interface{}{"type": "project", "labels": map[string]string{}},
		"protoPayload": map[string]interface{}{
			"@type":              "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName":        "iam.googleapis.com",
			"methodName":         "Create",
			"authenticationInfo": map[string]string{"principalEmail": "user@example.com"},
			"requestMetadata":    map[string]string{"callerIp": "1.2.3.4"},
			"status":             map[string]interface{}{"code": 13, "message": ""},
		},
	}
	data, _ := json.Marshal(entry)
	e, err := parseGCPAuditLogEntry(data)
	require.NoError(t, err)
	// When message is empty, fall back to "CODE_13"
	assert.Equal(t, "CODE_13", e.CloudAudit.ErrorCode)
}

func TestParseGCPAuditLogEntry_RegionFromZone(t *testing.T) {
	entry := map[string]interface{}{
		"insertId": "zone-entry",
		"resource": map[string]interface{}{
			"type":   "gce_instance",
			"labels": map[string]string{"zone": "us-central1-a"},
		},
		"protoPayload": map[string]interface{}{
			"@type":              "type.googleapis.com/google.cloud.audit.AuditLog",
			"serviceName":        "compute.googleapis.com",
			"methodName":         "v1.compute.instances.get",
			"authenticationInfo": map[string]string{"principalEmail": "user@example.com"},
			"requestMetadata":    map[string]string{"callerIp": "1.2.3.4"},
		},
	}
	data, _ := json.Marshal(entry)
	e, err := parseGCPAuditLogEntry(data)
	require.NoError(t, err)
	assert.Equal(t, "us-central1-a", e.CloudAudit.Region)
}

// ── NewGCPAuditCollector ──────────────────────────────────────────────────────

func TestNewGCPAuditCollector_Defaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/my-project/subscriptions/audit-sub",
		MaxMessages:        50,
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	require.NotNil(t, c)
	assert.Equal(t, "gcp_audit", c.Name())
}

func TestNewGCPAuditCollector_DefaultMaxMessages(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/my-project/subscriptions/audit-sub",
		MaxMessages:        0, // should default to 100
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	assert.Equal(t, 100, c.cfg.MaxMessages)
}

func TestNewGCPAuditCollector_InvalidPollInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/my-project/subscriptions/audit-sub",
		PollInterval:       "not-valid",
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	// Should use default 10s
	assert.Equal(t, 10*time.Second, c.pollInterval)
}

// redirectRoundTripper redirects all HTTP requests to a fixed target server,
// preserving the original request path and body. Used in tests to intercept
// calls to external APIs (Pub/Sub, metadata server) without DNS/TLS setup.
type redirectRoundTripper struct {
	target *httptest.Server
}

func (r *redirectRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL, _ := url.Parse(r.target.URL)
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = newURL.Scheme
	req2.URL.Host = newURL.Host
	req2.Host = newURL.Host
	return http.DefaultTransport.RoundTrip(req2)
}

// newRedirectClient returns an *http.Client that routes all traffic to target.
func newRedirectClient(target *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &redirectRoundTripper{target: target},
	}
}

// ── Pub/Sub mock tests ────────────────────────────────────────────────────────

// TestGCPAuditCollector_PubSubPull verifies that pubsubPull correctly parses
// a Pub/Sub pull response from a mock server.
func TestGCPAuditCollector_PubSubPull(t *testing.T) {
	// Build a GCP audit log entry and base64-encode it
	logEntry := gcpAuditLogEntryJSON(t,
		"pull-test-1",
		"iam.googleapis.com",
		"google.iam.admin.v1.CreateServiceAccountKey",
		"admin@example.com",
		"10.0.0.1",
		"us-central1",
	)
	encoded := base64.StdEncoding.EncodeToString(logEntry)

	// Build Pub/Sub pull response
	pullResp := map[string]interface{}{
		"receivedMessages": []map[string]interface{}{
			{
				"ackId": "ack-001",
				"message": map[string]interface{}{
					"data":        encoded,
					"messageId":   "msg-001",
					"publishTime": "2024-01-15T10:00:00Z",
				},
			},
		},
	}
	pullRespJSON, _ := json.Marshal(pullResp)

	pubsubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(pullRespJSON)
	}))
	defer pubsubServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/test/subscriptions/sub",
		MaxMessages:        10,
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	// Use the redirect client so all HTTP traffic goes to pubsubServer
	c.client = newRedirectClient(pubsubServer)

	ctx := context.Background()
	messages, ackIDs, err := c.pubsubPull(ctx, "test-token")
	require.NoError(t, err)
	require.Len(t, messages, 1)
	require.Len(t, ackIDs, 1)
	assert.Equal(t, "ack-001", ackIDs[0])

	// Verify the decoded message is valid JSON
	var entry map[string]interface{}
	err = json.Unmarshal(messages[0], &entry)
	require.NoError(t, err)
	assert.Equal(t, "pull-test-1", entry["insertId"])
}

// TestGCPAuditCollector_PubSubPull_Non200 verifies error handling on HTTP errors.
func TestGCPAuditCollector_PubSubPull_Non200(t *testing.T) {
	pubsubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Unauthorized")
	}))
	defer pubsubServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/test/subscriptions/sub",
		MaxMessages:        10,
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	c.client = newRedirectClient(pubsubServer)

	_, _, err := c.pubsubPull(context.Background(), "test-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

// TestGCPAuditCollector_PubSubPull_Empty verifies correct handling of empty pull response.
func TestGCPAuditCollector_PubSubPull_Empty(t *testing.T) {
	pubsubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"receivedMessages":[]}`)
	}))
	defer pubsubServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/test/subscriptions/sub",
		MaxMessages:        10,
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	c.client = newRedirectClient(pubsubServer)

	msgs, ackIDs, err := c.pubsubPull(context.Background(), "token")
	require.NoError(t, err)
	assert.Empty(t, msgs)
	assert.Empty(t, ackIDs)
}

// TestGCPAuditCollector_PubSubAck verifies that pubsubAck sends the correct payload.
func TestGCPAuditCollector_PubSubAck(t *testing.T) {
	var receivedBody []byte
	ackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ackServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/test/subscriptions/sub",
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	c.client = newRedirectClient(ackServer)

	err := c.pubsubAck(context.Background(), "test-token", []string{"ack-001", "ack-002"})
	require.NoError(t, err)

	var req pubsubAckRequest
	err = json.Unmarshal(receivedBody, &req)
	require.NoError(t, err)
	assert.Equal(t, []string{"ack-001", "ack-002"}, req.AckIDs)
}

// TestGCPAuditCollector_PubSubAck_Empty verifies that empty ackIDs list is a no-op.
func TestGCPAuditCollector_PubSubAck_Empty(t *testing.T) {
	callCount := 0
	ackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ackServer.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/test/subscriptions/sub",
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)
	c.client = newRedirectClient(ackServer)

	err := c.pubsubAck(context.Background(), "token", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, callCount, "empty ackIDs should not make any HTTP request")
}

// TestGCPAuditCollector_StartStop verifies the lifecycle: the collector starts,
// the context is cancelled, and it shuts down without hanging.
func TestGCPAuditCollector_StartStop(t *testing.T) {
	pubsubServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"receivedMessages":[]}`)
	}))
	defer pubsubServer.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.GCPAuditCollectorConfig{
		PubSubSubscription: "projects/test/subscriptions/sub",
		PollInterval:       "50ms",
		MaxMessages:        10,
	}
	c := NewGCPAuditCollector(logger, cfg, StrategyDrop)

	// Inject a pre-cached token into the token cache to avoid real GCP auth
	c.tokenCache.mu.Lock()
	c.tokenCache.token = "mock-token"
	c.tokenCache.expiry = time.Now().Add(time.Hour)
	c.tokenCache.mu.Unlock()
	c.client = newRedirectClient(pubsubServer)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 64)
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Start(ctx, out)
	}()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("GCPAuditCollector.Start did not return after ctx cancel")
	}
}
