package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNew(t *testing.T) {
	c := New("http://node-a:9090/", "tok")
	if c.BaseURL() != "http://node-a:9090" {
		t.Errorf("BaseURL() = %q, want trailing slash trimmed", c.BaseURL())
	}
	if c.token != "tok" {
		t.Errorf("token = %q, want %q", c.token, "tok")
	}
	if c.http == nil || c.http.Timeout != 10*time.Second {
		t.Errorf("expected default http.Client with 10s timeout, got %+v", c.http)
	}
}

func TestNewWithClient(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}
	c := NewWithClient("http://node-b:8080/", "tok2", custom)
	if c.http != custom {
		t.Errorf("expected custom http.Client to be used")
	}
	if c.BaseURL() != "http://node-b:8080" {
		t.Errorf("BaseURL() = %q, want trailing slash trimmed", c.BaseURL())
	}

	cNil := NewWithClient("http://node-c:8080", "tok3", nil)
	if cNil.http == nil || cNil.http.Timeout != 10*time.Second {
		t.Errorf("nil hc should fall back to default client, got %+v", cNil.http)
	}
}

func TestBaseURL(t *testing.T) {
	c := New("http://example.com///", "")
	// TrimRight only strips trailing '/' characters, so all get trimmed.
	if c.BaseURL() != "http://example.com" {
		t.Errorf("BaseURL() = %q, want %q", c.BaseURL(), "http://example.com")
	}
}

func newTestAlerts() []types.Alert {
	return []types.Alert{
		{ID: "a1", RuleID: "rule_001", Message: "first"},
		{ID: "a2", RuleID: "rule_002", Message: "second"},
	}
}

func TestFetchAlerts_HappyPath(t *testing.T) {
	wantAlerts := newTestAlerts()
	var gotPath, gotMethod string
	var gotQuery url.Values
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotQuery = r.URL.Query()
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(wantAlerts)
	}))
	defer srv.Close()

	c := New(srv.URL, "secret-token")
	alerts, err := c.FetchAlerts(context.Background(), AlertQuery{
		Since:  5 * time.Minute,
		Limit:  10,
		Offset: 20,
	})
	if err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}
	if len(alerts) != len(wantAlerts) {
		t.Fatalf("got %d alerts, want %d", len(alerts), len(wantAlerts))
	}
	for i := range wantAlerts {
		if alerts[i].ID != wantAlerts[i].ID || alerts[i].RuleID != wantAlerts[i].RuleID || alerts[i].Message != wantAlerts[i].Message {
			t.Errorf("alert[%d] = %+v, want %+v", i, alerts[i], wantAlerts[i])
		}
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/api/v1/alerts" {
		t.Errorf("path = %q, want /api/v1/alerts", gotPath)
	}
	if got := gotQuery.Get("since"); got != (5 * time.Minute).String() {
		t.Errorf("since = %q, want %q", got, (5 * time.Minute).String())
	}
	if got := gotQuery.Get("limit"); got != "10" {
		t.Errorf("limit = %q, want %q", got, "10")
	}
	if got := gotQuery.Get("offset"); got != "20" {
		t.Errorf("offset = %q, want %q", got, "20")
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer secret-token")
	}
}

func TestFetchAlerts_ZeroValuedQueryOmitted(t *testing.T) {
	var gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]types.Alert{})
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.FetchAlerts(context.Background(), AlertQuery{}); err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}
	if gotRawQuery != "" {
		t.Errorf("raw query = %q, want empty (zero-valued fields omitted)", gotRawQuery)
	}
}

func TestFetchAlerts_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	var authHeaderPresent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, authHeaderPresent = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]types.Alert{})
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.FetchAlerts(context.Background(), AlertQuery{}); err != nil {
		t.Fatalf("FetchAlerts() error = %v", err)
	}
	if authHeaderPresent {
		t.Error("expected no Authorization header when token is empty")
	}
}

func TestFetchAlerts_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.FetchAlerts(context.Background(), AlertQuery{})
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to mention status 500", err.Error())
	}
}

func TestFetchAlerts_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	_, err := c.FetchAlerts(context.Background(), AlertQuery{})
	if err == nil {
		t.Fatal("expected decode error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "decode alerts") {
		t.Errorf("error = %q, want it to mention 'decode alerts'", err.Error())
	}
}

func TestFetchAlerts_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := srv.URL
	srv.Close() // closed server: connection to this address should fail

	c := New(addr, "")
	_, err := c.FetchAlerts(context.Background(), AlertQuery{})
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestFetchAlerts_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]types.Alert{})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := New(srv.URL, "")
	_, err := c.FetchAlerts(ctx, AlertQuery{})
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}

func TestFetchAlerts_ContextTimeout(t *testing.T) {
	blockCh := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blockCh
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(blockCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	c := New(srv.URL, "")
	_, err := c.FetchAlerts(ctx, AlertQuery{})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}
