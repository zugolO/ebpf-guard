// Package collector provides eBPF-based and cloud event collection.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

const (
	azureLoginURL    = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	azureActivityURL = "https://management.azure.com/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values"
)

// AzureMonitorCollector polls the Azure Activity Log via the Azure Monitor REST API
// and converts management events to types.Event with EventCloudAudit type.
//
// Authentication uses Azure AD OAuth2 client-credentials grant with a service principal
// (client_id + client_secret) or Workload Identity via environment variables.
type AzureMonitorCollector struct {
	logger       *slog.Logger
	cfg          config.AzureMonitorCollectorConfig
	client       *http.Client
	dropLogger   *dropLogger
	strategy     BackpressureStrategy
	pollInterval time.Duration
	tokenCache   *azureTokenCache
	stopped      chan struct{}
}

// NewAzureMonitorCollector creates a new Azure Activity Log collector.
func NewAzureMonitorCollector(logger *slog.Logger, cfg config.AzureMonitorCollectorConfig, strategy BackpressureStrategy) *AzureMonitorCollector {
	d, err := time.ParseDuration(cfg.PollInterval)
	if err != nil || d <= 0 {
		d = 60 * time.Second
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > 1000 {
		cfg.MaxEvents = 100
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	return &AzureMonitorCollector{
		logger:       logger.With("component", "azure_monitor_collector"),
		cfg:          cfg,
		client:       httpClient,
		dropLogger:   newDropLogger(5 * time.Second),
		strategy:     strategy,
		pollInterval: d,
		tokenCache:   newAzureTokenCache(httpClient, cfg),
		stopped:      make(chan struct{}),
	}
}

// Name returns the collector name.
func (a *AzureMonitorCollector) Name() string { return "azure_monitor" }

// Close waits for the collector to stop.
func (a *AzureMonitorCollector) Close() error {
	<-a.stopped
	return nil
}

// Start polls the Azure Activity Log API. Blocks until ctx is cancelled.
func (a *AzureMonitorCollector) Start(ctx context.Context, out chan<- types.Event) error {
	defer close(a.stopped)
	a.logger.Info("starting Azure Monitor collector",
		slog.String("subscription", a.cfg.SubscriptionID),
	)

	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()

	// Fetch on startup immediately.
	a.poll(ctx, out)

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("stopping Azure Monitor collector")
			return nil
		case <-ticker.C:
			a.poll(ctx, out)
		}
	}
}

// poll fetches Activity Log events from Azure Monitor and emits them.
func (a *AzureMonitorCollector) poll(ctx context.Context, out chan<- types.Event) {
	token, err := a.tokenCache.get(ctx)
	if err != nil {
		a.logger.Warn("azure_monitor: resolve token error", slog.Any("error", err))
		return
	}

	events, err := a.fetchActivityLog(ctx, token)
	if err != nil {
		a.logger.Warn("azure_monitor: fetch error", slog.Any("error", err))
		return
	}

	for _, e := range events {
		sendEvent(ctx, out, e, a.strategy, func() {
			a.dropLogger.record(a.logger, a.Name())
		})
	}
}

// fetchActivityLog retrieves Activity Log events from the Azure Management API.
func (a *AzureMonitorCollector) fetchActivityLog(ctx context.Context, token string) ([]types.Event, error) {
	endpoint := fmt.Sprintf(azureActivityURL, a.cfg.SubscriptionID)

	params := url.Values{}
	params.Set("api-version", "2015-04-01")
	params.Set("$top", fmt.Sprintf("%d", a.cfg.MaxEvents))
	// Select only the last hour to avoid re-fetching old data.
	filterTime := time.Now().UTC().Add(-1 * time.Hour).Format("2006-01-02T15:04:05Z")
	params.Set("$filter", fmt.Sprintf("eventTimestamp ge '%s'", filterTime))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("activity log request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("activity log status %d: %s", resp.StatusCode, body)
	}

	return parseAzureActivityLog(resp.Body)
}

// ── Azure Activity Log parsing ─────────────────────────────────────────────────

// azureActivityResponse is the top-level response from the Activity Log API.
type azureActivityResponse struct {
	Value []azureActivityEntry `json:"value"`
}

// azureActivityEntry mirrors the relevant fields of an Azure Activity Log event.
type azureActivityEntry struct {
	ID                string `json:"id"`
	OperationName     string `json:"operationName"`
	ResourceID        string `json:"resourceId"`
	ResourceGroupName string `json:"resourceGroupName"`
	ResourceProvider  struct {
		Value string `json:"localizedValue"`
		Name  string `json:"value"`
	} `json:"resourceProviderName"`
	EventTimestamp string `json:"eventTimestamp"`
	CorrelationID  string `json:"correlationId"`
	Level          string `json:"level"`
	Caller         string `json:"caller"`
	// Claims carries the caller identity claims (user/service principal).
	Claims map[string]string `json:"claims"`
	// Properties carries operation-specific data (status, sub-status, etc.).
	Properties struct {
		StatusCode   string `json:"statusCode"`
		StatusMessage string `json:"statusMessage"`
		EventCategory string `json:"eventCategory"`
	} `json:"properties"`
	// HTTPRequest carries the HTTP request details from the original API call.
	HTTPRequest struct {
		ClientRequestID string `json:"clientRequestId"`
		ClientIPAddress string `json:"clientIpAddress"`
		Method          string `json:"method"`
		URI             string `json:"uri"`
	} `json:"httpRequest"`
}

func parseAzureActivityLog(body io.Reader) ([]types.Event, error) {
	var resp azureActivityResponse
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("parse activity log: %w", err)
	}

	events := make([]types.Event, 0, len(resp.Value))
	now := uint64(time.Now().UnixNano())

	for _, entry := range resp.Value {
		principal := entry.Caller
		if principal == "" {
			if claims, ok := entry.Claims["upn"]; ok {
				principal = claims
			} else if claims, ok := entry.Claims["appid"]; ok {
				principal = claims
			}
		}

		// Derive the service name from the resource provider.
		service := strings.ToLower(entry.ResourceProvider.Name)
		if service == "" && entry.ResourceProvider.Value != "" {
			service = strings.ToLower(entry.ResourceProvider.Value)
		}

		sourceIP := entry.HTTPRequest.ClientIPAddress

		errorCode := ""
		if entry.Level == "Error" || entry.Level == "Critical" {
			if entry.Properties.StatusMessage != "" {
				errorCode = entry.Properties.StatusMessage
			} else if entry.Properties.StatusCode != "" {
				errorCode = entry.Properties.StatusCode
			}
		}

		// Extract region from the resource location (embedded in resource ID).
		region := extractAzureRegion(entry.ResourceID)

		e := types.Event{
			Type:      types.EventCloudAudit,
			Timestamp: now,
			CloudAudit: &types.CloudAuditEvent{
				Provider:    "azure",
				Service:     service,
				Action:      entry.OperationName,
				Principal:   principal,
				ResourceARN: entry.ResourceID,
				SourceIP:    sourceIP,
				UserAgent:   "",
				ErrorCode:   errorCode,
				Region:      region,
				EventID:     entry.CorrelationID,
			},
		}
		if e.CloudAudit.EventID == "" {
			e.CloudAudit.EventID = entry.ID
		}
		events = append(events, e)
	}
	return events, nil
}

// extractAzureRegion extracts the Azure region from a resource ID.
// Resource IDs have the form: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/...
// The region is embedded in the resource location property, not the ID itself.
// We return the subscription segment as a crude location hint; real deployments
// should pair this collector with the ARM resource metadata API for precise location.
func extractAzureRegion(resourceID string) string {
	if resourceID == "" {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(resourceID, "/"), "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1] // resource group name as region hint
		}
	}
	return ""
}

// ── Azure OAuth2 token cache ──────────────────────────────────────────────────

type azureTokenCache struct {
	mu     sync.Mutex
	token  string
	expiry time.Time
	client *http.Client
	cfg    config.AzureMonitorCollectorConfig
}

func newAzureTokenCache(client *http.Client, cfg config.AzureMonitorCollectorConfig) *azureTokenCache {
	return &azureTokenCache{client: client, cfg: cfg}
}

func (c *azureTokenCache) get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.expiry.Add(-5*time.Minute)) && c.token != "" {
		return c.token, nil
	}
	token, expiry, err := c.resolve(ctx)
	if err != nil {
		return "", err
	}
	c.token = token
	c.expiry = expiry
	return token, nil
}

// resolve obtains an OAuth2 access token for Azure AD.
// Resolution order:
//  1. Explicit client_id + client_secret + tenant_id from config.
//  2. AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID environment variables.
//  3. Azure AD Workload Identity (federated credential via token file).
func (c *azureTokenCache) resolve(ctx context.Context) (string, time.Time, error) {
	clientID := c.cfg.ClientID
	clientSecret := c.cfg.ClientSecret
	tenantID := c.cfg.TenantID

	if clientID == "" {
		clientID = os.Getenv("AZURE_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	}
	if tenantID == "" {
		tenantID = os.Getenv("AZURE_TENANT_ID")
	}

	if clientID != "" && clientSecret != "" && tenantID != "" {
		return azureTokenFromClientCredentials(ctx, c.client, tenantID, clientID, clientSecret)
	}

	// Try Workload Identity (Azure AD workload identity federation).
	if clientID != "" && tenantID != "" {
		tokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
		if tokenFile != "" {
			return azureTokenFromFederatedIdentity(ctx, c.client, tenantID, clientID, tokenFile)
		}
	}

	// Try Azure Instance Metadata Service (IMDS) for managed identity.
	if clientID != "" {
		return azureTokenFromIMDS(ctx, c.client, clientID)
	}

	return "", time.Time{}, fmt.Errorf("azure_monitor: no credentials configured — set client_id, client_secret, tenant_id or use managed identity")
}

// azureTokenFromClientCredentials exchanges client_id + client_secret for an access token.
func azureTokenFromClientCredentials(ctx context.Context, client *http.Client, tenantID, clientID, clientSecret string) (string, time.Time, error) {
	endpoint := fmt.Sprintf(azureLoginURL, tenantID)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "https://management.azure.com/.default")

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("azure oauth2: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("azure oauth2 status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode azure token: %w", err)
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}

// azureTokenFromFederatedIdentity exchanges a federated token for an access token.
func azureTokenFromFederatedIdentity(ctx context.Context, client *http.Client, tenantID, clientID, tokenFile string) (string, time.Time, error) {
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read federated token file: %w", err)
	}
	assertion := strings.TrimSpace(string(tokenBytes))

	endpoint := fmt.Sprintf(azureLoginURL, tenantID)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)
	data.Set("client_id", clientID)
	data.Set("scope", "https://management.azure.com/.default")

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("azure federated oauth2: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("azure federated oauth2 status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode azure federated token: %w", err)
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}

// azureTokenFromIMDS fetches a token from the Azure Instance Metadata Service (managed identity).
func azureTokenFromIMDS(ctx context.Context, client *http.Client, clientID string) (string, time.Time, error) {
	endpoint := fmt.Sprintf("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=%s&resource=https://management.azure.com", clientID)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("azure imds: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("azure imds status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   string `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode azure imds token: %w", err)
	}

	expiry := time.Now().Add(1 * time.Hour) // IMDS returns string expires_in
	if result.ExpiresIn != "" {
		if d, err := time.ParseDuration(result.ExpiresIn + "s"); err == nil {
			expiry = time.Now().Add(d)
		}
	}
	return result.AccessToken, expiry, nil
}
