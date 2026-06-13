// Package collector provides tests for the Azure Monitor collector.
package collector

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestNewAzureMonitorCollector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.AzureMonitorCollectorConfig{
		Enabled:        true,
		SubscriptionID: "test-sub-id",
		TenantID:       "test-tenant-id",
		ClientID:       "test-client-id",
		ClientSecret:   "test-secret",
	}

	c := NewAzureMonitorCollector(logger, cfg, StrategyDrop)
	require.NotNil(t, c)
	assert.Equal(t, "azure_monitor", c.Name())

	// Start the collector briefly so Close() won't deadlock.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = c.Start(ctx, make(chan<- types.Event, 1))
}

func TestAzureMonitorCollector_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.AzureMonitorCollectorConfig{
		Enabled:        true,
		SubscriptionID: "test-sub-id",
	}

	c := NewAzureMonitorCollector(logger, cfg, StrategyDrop)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := c.Start(ctx, make(chan<- types.Event, 1))
	assert.NoError(t, err, "Start should return nil after context cancellation")
}

func TestAzureMonitorCollector_DefaultPollInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.AzureMonitorCollectorConfig{
		Enabled:        true,
		SubscriptionID: "sub",
		TenantID:       "tenant",
		ClientID:       "client",
		ClientSecret:   "secret",
		// PollInterval left empty
	}

	c := NewAzureMonitorCollector(logger, cfg, StrategyDrop)
	assert.Equal(t, 60*time.Second, c.pollInterval)
}

func TestAzureMonitorCollector_CustomPollInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.AzureMonitorCollectorConfig{
		Enabled:        true,
		SubscriptionID: "sub",
		PollInterval:   "30s",
	}

	c := NewAzureMonitorCollector(logger, cfg, StrategyDrop)
	assert.Equal(t, 30*time.Second, c.pollInterval)
}

func TestAzureMonitorCollector_InvalidPollInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.AzureMonitorCollectorConfig{
		Enabled:        true,
		SubscriptionID: "sub",
		PollInterval:   "invalid",
	}

	c := NewAzureMonitorCollector(logger, cfg, StrategyDrop)
	assert.Equal(t, 60*time.Second, c.pollInterval) // defaults to 60s
}

func TestParseAzureActivityLog_Basic(t *testing.T) {
	input := `{
  "value": [
    {
      "id": "/subscriptions/sub-123/resourceGroups/myRG/providers/microsoft.insights/eventtypes/management/values/event-1",
      "operationName": "Microsoft.Compute/virtualMachines/write",
      "resourceId": "/subscriptions/sub-123/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM",
      "resourceGroupName": "myRG",
      "resourceProviderName": {
        "localizedValue": "Microsoft Compute",
        "value": "Microsoft.Compute"
      },
      "eventTimestamp": "2026-01-01T12:00:00Z",
      "correlationId": "corr-abc-123",
      "level": "Informational",
      "caller": "user@contoso.com",
      "claims": {
        "upn": "user@contoso.com"
      },
      "httpRequest": {
        "clientIpAddress": "203.0.113.42",
        "method": "PUT",
        "uri": "https://management.azure.com/subscriptions/sub-123/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM?api-version=2023-01-01"
      }
    }
  ]
}`

	events, err := parseAzureActivityLog(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, events, 1)

	e := events[0]
	assert.Equal(t, types.EventCloudAudit, e.Type)
	require.NotNil(t, e.CloudAudit)
	assert.Equal(t, "azure", e.CloudAudit.Provider)
	assert.Equal(t, "microsoft.compute", e.CloudAudit.Service)
	assert.Equal(t, "Microsoft.Compute/virtualMachines/write", e.CloudAudit.Action)
	assert.Equal(t, "user@contoso.com", e.CloudAudit.Principal)
	assert.Equal(t, "203.0.113.42", e.CloudAudit.SourceIP)
	assert.Equal(t, "corr-abc-123", e.CloudAudit.EventID)
	assert.Empty(t, e.CloudAudit.ErrorCode)
	assert.Equal(t, "myRG", e.CloudAudit.Region) // extracted from resource ID
}

func TestParseAzureActivityLog_ErrorEvent(t *testing.T) {
	input := `{
  "value": [
    {
      "id": "/subscriptions/sub-123/providers/microsoft.insights/eventtypes/management/values/event-2",
      "operationName": "Microsoft.Network/networkSecurityGroups/write",
      "resourceId": "/subscriptions/sub-123/resourceGroups/netRG/providers/Microsoft.Network/networkSecurityGroups/nsg1",
      "resourceProviderName": {
        "localizedValue": "Microsoft Network",
        "value": "Microsoft.Network"
      },
      "eventTimestamp": "2026-01-01T12:00:00Z",
      "correlationId": "corr-def-456",
      "level": "Error",
      "caller": "svc-principal@contoso.com",
      "httpRequest": {
        "clientIpAddress": "10.0.0.1",
        "method": "PUT"
      },
      "properties": {
        "statusCode": "Forbidden",
        "statusMessage": "Network security rule limit exceeded"
      }
    }
  ]
}`

	events, err := parseAzureActivityLog(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, events, 1)

	e := events[0]
	assert.Equal(t, "critical", mapAzureLevel("Error"))
	assert.Contains(t, e.CloudAudit.ErrorCode, "Network security rule limit exceeded")
}

func TestParseAzureActivityLog_EmptyResponse(t *testing.T) {
	input := `{"value": []}`

	events, err := parseAzureActivityLog(strings.NewReader(input))
	require.NoError(t, err)
	assert.Len(t, events, 0)
}

func TestParseAzureActivityLog_ServicePrincipal(t *testing.T) {
	input := `{
  "value": [
    {
      "operationName": "Microsoft.Storage/storageAccounts/listKeys/action",
      "resourceId": "/subscriptions/sub-123/resourceGroups/storageRG/providers/Microsoft.Storage/storageAccounts/mystorage",
      "resourceProviderName": {
        "value": "Microsoft.Storage"
      },
      "eventTimestamp": "2026-01-01T00:00:00Z",
      "correlationId": "corr-sp-789",
      "level": "Warning",
      "caller": "",
      "claims": {
        "appid": "sp-app-id-12345"
      },
      "httpRequest": {
        "clientIpAddress": "198.51.100.7"
      }
    }
  ]
}`

	events, err := parseAzureActivityLog(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "sp-app-id-12345", events[0].CloudAudit.Principal)
}

func TestExtractAzureRegion(t *testing.T) {
	assert.Equal(t, "myRG", extractAzureRegion("/subscriptions/sub/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/vm1"))
	assert.Equal(t, "prod", extractAzureRegion("/subscriptions/sub/resourceGroups/prod/providers/Microsoft.Network/virtualNetworks/vnet1"))
	assert.Equal(t, "", extractAzureRegion(""))
	assert.Equal(t, "", extractAzureRegion("/subscriptions/sub/providers/Microsoft.Network/operations/op1"))
}

func mapAzureLevel(level string) string {
	switch strings.ToLower(level) {
	case "error", "critical":
		return "critical"
	default:
		return "warning"
	}
}
