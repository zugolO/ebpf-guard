// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("github.com/zugolO/ebpf-guard/internal/exporter")

// MTLSConfig holds mTLS configuration for Alertmanager.
type MTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CAFile   string
}

// AlertmanagerClient sends alerts to Alertmanager webhook endpoint.
type AlertmanagerClient struct {
	webhookURL   string
	generatorURL string
	batchSize    int
	batchTimeout time.Duration

	mu     sync.Mutex
	batch  []types.AlertPayload
	timer  *time.Timer
	client *http.Client

	failures    int
	threshold   int
	lastFailure time.Time
	cooldown    time.Duration
	open        bool

	closed bool
	wg     sync.WaitGroup
}

// NewAlertmanagerClient creates a new Alertmanager webhook client.
func NewAlertmanagerClient(webhookURL, generatorURL string, batchSize, batchTimeout, circuitBreakerThreshold int) *AlertmanagerClient {
	return NewAlertmanagerClientWithMTLS(webhookURL, generatorURL, batchSize, batchTimeout, circuitBreakerThreshold, nil)
}

// NewAlertmanagerClientWithMTLS creates a new Alertmanager webhook client with optional mTLS.
func NewAlertmanagerClientWithMTLS(webhookURL, generatorURL string, batchSize, batchTimeout, circuitBreakerThreshold int, mtls *MTLSConfig) *AlertmanagerClient {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	if mtls != nil && mtls.Enabled {
		tlsConfig, err := createMTLSConfig(mtls)
		if err != nil {
			slog.Warn("exporter/alertmanager: failed to configure mTLS, using default transport",
				slog.Any("error", err))
		} else {
			client.Transport = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
			slog.Info("exporter/alertmanager: mTLS configured successfully")
		}
	}

	return &AlertmanagerClient{
		webhookURL:   webhookURL,
		generatorURL: generatorURL,
		batchSize:    batchSize,
		batchTimeout: time.Duration(batchTimeout) * time.Second,
		batch:        make([]types.AlertPayload, 0, batchSize),
		client:       client,
		threshold:    circuitBreakerThreshold,
		cooldown:     30 * time.Second,
	}
}

// createMTLSConfig creates TLS configuration for mTLS.
func createMTLSConfig(mtls *MTLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(mtls.CertFile, mtls.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("exporter/alertmanager: load client cert: %w", err)
	}

	caCert, err := os.ReadFile(mtls.CAFile)
	if err != nil {
		return nil, fmt.Errorf("exporter/alertmanager: read CA bundle: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("exporter/alertmanager: failed to parse CA bundle")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// SendAlert queues an alert for batch sending.
func (c *AlertmanagerClient) SendAlert(ctx context.Context, alert types.Alert) {
	ctx, span := tracer.Start(ctx, "AlertmanagerClient.SendAlert",
		trace.WithAttributes(
			attribute.String("alert.rule_id", alert.RuleID),
			attribute.String("alert.severity", string(alert.Severity)),
		),
	)
	defer span.End()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		span.SetAttributes(attribute.Bool("alert.rejected", true))
		span.SetAttributes(attribute.String("alert.reject_reason", "client_closed"))
		return
	}

	payload := c.alertToPayload(alert)
	c.batch = append(c.batch, payload)

	span.SetAttributes(attribute.Int("batch.size", len(c.batch)))

	if len(c.batch) >= c.batchSize {
		c.flushUnlocked()
		return
	}

	if c.timer == nil {
		c.timer = time.AfterFunc(c.batchTimeout, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.closed {
				return
			}
			// Race B fix: nil timer before flush to prevent spurious callback
			// If timer.Stop() returns false (goroutine already started), the callback
			// holds c.mu.Lock. Since flushUnlocked is guarded by c.mu, this is safe,
			// but setting timer=nil prevents the callback from calling flushUnlocked
			// after the batch was already sent by a concurrent Flush() call.
			c.timer = nil
			c.flushUnlocked()
		})
	}
}

// Flush sends any pending alerts immediately.
func (c *AlertmanagerClient) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushUnlocked()
}

func (c *AlertmanagerClient) flushUnlocked() {
	if len(c.batch) == 0 {
		return
	}

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	if c.open {
		if time.Since(c.lastFailure) > c.cooldown {
			c.open = false
			c.failures = 0
			slog.Info("exporter/alertmanager: circuit breaker closed")
		} else {
			slog.Warn("exporter/alertmanager: circuit breaker open, dropping alerts",
				slog.Int("dropped", len(c.batch)))
			c.batch = c.batch[:0]
			return
		}
	}

	batch := make([]types.AlertPayload, len(c.batch))
	copy(batch, c.batch)
	c.batch = c.batch[:0]

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.sendBatch(batch)
	}()
}

func (c *AlertmanagerClient) sendBatch(alerts []types.AlertPayload) {
	if len(alerts) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, span := tracer.Start(ctx, "AlertmanagerClient.sendBatch",
		trace.WithAttributes(
			attribute.Int("batch.count", len(alerts)),
		),
	)
	defer span.End()

	body, err := json.Marshal(alerts)
	if err != nil {
		slog.Error("exporter/alertmanager: failed to marshal alerts", slog.Any("error", err))
		span.RecordError(err)
		c.recordFailure()
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("exporter/alertmanager: failed to create request", slog.Any("error", err))
		span.RecordError(err)
		c.recordFailure()
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Error("exporter/alertmanager: failed to send alerts", slog.Any("error", err))
		span.RecordError(err)
		c.recordFailure()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Info("exporter/alertmanager: alerts sent successfully",
			slog.Int("count", len(alerts)),
			slog.Int("status", resp.StatusCode))
		span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
		c.recordSuccess()
	} else {
		slog.Error("exporter/alertmanager: alertmanager returned error",
			slog.Int("status", resp.StatusCode),
			slog.Int("count", len(alerts)))
		span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
		c.recordFailure()
	}
}

func (c *AlertmanagerClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures++
	c.lastFailure = time.Now()

	if c.failures >= c.threshold && !c.open {
		c.open = true
		slog.Warn("exporter/alertmanager: circuit breaker opened",
			slog.Int("failures", c.failures),
			slog.Duration("cooldown", c.cooldown))
	}
}

func (c *AlertmanagerClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.failures > 0 {
		c.failures = 0
	}
}

func (c *AlertmanagerClient) alertToPayload(alert types.Alert) types.AlertPayload {
	payload := types.AlertPayload{
		Labels: types.AlertLabels{
			Alertname: "EbpfGuardAlert",
			RuleID:    alert.RuleID,
			Severity:  string(alert.Severity),
		},
		Annotations: types.AlertAnnotations{
			Summary:     alert.RuleName,
			Description: alert.Message,
		},
		GeneratorURL: c.generatorURL,
	}

	if alert.Enrichment.PodName != "" || alert.Enrichment.Namespace != "" {
		payload.Labels.Pod = alert.Enrichment.PodName
		payload.Labels.Namespace = alert.Enrichment.Namespace
		payload.Labels.ContainerID = alert.Enrichment.ContainerID
		if len(alert.Enrichment.Labels) > 0 {
			payload.Labels.PodLabels = alert.Enrichment.Labels
		}
	}

	if alert.TraceID != "" {
		payload.Annotations.Description = alert.Message + " [trace_id: " + alert.TraceID + "]"
	}

	return payload
}

// Close flushes pending alerts and closes the client.
// Blocks until all in-flight sendBatch goroutines complete.
func (c *AlertmanagerClient) Close() error {
	c.mu.Lock()
	c.closed = true

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()

	c.Flush()
	c.wg.Wait()
	return nil
}
