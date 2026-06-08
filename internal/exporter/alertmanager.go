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
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("github.com/zugolO/ebpf-guard/internal/exporter")

// validateWebhookURL rejects URLs that could be used for SSRF.
// It enforces http/https scheme and blocks URLs that resolve to loopback,
// link-local, or RFC-1918 private addresses — unless the hostname is an
// explicit private/internal DNS name (resolved lazily at send time).
//
// Note: blocking private IPs is NOT applied here because Alertmanager is
// commonly deployed inside the cluster (e.g. http://alertmanager:9093).
// Instead we only reject clearly dangerous schemes that browsers and HTTP
// clients may follow (file://, gopher://, ftp://, etc.).
func validateWebhookURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("webhook URL must not be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		// Allowed.
	default:
		return fmt.Errorf("webhook URL scheme %q is not allowed; use http or https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook URL must have a host")
	}
	// Reject raw IP literals that are loopback or link-local to prevent
	// trivial SSRF to localhost services. Cluster-internal DNS names (e.g.
	// alertmanager.monitoring.svc) are intentionally allowed.
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("webhook URL must not point to a loopback address")
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("webhook URL must not point to a link-local address")
		}
	}
	return nil
}

// MTLSConfig holds mTLS configuration for Alertmanager.
type MTLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
	CAFile   string
}

// CircuitBreakerConfig holds circuit-breaker and fallback-queue settings for
// the Alertmanager client.
type CircuitBreakerConfig struct {
	// Threshold is the number of consecutive failures before opening the circuit.
	// Zero or negative uses the default of 5.
	Threshold int
	// ResetTimeout is how long to wait in Open state before attempting a probe.
	// Zero uses the default of 30s.
	ResetTimeout time.Duration
	// FallbackBufferSize caps the number of alerts buffered while the circuit is
	// open.  When full, the oldest entry is evicted.  Zero uses the default of 10_000.
	FallbackBufferSize int
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

	cb       *CircuitBreaker
	fallback *FallbackQueue

	closed bool
	wg     sync.WaitGroup
}

// NewAlertmanagerClient creates a new Alertmanager webhook client with default
// circuit-breaker settings (resetTimeout=30s, fallbackBufferSize=10_000).
func NewAlertmanagerClient(webhookURL, generatorURL string, batchSize, batchTimeout, circuitBreakerThreshold int) *AlertmanagerClient {
	return NewAlertmanagerClientWithMTLS(webhookURL, generatorURL, batchSize, batchTimeout, circuitBreakerThreshold, nil)
}

// NewAlertmanagerClientWithMTLS creates a new Alertmanager webhook client with
// optional mTLS and default circuit-breaker settings.
func NewAlertmanagerClientWithMTLS(webhookURL, generatorURL string, batchSize, batchTimeout, circuitBreakerThreshold int, mtls *MTLSConfig) *AlertmanagerClient {
	return newAlertmanagerClientFull(webhookURL, generatorURL, batchSize, batchTimeout,
		CircuitBreakerConfig{Threshold: circuitBreakerThreshold}, mtls, nil, nil, nil)
}

// NewAlertmanagerClientFull creates a client with explicit circuit-breaker config
// and optional Prometheus metrics for circuit state, fallback queue size, and
// dropped alerts.
func NewAlertmanagerClientFull(
	webhookURL, generatorURL string,
	batchSize, batchTimeout int,
	cbCfg CircuitBreakerConfig,
	mtls *MTLSConfig,
	circuitStateGauge prometheus.Gauge,
	fallbackSizeGauge prometheus.Gauge,
	droppedCounter prometheus.Counter,
) *AlertmanagerClient {
	return newAlertmanagerClientFull(webhookURL, generatorURL, batchSize, batchTimeout,
		cbCfg, mtls, circuitStateGauge, fallbackSizeGauge, droppedCounter)
}

func newAlertmanagerClientFull(
	webhookURL, generatorURL string,
	batchSize, batchTimeout int,
	cbCfg CircuitBreakerConfig,
	mtls *MTLSConfig,
	circuitStateGauge prometheus.Gauge,
	fallbackSizeGauge prometheus.Gauge,
	droppedCounter prometheus.Counter,
) *AlertmanagerClient {
	if err := validateWebhookURL(webhookURL); err != nil {
		slog.Warn("exporter/alertmanager: unsafe webhook URL rejected",
			slog.String("url", webhookURL),
			slog.Any("error", err))
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	if mtls != nil && mtls.Enabled {
		tlsConfig, err := createMTLSConfig(mtls)
		if err != nil {
			slog.Warn("exporter/alertmanager: failed to configure mTLS, using default transport",
				slog.Any("error", err))
		} else {
			httpClient.Transport = &http.Transport{
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
		client:       httpClient,
		cb:           newCircuitBreaker(cbCfg.Threshold, cbCfg.ResetTimeout, circuitStateGauge, nil),
		fallback:     newFallbackQueue(cbCfg.FallbackBufferSize, fallbackSizeGauge, droppedCounter),
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

	// Fast-fail: if the circuit is Open, route directly to the fallback buffer
	// without touching the send batch.  TryRecover transitions Open→HalfOpen
	// when the reset timeout has elapsed; a HalfOpen probe is allowed through.
	c.cb.TryRecover(time.Now())
	if !c.cb.Allow() {
		c.fallback.Enqueue(payload)
		span.SetAttributes(attribute.Bool("alert.fallback", true))
		return
	}

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

// FlushContext sends any pending alerts and blocks until all in-flight HTTP
// sends complete or ctx expires.
func (c *AlertmanagerClient) FlushContext(ctx context.Context) error {
	c.Flush()
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *AlertmanagerClient) flushUnlocked() {
	if len(c.batch) == 0 && c.fallback.Len() == 0 {
		return
	}

	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	// Attempt Open→HalfOpen transition if the reset timeout has elapsed.
	c.cb.TryRecover(time.Now())

	if !c.cb.Allow() {
		// Circuit is Open: buffer current batch into the fallback queue instead
		// of dropping it.  Memory is bounded by FallbackQueue.maxSize.
		for _, payload := range c.batch {
			c.fallback.Enqueue(payload)
		}
		c.batch = c.batch[:0]
		slog.Warn("exporter/alertmanager: circuit open, buffering alerts in fallback queue",
			slog.Int("fallback_size", c.fallback.Len()))
		return
	}

	// Circuit is Closed or HalfOpen: prepend any recovered fallback items so
	// they are replayed in FIFO order before new alerts.
	fallbackPayloads := c.fallback.DrainAll()

	total := len(fallbackPayloads) + len(c.batch)
	batch := make([]types.AlertPayload, 0, total)
	batch = append(batch, fallbackPayloads...)
	batch = append(batch, c.batch...)
	c.batch = c.batch[:0]

	if len(batch) == 0 {
		return
	}

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
	c.cb.RecordFailure()
}

func (c *AlertmanagerClient) recordSuccess() {
	recovered := c.cb.RecordSuccess()
	if !recovered {
		return
	}
	// Circuit just transitioned HalfOpen→Closed.
	// The fallback queue will be drained on the next flushUnlocked call
	// (triggered by the next SendAlert or explicit Flush).
	// Force an immediate drain so buffered alerts are replayed without waiting.
	c.mu.Lock()
	c.flushUnlocked()
	c.mu.Unlock()
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
