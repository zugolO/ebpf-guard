// Package exporter provides an OTLP (OpenTelemetry Protocol) log exporter.
package exporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// OTLPConfig holds OpenTelemetry Protocol log exporter configuration.
type OTLPConfig struct {
	Enabled    bool              `mapstructure:"enabled"`
	Endpoint   string            `mapstructure:"endpoint"`    // e.g. "http://otel-collector:4318"
	TLSEnabled bool              `mapstructure:"tls_enabled"` // upgrade to HTTPS
	CACert     string            `mapstructure:"ca_cert"`
	ClientCert string            `mapstructure:"client_cert"`
	ClientKey  string            `mapstructure:"client_key"`
	Headers    map[string]string `mapstructure:"headers"`
	MinSeverity string           `mapstructure:"min_severity"`
	Timeout    time.Duration     `mapstructure:"timeout"`
}

// otlpSeverityNumber maps ebpf-guard severity to OTLP SeverityNumber.
// See: https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
func otlpSeverityNumber(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 21 // FATAL
	default:
		return 13 // WARN
	}
}

// OTLPNotifier sends alerts as OTLP log records over HTTP/JSON to an
// OpenTelemetry Collector endpoint (POST /v1/logs).
type OTLPNotifier struct {
	config      OTLPConfig
	client      *http.Client
	logsURL     string
	logger      *slog.Logger
	minSeverity types.Severity

	sent   prometheus.Counter
	errors prometheus.Counter

	// closed is set to 1 on Close() to prevent further sends.
	closed atomic.Int32
}

var (
	otlpSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_otlp_alerts_sent_total",
		Help: "Total number of alerts successfully delivered via OTLP.",
	})
	otlpErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_otlp_alerts_errors_total",
		Help: "Total number of OTLP alert delivery errors.",
	})
)

// NewOTLPNotifier creates a new OTLP log notifier.
func NewOTLPNotifier(cfg OTLPConfig, logger *slog.Logger) *OTLPNotifier {
	if !cfg.Enabled || cfg.Endpoint == "" {
		return &OTLPNotifier{config: cfg, logger: logger}
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	transport := &http.Transport{}
	if cfg.TLSEnabled || cfg.CACert != "" || cfg.ClientCert != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			pem, err := os.ReadFile(cfg.CACert)
			if err != nil {
				logger.Error("otlp: failed to read CA cert", slog.String("path", cfg.CACert), slog.Any("error", err))
			} else {
				pool.AppendCertsFromPEM(pem)
				tlsCfg.RootCAs = pool
			}
		}
		if cfg.ClientCert != "" && cfg.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
			if err != nil {
				logger.Error("otlp: failed to load client cert", slog.Any("error", err))
			} else {
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
		}
		transport.TLSClientConfig = tlsCfg
	}

	endpoint := cfg.Endpoint
	if endpoint[len(endpoint)-1] == '/' {
		endpoint = endpoint[:len(endpoint)-1]
	}

	return &OTLPNotifier{
		config:      cfg,
		client:      &http.Client{Transport: transport, Timeout: cfg.Timeout},
		logsURL:     endpoint + "/v1/logs",
		logger:      logger,
		minSeverity: minSev,
		sent:        otlpSentTotal,
		errors:      otlpErrorsTotal,
	}
}

func (n *OTLPNotifier) Name() string    { return "otlp" }
func (n *OTLPNotifier) Enabled() bool   { return n.config.Enabled && n.config.Endpoint != "" && n.client != nil }

// Send serialises alert as an OTLP LogRecord and POSTs it to /v1/logs.
func (n *OTLPNotifier) Send(ctx context.Context, alert types.Alert) error {
	if n.closed.Load() == 1 {
		return nil
	}
	if !n.meetsSeverity(alert) {
		return nil
	}

	payload, err := n.buildPayload(alert)
	if err != nil {
		return fmt.Errorf("otlp: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.logsURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("otlp: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		n.errors.Inc()
		return fmt.Errorf("otlp: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		n.errors.Inc()
		return fmt.Errorf("otlp: collector returned HTTP %d", resp.StatusCode)
	}

	n.sent.Inc()
	return nil
}

func (n *OTLPNotifier) Close() error {
	n.closed.Store(1)
	return nil
}

// meetsSeverity reports whether the alert meets the minimum severity threshold.
func (n *OTLPNotifier) meetsSeverity(alert types.Alert) bool {
	if n.minSeverity == types.SeverityCritical {
		return alert.Severity == types.SeverityCritical
	}
	return true
}

// buildPayload builds the OTLP JSON/HTTP body for the given alert.
// Format follows: https://opentelemetry.io/docs/specs/otlp/#otlphttp-request
func (n *OTLPNotifier) buildPayload(alert types.Alert) ([]byte, error) {
	attrs := []map[string]interface{}{
		kvStr("rule.id", alert.RuleID),
		kvStr("rule.name", alert.RuleName),
		kvStr("process.comm", alert.Comm),
		kvStr("process.pid", strconv.FormatUint(uint64(alert.PID), 10)),
		kvStr("ebpf_guard.severity", string(alert.Severity)),
		kvStr("ebpf_guard.fingerprint", alert.Fingerprint),
		kvStr("ebpf_guard.action", alert.Action),
	}
	if alert.Enrichment.PodName != "" {
		attrs = append(attrs, kvStr("k8s.pod.name", alert.Enrichment.PodName))
		attrs = append(attrs, kvStr("k8s.namespace.name", alert.Enrichment.Namespace))
		attrs = append(attrs, kvStr("k8s.node.name", alert.Enrichment.NodeName))
	}
	if alert.Enrichment.ContainerImage != "" {
		attrs = append(attrs, kvStr("container.image.name", alert.Enrichment.ContainerImage))
	}

	// Encode trace/span IDs in hex if present.
	traceIDHex := alert.TraceID
	spanIDHex := alert.SpanID
	if len(alert.TraceID) == 32 {
		// already hex
	} else if len(alert.TraceID) == 16 {
		traceIDHex = hex.EncodeToString([]byte(alert.TraceID))
	}
	if len(alert.SpanID) == 16 {
		// already hex
	} else if len(alert.SpanID) == 8 {
		spanIDHex = hex.EncodeToString([]byte(alert.SpanID))
	}

	logRecord := map[string]interface{}{
		"timeUnixNano":   strconv.FormatInt(alert.Timestamp.UnixNano(), 10),
		"severityNumber": otlpSeverityNumber(alert.Severity),
		"severityText":   string(alert.Severity),
		"body":           map[string]interface{}{"stringValue": alert.Message},
		"attributes":     attrs,
		"traceId":        traceIDHex,
		"spanId":         spanIDHex,
	}

	payload := map[string]interface{}{
		"resourceLogs": []interface{}{
			map[string]interface{}{
				"resource": map[string]interface{}{
					"attributes": []interface{}{
						kvStr("service.name", "ebpf-guard"),
						kvStr("service.version", "1.0.0"),
					},
				},
				"scopeLogs": []interface{}{
					map[string]interface{}{
						"scope": map[string]interface{}{
							"name":    "github.com/zugolO/ebpf-guard",
							"version": "1.0.0",
						},
						"logRecords": []interface{}{logRecord},
					},
				},
			},
		},
	}

	return json.Marshal(payload)
}

// kvStr builds an OTLP string-valued key-value attribute map.
func kvStr(key, value string) map[string]interface{} {
	return map[string]interface{}{
		"key":   key,
		"value": map[string]interface{}{"stringValue": value},
	}
}
