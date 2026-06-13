//go:build kafka

// Package exporter provides a Kafka producer for alert fanout.
package exporter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// KafkaConfig holds Kafka producer configuration.
type KafkaConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Brokers []string `mapstructure:"brokers"` // e.g. ["kafka:9092"]
	Topic   string   `mapstructure:"topic"`   // destination topic
	// Payload controls the message format: "json" (default) or "falco".
	Payload string `mapstructure:"payload"`
	// SASL authentication (PLAIN only; SCRAM requires xdg-go/scram)
	SASLEnabled  bool   `mapstructure:"sasl_enabled"`
	SASLUsername string `mapstructure:"sasl_username"`
	SASLPassword string `mapstructure:"sasl_password"`
	// TLS transport security
	TLSEnabled bool   `mapstructure:"tls_enabled"`
	CACert     string `mapstructure:"ca_cert"`
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`

	MinSeverity string `mapstructure:"min_severity"`
}

// KafkaNotifier sends alerts to a Kafka topic.
// The message key is the alert fingerprint for deduplication-friendly partition assignment.
type KafkaNotifier struct {
	config      KafkaConfig
	producer    sarama.SyncProducer
	logger      *slog.Logger
	minSeverity types.Severity
	useFalco    bool

	sent   prometheus.Counter
	errors prometheus.Counter

	closed atomic.Int32
}

var (
	kafkaSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_kafka_alerts_sent_total",
		Help: "Total number of alerts successfully delivered to Kafka.",
	})
	kafkaErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_kafka_alerts_errors_total",
		Help: "Total number of Kafka alert delivery errors.",
	})
)

// NewKafkaNotifier creates a new Kafka notifier.
func NewKafkaNotifier(cfg KafkaConfig, logger *slog.Logger) (*KafkaNotifier, error) {
	if !cfg.Enabled || len(cfg.Brokers) == 0 || cfg.Topic == "" {
		return &KafkaNotifier{config: cfg, logger: logger}, nil
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	if cfg.SASLEnabled && !cfg.TLSEnabled {
		return nil, errors.New("kafka: SASL PLAIN requires tls_enabled: true to avoid credential exposure")
	}

	saramaCfg := sarama.NewConfig()
	saramaCfg.Producer.RequiredAcks = sarama.WaitForAll
	saramaCfg.Producer.Retry.Max = 5
	saramaCfg.Producer.Return.Successes = true
	saramaCfg.Producer.Return.Errors = true
	saramaCfg.Net.DialTimeout = 10 * time.Second
	saramaCfg.Net.ReadTimeout = 10 * time.Second
	saramaCfg.Net.WriteTimeout = 10 * time.Second

	if cfg.TLSEnabled || cfg.CACert != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			pem, err := os.ReadFile(cfg.CACert)
			if err != nil {
				return nil, fmt.Errorf("kafka: failed to read CA cert %q: %w", cfg.CACert, err)
			}
			pool.AppendCertsFromPEM(pem)
			tlsCfg.RootCAs = pool
		}
		if cfg.ClientCert != "" && cfg.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
			if err != nil {
				return nil, fmt.Errorf("kafka: failed to load client cert %q: %w", cfg.ClientCert, err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		saramaCfg.Net.TLS.Enable = true
		saramaCfg.Net.TLS.Config = tlsCfg
	}

	if cfg.SASLEnabled {
		saramaCfg.Net.SASL.Enable = true
		saramaCfg.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		saramaCfg.Net.SASL.User = cfg.SASLUsername
		saramaCfg.Net.SASL.Password = cfg.SASLPassword
	}

	producer, err := sarama.NewSyncProducer(cfg.Brokers, saramaCfg)
	if err != nil {
		logger.Error("kafka: failed to create producer", slog.Any("error", err))
		return &KafkaNotifier{config: cfg, logger: logger}, nil
	}

	return &KafkaNotifier{
		config:      cfg,
		producer:    producer,
		logger:      logger,
		minSeverity: minSev,
		useFalco:    cfg.Payload == "falco",
		sent:        kafkaSentTotal,
		errors:      kafkaErrorsTotal,
	}, nil
}

func (n *KafkaNotifier) Name() string  { return "kafka" }
func (n *KafkaNotifier) Enabled() bool { return n.config.Enabled && n.producer != nil }

// Send encodes alert as JSON (or Falco-compatible JSON) and publishes it to Kafka.
// The message key is the alert fingerprint for partition affinity.
func (n *KafkaNotifier) Send(_ context.Context, alert types.Alert) error {
	if n.closed.Load() == 1 {
		return nil
	}
	if !n.kafkaMeetsSeverity(alert) {
		return nil
	}

	var (
		payload []byte
		err     error
	)
	if n.useFalco {
		payload, err = MarshalFalcoAlert(alert)
	} else {
		payload, err = json.Marshal(alert)
	}
	if err != nil {
		return fmt.Errorf("kafka: marshal alert: %w", err)
	}

	key := alert.Fingerprint
	if key == "" {
		key = alert.ID
	}

	msg := &sarama.ProducerMessage{
		Topic: n.config.Topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(payload),
		Headers: []sarama.RecordHeader{
			{Key: []byte("rule_id"), Value: []byte(alert.RuleID)},
			{Key: []byte("severity"), Value: []byte(string(alert.Severity))},
			{Key: []byte("source"), Value: []byte("ebpf-guard")},
		},
	}

	if _, _, err := n.producer.SendMessage(msg); err != nil {
		n.errors.Inc()
		return fmt.Errorf("kafka: publish: %w", err)
	}

	n.sent.Inc()
	return nil
}

// Close flushes and closes the Kafka producer.
func (n *KafkaNotifier) Close() error {
	if n.closed.Swap(1) == 1 {
		return nil
	}
	if n.producer != nil {
		return n.producer.Close()
	}
	return nil
}

func (n *KafkaNotifier) kafkaMeetsSeverity(alert types.Alert) bool {
	if n.minSeverity == types.SeverityCritical {
		return alert.Severity == types.SeverityCritical
	}
	return true
}
