//go:build !kafka

package exporter

import (
	"context"
	"log/slog"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// KafkaConfig holds Kafka producer configuration.
// When built without the kafka tag, all fields are preserved for config
// compatibility but the notifier is never enabled.
type KafkaConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	Brokers      []string `mapstructure:"brokers"`
	Topic        string   `mapstructure:"topic"`
	Payload      string   `mapstructure:"payload"`
	SASLEnabled  bool     `mapstructure:"sasl_enabled"`
	SASLUsername string   `mapstructure:"sasl_username"`
	SASLPassword string   `mapstructure:"sasl_password"`
	TLSEnabled   bool     `mapstructure:"tls_enabled"`
	CACert       string   `mapstructure:"ca_cert"`
	ClientCert   string   `mapstructure:"client_cert"`
	ClientKey    string   `mapstructure:"client_key"`
	MinSeverity  string   `mapstructure:"min_severity"`
}

// KafkaNotifier is a stub that never sends; Kafka support is not compiled in.
type KafkaNotifier struct {
	config KafkaConfig
	logger *slog.Logger
}

// NewKafkaNotifier creates a stub Kafka notifier. It logs a warning that
// the kafka build tag is not set and returns a disabled instance.
func NewKafkaNotifier(cfg KafkaConfig, logger *slog.Logger) (*KafkaNotifier, error) {
	if cfg.Enabled {
		logger.Warn("kafka: build tag not set — install with -tags kafka for Kafka support, skipping")
	}
	return &KafkaNotifier{config: cfg, logger: logger}, nil
}

func (n *KafkaNotifier) Name() string                         { return "kafka" }
func (n *KafkaNotifier) Enabled() bool                        { return false }
func (n *KafkaNotifier) Send(_ context.Context, _ types.Alert) error { return nil }
func (n *KafkaNotifier) Close() error                         { return nil }
