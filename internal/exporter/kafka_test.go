package exporter

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestKafkaNotifier_Disabled(t *testing.T) {
	n := NewKafkaNotifier(KafkaConfig{Enabled: false}, slog.Default())
	assert.False(t, n.Enabled())
}

func TestKafkaNotifier_NoBrokers(t *testing.T) {
	n := NewKafkaNotifier(KafkaConfig{Enabled: true, Brokers: nil, Topic: "alerts"}, slog.Default())
	assert.False(t, n.Enabled())
}

func TestKafkaNotifier_NoTopic(t *testing.T) {
	n := NewKafkaNotifier(KafkaConfig{Enabled: true, Brokers: []string{"kafka:9092"}, Topic: ""}, slog.Default())
	assert.False(t, n.Enabled())
}

func TestKafkaNotifier_UnreachableBroker(t *testing.T) {
	// Connecting to an unreachable broker should produce a disabled notifier (error logged).
	n := NewKafkaNotifier(KafkaConfig{
		Enabled: true,
		Brokers: []string{"127.0.0.1:19092"}, // nothing listening here
		Topic:   "alerts",
	}, slog.Default())
	// Notifier should be disabled (producer failed to init)
	assert.False(t, n.Enabled())
}

func TestKafkaNotifier_Name(t *testing.T) {
	n := &KafkaNotifier{config: KafkaConfig{}}
	assert.Equal(t, "kafka", n.Name())
}

func TestKafkaNotifier_MinSeverity(t *testing.T) {
	n := &KafkaNotifier{
		config:      KafkaConfig{Enabled: true},
		minSeverity: types.SeverityCritical,
	}

	alert := makeTestAlert()
	alert.Severity = types.SeverityWarning
	assert.False(t, n.kafkaMeetsSeverity(alert))

	alert.Severity = types.SeverityCritical
	assert.True(t, n.kafkaMeetsSeverity(alert))
}

func TestKafkaNotifier_SendAfterClose(t *testing.T) {
	n := &KafkaNotifier{
		config: KafkaConfig{Enabled: true},
	}
	n.closed.Store(1)

	// Should not panic or error when closed
	err := n.Send(context.Background(), makeTestAlert())
	assert.NoError(t, err)
}

func TestKafkaNotifier_CloseTwice(t *testing.T) {
	n := &KafkaNotifier{config: KafkaConfig{}}
	assert.NoError(t, n.Close())
	assert.NoError(t, n.Close()) // second close must be idempotent
}
