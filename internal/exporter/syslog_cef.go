// Package exporter provides a syslog RFC 5424 / CEF notifier.
package exporter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// SyslogCEFConfig holds syslog / CEF exporter configuration.
type SyslogCEFConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Network string `mapstructure:"network"`  // "tcp", "tcp+tls", "udp"
	Address string `mapstructure:"address"`  // "host:port", default port 514
	// Format selects the wire format: "rfc5424" (default) or "cef".
	Format  string `mapstructure:"format"`
	AppName string `mapstructure:"app_name"` // syslog APP-NAME field (default "ebpf-guard")
	// Facility: 1=user, 16=local0 … 23=local7. Default 1.
	Facility int `mapstructure:"facility"`
	// TLS (used when Network == "tcp+tls")
	CACert     string `mapstructure:"ca_cert"`
	ClientCert string `mapstructure:"client_cert"`
	ClientKey  string `mapstructure:"client_key"`

	MinSeverity string        `mapstructure:"min_severity"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

// SyslogCEFNotifier sends alerts as RFC 5424 syslog messages (with optional CEF
// extension) over TCP, TCP+TLS, or UDP.
type SyslogCEFNotifier struct {
	config      SyslogCEFConfig
	logger      *slog.Logger
	minSeverity types.Severity
	appName     string
	useCEF      bool
	network     string // resolved net dial network ("tcp", "udp")
	tlsCfg      *tls.Config

	mu   sync.Mutex
	conn net.Conn

	sent   prometheus.Counter
	errors prometheus.Counter

	closed atomic.Int32
}

var (
	syslogSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_syslog_alerts_sent_total",
		Help: "Total number of alerts successfully delivered via syslog.",
	})
	syslogErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_guard_syslog_alerts_errors_total",
		Help: "Total number of syslog alert delivery errors.",
	})
)

// NewSyslogCEFNotifier creates a new syslog/CEF notifier.
func NewSyslogCEFNotifier(cfg SyslogCEFConfig, logger *slog.Logger) *SyslogCEFNotifier {
	if !cfg.Enabled || cfg.Address == "" {
		return &SyslogCEFNotifier{config: cfg, logger: logger}
	}

	minSev := types.SeverityWarning
	if cfg.MinSeverity == "critical" {
		minSev = types.SeverityCritical
	}

	if cfg.AppName == "" {
		cfg.AppName = "ebpf-guard"
	}
	if cfg.Facility == 0 {
		cfg.Facility = 1 // user
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	network := "tcp"
	var tlsCfg *tls.Config

	switch strings.ToLower(cfg.Network) {
	case "udp":
		network = "udp"
	case "tcp+tls", "tls":
		network = "tcp"
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CACert != "" {
			pool := x509.NewCertPool()
			pem, err := os.ReadFile(cfg.CACert)
			if err != nil {
				logger.Error("syslog: failed to read CA cert", slog.Any("error", err))
			} else {
				pool.AppendCertsFromPEM(pem)
				tlsCfg.RootCAs = pool
			}
		}
		if cfg.ClientCert != "" && cfg.ClientKey != "" {
			cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
			if err != nil {
				logger.Error("syslog: failed to load client cert", slog.Any("error", err))
			} else {
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
		}
	default:
		network = "tcp"
	}

	return &SyslogCEFNotifier{
		config:      cfg,
		logger:      logger,
		minSeverity: minSev,
		appName:     cfg.AppName,
		useCEF:      strings.ToLower(cfg.Format) == "cef",
		network:     network,
		tlsCfg:      tlsCfg,
		sent:        syslogSentTotal,
		errors:      syslogErrorsTotal,
	}
}

func (n *SyslogCEFNotifier) Name() string  { return "syslog" }
func (n *SyslogCEFNotifier) Enabled() bool { return n.config.Enabled && n.config.Address != "" }

// Send formats and delivers an alert as a syslog message.
func (n *SyslogCEFNotifier) Send(ctx context.Context, alert types.Alert) error {
	if n.closed.Load() == 1 {
		return nil
	}
	if !n.syslogMeetsSeverity(alert) {
		return nil
	}

	var msg string
	if n.useCEF {
		msg = n.formatCEF(alert)
	} else {
		msg = n.formatRFC5424(alert)
	}

	return n.writeLine(ctx, msg)
}

// Close closes the underlying connection.
func (n *SyslogCEFNotifier) Close() error {
	if n.closed.Swap(1) == 1 {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn != nil {
		return n.conn.Close()
	}
	return nil
}

func (n *SyslogCEFNotifier) syslogMeetsSeverity(alert types.Alert) bool {
	if n.minSeverity == types.SeverityCritical {
		return alert.Severity == types.SeverityCritical
	}
	return true
}

// writeLine dials (or reuses) the connection and writes msg + newline.
func (n *SyslogCEFNotifier) writeLine(ctx context.Context, msg string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.conn == nil {
		conn, err := n.dial(ctx)
		if err != nil {
			n.errors.Inc()
			return fmt.Errorf("syslog: dial %s: %w", n.config.Address, err)
		}
		n.conn = conn
	}

	deadline, ok := ctx.Deadline()
	if ok {
		_ = n.conn.SetWriteDeadline(deadline)
	} else {
		_ = n.conn.SetWriteDeadline(time.Now().Add(n.config.Timeout))
	}

	_, err := fmt.Fprintln(n.conn, msg)
	if err != nil {
		// Connection broken — close and let the next Send re-dial.
		_ = n.conn.Close()
		n.conn = nil
		n.errors.Inc()
		return fmt.Errorf("syslog: write: %w", err)
	}

	n.sent.Inc()
	return nil
}

func (n *SyslogCEFNotifier) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: n.config.Timeout}
	if n.tlsCfg != nil {
		return tls.DialWithDialer(dialer, n.network, n.config.Address, n.tlsCfg)
	}
	return dialer.DialContext(ctx, n.network, n.config.Address)
}

// ─── RFC 5424 formatting ──────────────────────────────────────────────────────

// syslogSeverity maps ebpf-guard severity to syslog severity value (RFC 5424 §6.2.1).
func syslogSeverity(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 2 // CRIT
	default:
		return 4 // WARNING
	}
}

// formatRFC5424 builds an RFC 5424 syslog message.
// HEADER: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
// STRUCTURED-DATA: [ebpf-guard@50000 rule="..." pid="..." ...]
// MSG: human-readable alert message
func (n *SyslogCEFNotifier) formatRFC5424(alert types.Alert) string {
	pri := n.config.Facility*8 + syslogSeverity(alert.Severity)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "-"
	}
	ts := alert.Timestamp.UTC().Format(time.RFC3339Nano)

	// Structured data — use private enterprise number 50000 as placeholder.
	pod := alert.Enrichment.PodName
	if pod == "" {
		pod = "-"
	}
	ns := alert.Enrichment.Namespace
	if ns == "" {
		ns = "-"
	}
	sd := fmt.Sprintf(
		`[ebpf-guard@50000 rule="%s" severity="%s" pid="%d" comm="%s" pod="%s" namespace="%s" fingerprint="%s"]`,
		escapeSD(alert.RuleID),
		escapeSD(string(alert.Severity)),
		alert.PID,
		escapeSD(alert.Comm),
		escapeSD(pod),
		escapeSD(ns),
		escapeSD(alert.Fingerprint),
	)

	return fmt.Sprintf("<%d>1 %s %s %s - - %s %s",
		pri, ts, hostname, n.appName, sd, alert.Message)
}

// escapeSD escapes RFC 5424 structured-data param-value characters.
func escapeSD(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return s
}

// ─── CEF formatting ───────────────────────────────────────────────────────────

// cefSeverity maps ebpf-guard severity to ArcSight CEF severity (0-10).
func cefSeverity(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 10
	default:
		return 4
	}
}

// formatCEF builds a CEF:0 (ArcSight Common Event Format) message.
// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
func (n *SyslogCEFNotifier) formatCEF(alert types.Alert) string {
	name := alert.RuleName
	if name == "" {
		name = alert.RuleID
	}

	ext := strings.Builder{}
	ext.WriteString("rt=")
	ext.WriteString(alert.Timestamp.UTC().Format("Jan 02 2006 15:04:05"))
	ext.WriteString(" suser=")
	ext.WriteString(escapeCEFValue(alert.Comm))
	ext.WriteString(" spid=")
	ext.WriteString(fmt.Sprintf("%d", alert.PID))
	ext.WriteString(" cs1Label=rule_id cs1=")
	ext.WriteString(escapeCEFValue(alert.RuleID))
	if alert.Enrichment.PodName != "" {
		ext.WriteString(" cs2Label=pod cs2=")
		ext.WriteString(escapeCEFValue(alert.Enrichment.PodName))
		ext.WriteString(" cs3Label=namespace cs3=")
		ext.WriteString(escapeCEFValue(alert.Enrichment.Namespace))
	}
	if alert.TraceID != "" {
		ext.WriteString(" cs4Label=trace_id cs4=")
		ext.WriteString(escapeCEFValue(alert.TraceID))
	}
	if alert.Fingerprint != "" {
		ext.WriteString(" cs5Label=fingerprint cs5=")
		ext.WriteString(escapeCEFValue(alert.Fingerprint))
	}
	ext.WriteString(" msg=")
	ext.WriteString(escapeCEFValue(alert.Message))

	return fmt.Sprintf("CEF:0|ebpf-guard|ebpf-guard|1.0|%s|%s|%d|%s",
		escapeCEFHeader(alert.RuleID),
		escapeCEFHeader(name),
		cefSeverity(alert.Severity),
		ext.String())
}

// escapeCEFHeader escapes pipe and backslash in CEF header fields.
func escapeCEFHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// escapeCEFValue escapes equals signs, backslashes, and newlines in CEF extension values.
func escapeCEFValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}
