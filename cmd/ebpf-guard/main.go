// Package main is the entry point for the ebpf-guard security agent.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/semaphore"
	"github.com/zugolO/ebpf-guard/internal/audit"
	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/attacker"
	"github.com/zugolO/ebpf-guard/internal/autolearn"
	"github.com/zugolO/ebpf-guard/internal/canary"
	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/drift"
	"github.com/zugolO/ebpf-guard/internal/enforcer"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/gossip"
	"github.com/zugolO/ebpf-guard/internal/migration"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
	"github.com/zugolO/ebpf-guard/internal/runtime"
	"github.com/zugolO/ebpf-guard/internal/simulate"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/internal/tui"
	"github.com/zugolO/ebpf-guard/internal/watchdog"
	"github.com/zugolO/ebpf-guard/internal/wasm"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Build-time variables set via ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = ""
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		cfgPath         string
		logLevel        string
		dryRun          bool
		simulateMode    bool
		simulateDuration string
		shutdownTimeout string
	)

	root := &cobra.Command{
		Use:   "ebpf-guard",
		Short: "eBPF-based runtime security agent for Linux/Kubernetes",
		Long: `ebpf-guard attaches eBPF probes to collect kernel events, correlates them
against YAML detection rules, and exports alerts to Prometheus and Alertmanager.`,
		Version:      fmt.Sprintf("%s (commit %s)", Version, Commit),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cfgPath, logLevel, dryRun, simulateMode, simulateDuration, shutdownTimeout)
		},
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	root.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "run without real eBPF probes (uses synthetic events)")
	root.PersistentFlags().BoolVar(&simulateMode, "simulate", false,
		"simulate enforcement: count what would be killed/blocked/throttled without acting")
	root.PersistentFlags().StringVar(&simulateDuration, "simulate-duration", "",
		"stop simulation after this duration (e.g. 24h, 30m); empty = run until Ctrl+C")
	root.PersistentFlags().StringVar(&shutdownTimeout, "shutdown-timeout", "",
		"graceful shutdown timeout, overrides config (e.g. 60s, 2m); valid range [5s, 300s]")

	rulesCmd := newRulesCmd(&cfgPath)
	rulesCmd.AddCommand(newRulesTestCmd(&cfgPath))
	rulesCmd.AddCommand(newRulesCheckCmd())

	configCmd := newConfigCmd()

	root.AddCommand(
		newAlertsCmd(&cfgPath),
		newStatusCmd(),
		rulesCmd,
		newVersionCmd(),
		newLearnCmd(),
		newDashboardCmd(),
		configCmd,
		newAttackSimCmd(&cfgPath),
		newPluginsCmd(),
	)

	return root
}

func runAgent(cfgPath, logLevel string, dryRun bool, simulateMode bool, simulateDuration, shutdownTimeoutFlag string) error {
	setupLogger(logLevel)

	slog.Info("ebpf-guard starting",
		slog.String("version", Version),
		slog.String("commit", Commit),
		slog.Bool("dry_run", dryRun),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfgManager, err := config.NewManagerSkipPermCheck(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg := cfgManager.Get()

	if shutdownTimeoutFlag != "" {
		d, err := time.ParseDuration(shutdownTimeoutFlag)
		if err != nil {
			return fmt.Errorf("invalid --shutdown-timeout: %w", err)
		}
		if d < 5*time.Second || d > 300*time.Second {
			return fmt.Errorf("--shutdown-timeout %s out of range: must be in [5s, 300s]", d)
		}
		cfg.Server.ShutdownTimeout = d
	}

	if err := config.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("config validation:\n%w", err)
	}

	// ── BTF source resolution ──────────────────────────────────────────────────
	// Detect which BTF strategy is available before loading any eBPF programs.
	// This must run before collector initialisation so collectors that require
	// BTF struct offsets (LSM, TLS uprobes) can be skipped gracefully.
	if !dryRun {
		internalbpf.RegisterBTFMetrics(prometheus.DefaultRegisterer)

		kf, kfErr := internalbpf.DetectFeatures()
		if kfErr != nil {
			slog.Warn("kernel feature detection failed", slog.Any("error", kfErr))
		}

		btfResult, btfErr := internalbpf.ResolveBTF(internalbpf.BTFResolutionConfig{
			BTFPath:                 cfg.BPF.BTFPath,
			BTFHubEnabled:           cfg.BPF.BTFHubEnabled,
			BTFHubCache:             cfg.BPF.BTFHubCache,
			FallbackReducedFeatures: cfg.BPF.FallbackReducedFeatures,
		})
		if btfErr != nil {
			return fmt.Errorf("btf resolution: %w", btfErr)
		}

		if kf != nil {
			kf.BTFSource = btfResult.Source
			if err := kf.CheckMinimumRequirements(cfg.BPF.FallbackReducedFeatures); err != nil {
				return fmt.Errorf("kernel requirements not met: %w", err)
			}
			slog.Info("kernel features detected", slog.String("features", kf.String()),
				slog.String("btf_source", string(btfResult.Source)))
		}

		if len(btfResult.DisabledCollectors) > 0 {
			slog.Warn("btf: reduced feature set active — some collectors are disabled",
				slog.Any("disabled", btfResult.DisabledCollectors))
		}
	}

	rules, err := correlator.LoadRulesFromFile(cfg.Rules.Path)
	if err != nil {
		slog.Warn("failed to load rules file, starting with empty rule set",
			slog.String("path", cfg.Rules.Path),
			slog.Any("error", err))
		rules = nil
	} else {
		slog.Info("rules loaded", slog.Int("count", len(rules)))
	}

	// Audit log for rule changes and config hot-reloads.
	var rulesAuditLog *audit.RulesLogger
	if cfg.Audit.Enabled {
		rl, rlErr := audit.NewRulesLogger(cfg.Audit.Path, cfg.Audit.MaxSizeMB, cfg.Audit.IncludeRuleDiffs)
		if rlErr != nil {
			slog.Warn("audit log: failed to open, rule-change auditing disabled",
				slog.String("path", cfg.Audit.Path),
				slog.Any("error", rlErr))
		} else {
			rulesAuditLog = rl
			defer rulesAuditLog.Close()
			ruleIDs := ruleIDsFrom(rules)
			if logErr := rulesAuditLog.LogRulesLoaded(cfg.Rules.Path, ruleIDs); logErr != nil {
				slog.Warn("audit log: failed to write rules_loaded entry", slog.Any("error", logErr))
			}
		}
	}

	// Feature D: canary trap / honeypot detection.
	var canaryManager *canary.Manager
	if cfg.Canary.Enabled {
		canaryManager = canary.New(canary.Config{
			Enabled:        true,
			AutoCreate:     cfg.Canary.AutoCreate,
			Files:          cfg.Canary.Files,
			AlertSeverity:  cfg.Canary.AlertSeverity,
			VerifyInterval: cfg.Canary.VerifyInterval,
			AlertOnTamper:  cfg.Canary.AlertOnTamper,
		})
		canaryManager.Setup()
		canaryRules := canaryManager.Rules()
		rules = append(rules, canaryRules...)
		slog.Info("canary: traps armed",
			slog.Int("files", len(canaryManager.Paths())),
			slog.Int("rules", len(canaryRules)))
	}

	// Feature C: event log for rule replay.
	var eventLog *store.EventLog
	if cfg.EventLog.Enabled {
		maxBytes := int64(cfg.EventLog.MaxSizeMB) * 1024 * 1024
		el, elErr := store.NewEventLog(store.EventLogConfig{
			Path:         cfg.EventLog.Path,
			MaxSizeBytes: maxBytes,
		})
		if elErr != nil {
			slog.Warn("event log: failed to open, replay will be unavailable",
				slog.String("path", cfg.EventLog.Path),
				slog.Any("error", elErr))
		} else {
			eventLog = el
			defer eventLog.Close()
			slog.Info("event log: recording events for replay",
				slog.String("path", cfg.EventLog.Path))
		}
	}

	engineCfg := correlator.DefaultCorrelationEngineConfig()
	engineCfg.Rules = rules
	engineCfg.BufferSize = cfg.Correlator.BufferSize
	if engineCfg.BufferSize <= 0 {
		engineCfg.BufferSize = 10000
	}
	engineCfg.EnableAnomaly = cfg.Profiler.Enabled
	engineCfg.AnomalyThreshold = cfg.Profiler.AnomalyThreshold
	engineCfg.LearningPeriod = time.Duration(cfg.Profiler.LearningPeriod) * time.Second
	engineCfg.EWMAWeight = cfg.Profiler.EWMAWeight
	engineCfg.MinLearningSamples = cfg.Profiler.MinLearningSamples
	engineCfg.EnableRateLimit = cfg.Rules.RateLimitAlerts
	engineCfg.RateLimitWindow = time.Duration(cfg.Rules.RateLimitWindow) * time.Second
	engineCfg.MaxAlertsPerWindow = cfg.Rules.MaxAlertsPerWindow
	if cfg.Correlator.MaxAlertsPerSecond > 0 {
		engineCfg.MaxAlertsPerSecond = cfg.Correlator.MaxAlertsPerSecond
	}

	if cfg.Profiler.Enabled {
		profCfg := profiler.ProfilerConfig{
			Threshold:      cfg.Profiler.AnomalyThreshold,
			Weight:         cfg.Profiler.EWMAWeight,
			TTLSeconds:     cfg.Profiler.ProfileTTL,
			MaxTrackedPIDs: cfg.Profiler.MaxTrackedPIDs,
			Sequence: profiler.SequenceConfig{
				Enabled:    cfg.Profiler.Sequence.Enabled,
				WindowSize: cfg.Profiler.Sequence.WindowSize,
				Threshold:  cfg.Profiler.Sequence.Threshold,
			},
			Lineage: profiler.LineageConfig{
				Enabled:  cfg.Profiler.Lineage.Enabled,
				TTL:      time.Duration(cfg.Profiler.Lineage.TTL) * time.Second,
				MaxDepth: cfg.Profiler.Lineage.MaxDepth,
			},
		}
		p := profiler.NewProfilerWithContext(ctx, profCfg, slog.Default())
		engineCfg.LineageTracker = p.GetLineageTracker()

		if cfg.Watchdog.MemoryPressure.Enabled {
			memCfg := watchdog.MemoryConfig{
				Enabled:                  true,
				CheckInterval:            time.Duration(cfg.Watchdog.MemoryPressure.CheckInterval) * time.Second,
				LowMemoryThreshold:       cfg.Watchdog.MemoryPressure.LowMemoryThreshold,
				RecoveryThreshold:        cfg.Watchdog.MemoryPressure.RecoveryThreshold,
				DisableSequenceThreshold: cfg.Watchdog.MemoryPressure.DisableSequenceThreshold,
				DisableAllThreshold:      cfg.Watchdog.MemoryPressure.DisableAllThreshold,
			}
			seqProfilers := []watchdog.ControllableProfiler{p.GetSequenceProfiler()}
			memWatcher := watchdog.NewMemoryPressureWatcherWithSequence(
				memCfg, slog.Default(), seqProfilers, nil, nil,
			)
			if err := memWatcher.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
				slog.Warn("memory pressure: failed to register metrics", slog.Any("error", err))
			}
			go memWatcher.Start(ctx)
		}
	}

	// Feature F: cross-node alert correlation via gossip amplification.
	var gossipMgr *gossip.Manager
	if cfg.Gossip.Enabled {
		nodeName := cfg.Gossip.NodeName
		if nodeName == "" {
			if h, err := os.Hostname(); err == nil {
				nodeName = h
			}
		}
		gm, gErr := gossip.NewManager(gossip.Config{
			Enabled:           true,
			NodeName:          nodeName,
			Secret:            cfg.Gossip.Secret,
			SecretPrevious:    cfg.Gossip.SecretPrevious,
			SecretRotationTTL: cfg.Gossip.SecretRotationTTL,
			Peers:             cfg.Gossip.Peers,
			IOCTTL:            time.Duration(cfg.Gossip.IOCTTLSeconds) * time.Second,
			MaxIOCs:           cfg.Gossip.MaxIOCs,
			PushInterval:      time.Duration(cfg.Gossip.PushIntervalSeconds) * time.Second,
			TLSEnabled:        cfg.Gossip.TLSEnabled,
			TLSCertFile:       cfg.Gossip.TLSCertFile,
			TLSKeyFile:        cfg.Gossip.TLSKeyFile,
			TLSCAFile:         cfg.Gossip.TLSCAFile,
		}, slog.Default())
		if gErr != nil {
			slog.Warn("gossip: failed to initialise, cross-node correlation disabled",
				slog.Any("error", gErr))
		} else {
			gossipMgr = gm
			gossipMgr.RegisterMetrics(prometheus.DefaultRegisterer)
			gm.Start(ctx)
			engineCfg.IOCMatcher = gm
			engineCfg.SensitivityAdjuster = gm
			slog.Info("gossip: cross-node alert correlation active",
				slog.String("node", nodeName),
				slog.Int("peers", len(cfg.Gossip.Peers)))
		}
	}

	// Open the append-only enforcement audit log when configured.
	var auditCh chan enforcer.AuditEntry
	if cfg.Enforcement.AuditLog != "" {
		al, alErr := audit.New(cfg.Enforcement.AuditLog)
		if alErr != nil {
			slog.Warn("enforcer: audit log unavailable, audit disabled",
				slog.String("path", cfg.Enforcement.AuditLog),
				slog.Any("error", alErr))
		} else {
			defer al.Close()
			auditCh = make(chan enforcer.AuditEntry, 256)
			go func() {
				for entry := range auditCh {
					_ = al.Log(audit.Entry{
						TS:       entry.Timestamp,
						Action:   string(entry.Action),
						PID:      entry.PID,
						Rule:     entry.RuleID,
						Comm:     entry.Comm,
						Enforced: entry.Success,
					})
				}
			}()
			slog.Info("enforcer: audit log enabled",
				slog.String("path", cfg.Enforcement.AuditLog))
		}
	}

	// Initialize enforcer when enabled in config.
	// Wired to the engine so rule actions (kill/block/throttle) are executed
	// asynchronously via the engine's bounded worker pool.
	var enf *enforcer.Enforcer
	if cfg.Enforcement.Enabled {
		enfCfg := enforcer.Config{
			DryRun:                  cfg.Enforcement.DryRun,
			BlockBackend:            enforcer.BlockBackend(cfg.Enforcement.BlockBackend),
			EnableBlock:             cfg.Enforcement.EnableBlock,
			EnableKill:              cfg.Enforcement.EnableKill,
			EnableThrottle:          cfg.Enforcement.EnableThrottle,
			ThrottleCPUPercent:      cfg.Enforcement.ThrottleCPUPercent,
			ThrottleMaxAge:          time.Duration(cfg.Enforcement.ThrottleMaxAgeMinutes) * time.Minute,
			ThrottleCleanupInterval: time.Duration(cfg.Enforcement.ThrottleCleanupIntervalMinutes) * time.Minute,
			AuditLogChannel:         auditCh,
		}
		if e, enfErr := enforcer.NewEnforcer(slog.Default(), enfCfg); enfErr != nil {
			slog.Warn("enforcer: failed to initialize, enforcement disabled",
				slog.Any("error", enfErr))
		} else {
			enf = e
			engineCfg.ActionExecutor = enf
			slog.Info("enforcer: active",
				slog.String("backend", cfg.Enforcement.BlockBackend),
				slog.Bool("dry_run", cfg.Enforcement.DryRun))
		}
	}

	engine := correlator.NewCorrelationEngineWithConfig(engineCfg)

	// Feature E: BPF self-telemetry — per-program CPU overhead metrics.
	bpfTelemetry := watchdog.NewBPFTelemetry(slog.Default())
	if err := prometheus.Register(bpfTelemetry); err != nil {
		slog.Warn("bpf_telemetry: failed to register Prometheus collector",
			slog.Any("error", err))
	}

	sqliteVacuumInterval, _ := time.ParseDuration(cfg.Store.SQLite.VacuumInterval)
	if sqliteVacuumInterval <= 0 {
		sqliteVacuumInterval = time.Hour
	}
	sqliteRetentionPeriod, _ := time.ParseDuration(cfg.Store.SQLite.RetentionPeriod)
	sqliteBackupInterval, _ := time.ParseDuration(cfg.Store.SQLite.Backup.Interval)

	alertStore, err := store.New(store.Config{
		Backend: cfg.Store.Backend,
		SQLite: store.SQLiteConfig{
			Path:              cfg.Store.SQLite.Path,
			MaxOpenConns:      10,
			MaxIdleConns:      5,
			MaxAlerts:         cfg.Store.SQLite.MaxAlerts,
			VacuumInterval:    sqliteVacuumInterval,
			RetentionPeriod:   sqliteRetentionPeriod,
			BackupEnabled:     cfg.Store.SQLite.Backup.Enabled,
			BackupPath:        cfg.Store.SQLite.Backup.Path,
			BackupInterval:    sqliteBackupInterval,
			EncryptionEnabled: cfg.Store.SQLite.Encryption.Enabled,
			EncryptionKeyEnv:  cfg.Store.SQLite.Encryption.KeyEnv,
			EncryptionKeyFile: cfg.Store.SQLite.Encryption.KeyFile,
		},
		OpenSearch: store.OpenSearchConfig{
			Addresses:          []string{cfg.Store.OpenSearch.URL},
			Username:           cfg.Store.OpenSearch.Username,
			Password:           cfg.Store.OpenSearch.Password,
			InsecureSkipVerify: cfg.Store.OpenSearch.InsecureSkipVerify,
			CACert:             cfg.Store.OpenSearch.CACert,
			TLSServerName:      cfg.Store.OpenSearch.TLSServerName,
		},
		RetentionPeriod: 7 * 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("init alert store: %w", err)
	}
	defer alertStore.Close()

	viewerToken := cfg.Auth.ViewerToken
	adminToken := cfg.Auth.AdminToken
	// Backward compat: bearer_token promoted to admin if new fields are not set.
	if adminToken == "" && cfg.Auth.BearerToken != "" {
		adminToken = cfg.Auth.BearerToken
	}
	if cfg.Auth.Enabled {
		if adminToken == "" && len(cfg.Auth.Tokens) == 0 {
			adminToken = generateToken()
			slog.Info("auth: generated admin token (not shown for security)")
		}
		if viewerToken == "" && len(cfg.Auth.Tokens) == 0 {
			viewerToken = generateToken()
			slog.Info("auth: generated viewer token (not shown for security)")
		}
	}

	// Build namespace-scoped token list from config.
	var namespacedTokens []exporter.NamespacedToken
	for _, t := range cfg.Auth.Tokens {
		role := exporter.RoleViewer
		if t.Role == "admin" {
			role = exporter.RoleAdmin
		}
		namespacedTokens = append(namespacedTokens, exporter.NamespacedToken{
			Token:      t.Token,
			Role:       role,
			Namespaces: t.Namespaces,
		})
	}
	if len(namespacedTokens) > 0 {
		slog.Info("auth: namespace-scoped tokens configured", slog.Int("count", len(namespacedTokens)))
	}

	srv := exporter.NewServerWithMultiTenant(
		cfg.Server.BindAddress,
		cfg.Server.MetricsPath,
		cfg.Server.HealthPath,
		cfg.Server.EnablePprof,
		cfg.Server.EnableDebug,
		namespacedTokens,
		viewerToken,
		adminToken,
		cfg.Auth.Enabled,
	)
	srv.SetAlertStore(alertStore)
	srv.SetRulesProvider(func() []correlator.Rule {
		return engine.GetRules()
	})
	srv.SetIncidentTracker(engine.IncidentTracker())

	if gossipMgr != nil {
		srv.RegisterGossipRoutes(gossip.Handler(gossipMgr))
	}

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("start HTTP server: %w", err)
	}

	// ── Alertmanager webhook client ──────────────────────────────────────────
	var alertmanagerClient *exporter.AlertmanagerClient
	if cfg.Alerting.Enabled {
		resetTimeout := time.Duration(cfg.Alerting.CircuitBreakerResetTimeout) * time.Second
		if resetTimeout <= 0 {
			resetTimeout = 30 * time.Second
		}
		alertmanagerClient = exporter.NewAlertmanagerClientFull(
			cfg.Alerting.WebhookURL,
			cfg.Alerting.GeneratorURL,
			cfg.Alerting.BatchSize,
			cfg.Alerting.BatchTimeout,
			exporter.CircuitBreakerConfig{
				Threshold:          cfg.Alerting.CircuitBreakerThreshold,
				ResetTimeout:       resetTimeout,
				FallbackBufferSize: cfg.Alerting.FallbackBufferSize,
			},
			nil,
			nil, nil, nil,
		)
		slog.Info("alertmanager: webhook integration active",
			slog.String("url", cfg.Alerting.WebhookURL))
	}

	// ── Notification fanout (Slack / Teams / Webhook / OTLP / Kafka / Syslog) ─
	var fanout *exporter.FanoutNotifier
	notifEnabled := cfg.Notifications.Slack.Enabled ||
		cfg.Notifications.Teams.Enabled ||
		cfg.Notifications.Webhook.Enabled ||
		cfg.Notifications.OTLP.Enabled ||
		cfg.Notifications.Kafka.Enabled ||
		cfg.Notifications.SyslogCEF.Enabled
	if notifEnabled {
		fanout = exporter.NewFanoutNotifier(exporter.FanoutConfig{
			Slack: exporter.SlackConfig{
				Enabled:     cfg.Notifications.Slack.Enabled,
				WebhookURL:  cfg.Notifications.Slack.WebhookURL,
				Channel:     cfg.Notifications.Slack.Channel,
				MinSeverity: cfg.Notifications.Slack.MinSeverity,
			},
			Teams: exporter.TeamsConfig{
				Enabled:     cfg.Notifications.Teams.Enabled,
				WebhookURL:  cfg.Notifications.Teams.WebhookURL,
				MinSeverity: cfg.Notifications.Teams.MinSeverity,
			},
			Webhook: exporter.WebhookConfig{
				Enabled: cfg.Notifications.Webhook.Enabled,
				URL:     cfg.Notifications.Webhook.URL,
				Headers: cfg.Notifications.Webhook.Headers,
			},
			OTLP: exporter.OTLPConfig{
				Enabled:     cfg.Notifications.OTLP.Enabled,
				Endpoint:    cfg.Notifications.OTLP.Endpoint,
				TLSEnabled:  cfg.Notifications.OTLP.TLSEnabled,
				CACert:      cfg.Notifications.OTLP.CACert,
				ClientCert:  cfg.Notifications.OTLP.ClientCert,
				ClientKey:   cfg.Notifications.OTLP.ClientKey,
				Headers:     cfg.Notifications.OTLP.Headers,
				MinSeverity: cfg.Notifications.OTLP.MinSeverity,
			},
			Kafka: exporter.KafkaConfig{
				Enabled:      cfg.Notifications.Kafka.Enabled,
				Brokers:      cfg.Notifications.Kafka.Brokers,
				Topic:        cfg.Notifications.Kafka.Topic,
				Payload:      cfg.Notifications.Kafka.Payload,
				SASLEnabled:  cfg.Notifications.Kafka.SASLEnabled,
				SASLUsername: cfg.Notifications.Kafka.SASLUsername,
				SASLPassword: cfg.Notifications.Kafka.SASLPassword,
				TLSEnabled:   cfg.Notifications.Kafka.TLSEnabled,
				CACert:       cfg.Notifications.Kafka.CACert,
				ClientCert:   cfg.Notifications.Kafka.ClientCert,
				ClientKey:    cfg.Notifications.Kafka.ClientKey,
				MinSeverity:  cfg.Notifications.Kafka.MinSeverity,
			},
			SyslogCEF: exporter.SyslogCEFConfig{
				Enabled:     cfg.Notifications.SyslogCEF.Enabled,
				Network:     cfg.Notifications.SyslogCEF.Network,
				Address:     cfg.Notifications.SyslogCEF.Address,
				Format:      cfg.Notifications.SyslogCEF.Format,
				AppName:     cfg.Notifications.SyslogCEF.AppName,
				Facility:    cfg.Notifications.SyslogCEF.Facility,
				CACert:      cfg.Notifications.SyslogCEF.CACert,
				ClientCert:  cfg.Notifications.SyslogCEF.ClientCert,
				ClientKey:   cfg.Notifications.SyslogCEF.ClientKey,
				MinSeverity: cfg.Notifications.SyslogCEF.MinSeverity,
			},
			FalcoOutput: cfg.Compat.FalcoOutput,
		}, 10*time.Second, slog.Default())
	}

	// ── Shutdown duration metric ─────────────────────────────────────────────
	shutdownDuration := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_shutdown_duration_seconds",
		Help: "Duration of the last graceful shutdown in seconds.",
	})
	if err := prometheus.Register(shutdownDuration); err != nil {
		slog.Warn("shutdown metric: failed to register",
			slog.Any("error", err))
	}

	// Determine event queue depth: prefer the explicit BPF config, fall back to
	// the correlator buffer size so existing deployments keep the same behaviour.
	eventQueueDepth := cfg.BPF.EventQueueDepth
	if eventQueueDepth <= 0 {
		eventQueueDepth = engineCfg.BufferSize
	}
	eventCh := make(chan types.Event, eventQueueDepth)
	engine.SetQueueDepthFn(func() int { return len(eventCh) }, func() int { return cap(eventCh) })
	exporter.RecordQueueDepth(0, eventQueueDepth)

	// Determine overflow policy: BPF config takes precedence over the collector
	// backpressure_strategy for the worker-pool overflow path.
	overflowPolicy := cfg.BPF.OverflowPolicy
	bpStrategy := collector.BackpressureStrategy(cfg.Collectors.BackpressureStrategy)
	if overflowPolicy == "" {
		overflowPolicy = string(bpStrategy)
	}
	if bpStrategy == "" {
		bpStrategy = collector.StrategyDrop
	}

	// Bounded worker pool: cap concurrent event-processing goroutines.
	maxConcurrent := int64(cfg.BPF.MaxConcurrentEvents)
	if maxConcurrent <= 0 {
		maxConcurrent = 4096
	}
	workerSem := semaphore.NewWeighted(maxConcurrent)

	slog.Info("event pipeline configured",
		slog.Int("queue_depth", eventQueueDepth),
		slog.Int64("max_concurrent_events", maxConcurrent),
		slog.String("overflow_policy", overflowPolicy))

	var collectors []collector.Collector
	if dryRun {
		slog.Info("dry-run mode: using synthetic event generator")
		collectors = []collector.Collector{
			collector.NewSyntheticCollector(slog.Default(), 100*time.Millisecond),
		}
	}

	// Wire up cloud audit collectors regardless of dry-run mode.
	if cfg.Collectors.CloudTrail.Enabled {
		ct := collector.NewCloudTrailCollector(slog.Default(), cfg.Collectors.CloudTrail, bpStrategy)
		collectors = append(collectors, ct)
		slog.Info("cloudtrail: collector enabled",
			slog.String("queue", cfg.Collectors.CloudTrail.SQSQueueURL))
	}
	if cfg.Collectors.GCPAudit.Enabled {
		gcp := collector.NewGCPAuditCollector(slog.Default(), cfg.Collectors.GCPAudit, bpStrategy)
		collectors = append(collectors, gcp)
		slog.Info("gcp_audit: collector enabled",
			slog.String("subscription", cfg.Collectors.GCPAudit.PubSubSubscription))
	}

	// Build the required-collector set from config and tell the HTTP server.
	requiredSet := make(map[string]bool, len(cfg.Collectors.Required))
	for _, name := range cfg.Collectors.Required {
		requiredSet[name] = true
	}
	if len(cfg.Collectors.Required) > 0 {
		srv.SetRequiredCollectors(cfg.Collectors.Required)
	}

	// startupErrCh carries the first error from each collector that exits before
	// the context is cancelled — used for fail-closed detection.
	startupErrCh := make(chan struct {
		name string
		err  error
	}, len(collectors))

	for _, c := range collectors {
		exporter.SetCollectorUp(c.Name(), true)
		srv.SetCollectorStatus(exporter.CollectorStatus{Name: c.Name(), Healthy: true})
		go func(c collector.Collector) {
			if err := c.Start(ctx, eventCh); err != nil && ctx.Err() == nil {
				slog.Error("collector error", slog.String("name", c.Name()), slog.Any("error", err))
				exporter.SetCollectorUp(c.Name(), false)
				srv.SetCollectorStatus(exporter.CollectorStatus{Name: c.Name(), Healthy: false, Error: err.Error()})
				startupErrCh <- struct {
					name string
					err  error
				}{c.Name(), err}
			}
		}(c)
	}

	// fail-closed: if a required collector fails before the context is done, abort.
	if cfg.Collectors.StartupPolicy == "fail-closed" && len(requiredSet) > 0 {
		go func() {
			for se := range startupErrCh {
				if requiredSet[se.name] {
					slog.Error("fail-closed: required collector failed, aborting",
						slog.String("collector", se.name),
						slog.Any("error", se.err))
					srv.SetBPFAttached(false)
					cancel()
				}
			}
		}()
	}

	if cfg.Rules.HotReload {
		cfgManager.OnChange(func(newCfg *config.Config) {
			oldRules := engine.GetRules()
			oldCount := len(oldRules)

			// Phase 1: parse and fully validate in isolation — no swap yet.
			t0 := time.Now()
			newRules, err := correlator.LoadRulesFromFile(newCfg.Rules.Path)
			engine.ObserveYAMLParseDuration(time.Since(t0))
			if err != nil {
				slog.Error("hot-reload aborted: validation failed",
					slog.Any("error", err),
					slog.Int("old_count", oldCount))
				engine.RecordReloadFailure()
				return
			}
			if err := correlator.ValidateFull(newRules); err != nil {
				slog.Error("hot-reload aborted: full validation failed",
					slog.Any("error", err),
					slog.Int("old_count", oldCount))
				engine.RecordReloadFailure()
				return
			}

			// Phase 2: atomic swap — only reached after full validation.
			engine.ReloadRules(newRules)
			slog.Info("hot-reload applied",
				slog.Int("rules_count", len(newRules)),
				slog.Int("old_count", oldCount))

			if rulesAuditLog != nil {
				if logErr := rulesAuditLog.LogRulesReloaded(
					"fsnotify",
					newCfg.Rules.Path,
					ruleIDsFrom(oldRules),
					ruleIDsFrom(newRules),
				); logErr != nil {
					slog.Warn("audit log: failed to write rules_reloaded entry", slog.Any("error", logErr))
				}
				if logErr := rulesAuditLog.LogConfigReloaded(newCfg.Rules.Path); logErr != nil {
					slog.Warn("audit log: failed to write config_reloaded entry", slog.Any("error", logErr))
				}
			}
		})
		if err := cfgManager.Watch(); err != nil {
			slog.Warn("hot-reload watch failed", slog.Any("error", err))
		}
	}

	// Start canary periodic verification loop (issue #115).
	if canaryManager != nil {
		canaryAlertFn := func(a types.Alert) {
			if err := alertStore.StoreBatch(ctx, []types.Alert{a}); err != nil {
				slog.Warn("canary: store tamper alert error", slog.Any("error", err))
			}
			if alertmanagerClient != nil {
				alertmanagerClient.SendAlert(ctx, a)
			}
			if fanout != nil {
				fanout.Send(ctx, a)
			}
		}
		if err := canaryManager.Start(ctx, canaryAlertFn); err != nil {
			slog.Warn("canary: failed to start verification loop", slog.Any("error", err))
		}
	}

	srv.SetReady(true)
	srv.SetBPFAttached(!dryRun)
	slog.Info("ebpf-guard ready", slog.String("addr", cfg.Server.BindAddress))

	// ── Simulate mode setup ──────────────────────────────────────────────────
	var simCollector *simulate.Collector
	if simulateMode {
		simCollector = simulate.NewCollector()
		fmt.Fprintln(os.Stderr, "ebpf-guard: SIMULATE mode — enforcement actions will be counted, not executed")
		if simulateDuration != "" {
			d, err := time.ParseDuration(simulateDuration)
			if err != nil {
				return fmt.Errorf("invalid --simulate-duration: %w", err)
			}
			go func() {
				select {
				case <-time.After(d):
					slog.Info("simulate: duration elapsed, stopping")
					cancel()
				case <-ctx.Done():
				}
			}()
		}
	}

	// ── Container runtime enricher (issue #123) ─────────────────────────────
	// Works on non-Kubernetes hosts and complements the K8s enricher.
	var runtimeEnricher *runtime.Enricher
	if cfg.Runtime.Enrichment != "" && cfg.Runtime.Enrichment != "off" {
		cacheTTL, _ := time.ParseDuration(cfg.Runtime.CacheTTL)
		reCfg := runtime.EnricherConfig{
			Mode:       cfg.Runtime.Enrichment,
			SocketPath: cfg.Runtime.SocketPath,
			CacheTTL:   cacheTTL,
			Metrics: runtime.EnricherMetrics{
				CacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
					Name: "ebpf_guard_runtime_cache_size",
					Help: "Number of container entries in the runtime enrichment cache.",
				}),
				MissTotal: prometheus.NewCounter(prometheus.CounterOpts{
					Name: "ebpf_guard_runtime_enrichment_misses_total",
					Help: "Total enrichment lookups that found no container metadata.",
				}),
			},
		}
		if re, reErr := runtime.NewEnricher(reCfg, slog.Default()); reErr != nil {
			slog.Warn("runtime enricher: unavailable, container metadata will not be added",
				slog.String("mode", cfg.Runtime.Enrichment),
				slog.Any("error", reErr))
		} else {
			runtimeEnricher = re
			runtimeEnricher.Start(ctx)
			defer func() { _ = runtimeEnricher.Stop() }()
			slog.Info("runtime enricher active",
				slog.String("source", runtimeEnricher.Source()))
		}
	}

	// Container drift detector — enabled when containers use K8s enrichment.
	driftDetector := drift.NewDetector(drift.DetectorConfig{
		BaselineWindow: 5 * time.Minute,
		Logger:         slog.Default(),
	})
	var driftSeq atomic.Uint64

	// Background: refresh queue depth gauge every second.
	var activeWorkers atomic.Int64
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				exporter.RecordQueueDepth(len(eventCh), cap(eventCh))
				exporter.SetGoroutinePoolActive(activeWorkers.Load())
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// Wait for all in-flight dispatch goroutines to finish before shutdown.
			if aerr := workerSem.Acquire(ctx, maxConcurrent); aerr != nil {
				slog.Debug("shutdown: worker pool drain interrupted", slog.Any("error", aerr))
			}
			gracefulShutdown(engine, collectors, alertStore, srv, enf, simCollector, alertmanagerClient, fanout, shutdownDuration,
				cfg.Server.ShutdownTimeout, cfg.Server.ShutdownDrainEnforcement, cfg.Server.ShutdownDrainRego)
			return nil

		case event, ok := <-eventCh:
			if !ok {
				return nil
			}
			if eventLog != nil {
				if wErr := eventLog.Write(event); wErr != nil {
					slog.Debug("event log: write error", slog.Any("error", wErr))
				}
			}

			// Enrich with container runtime metadata before rule evaluation so
			// conditions on container fields (name, image) can match.
			if runtimeEnricher != nil {
				runtimeEnricher.EnrichEvent(&event)
			}

			// engine.Ingest is single-goroutine safe; call it here before dispatch.
			alerts := engine.Ingest(ctx, event)

			// Run container drift detection alongside the rule engine.
			driftAlerts := driftDetector.Ingest(event)
			for _, da := range driftAlerts {
				seq := driftSeq.Add(1)
				alerts = append(alerts, drift.DriftAlertToTypes(da, seq))
			}

			if len(alerts) == 0 {
				continue
			}

			// Dispatch alert I/O (store + forward) in a bounded goroutine pool to
			// prevent unbounded goroutine growth under burst alert rates.
			if !workerSem.TryAcquire(1) {
				// Pool is saturated; drop this dispatch and record the overflow.
				exporter.RecordQueueOverflow()
				continue
			}
			n := activeWorkers.Add(1)
			exporter.SetGoroutinePoolActive(n)

			go func(dispatched []types.Alert) {
				defer func() {
					workerSem.Release(1)
					exporter.SetGoroutinePoolActive(activeWorkers.Add(-1))
				}()

				if simCollector != nil {
					for _, a := range dispatched {
						simCollector.Record(a)
					}
				}
				if err := alertStore.StoreBatch(ctx, dispatched); err != nil {
					slog.Warn("store alerts error", slog.Any("error", err))
				}
				// Forward alerts to Alertmanager webhook if configured.
				if alertmanagerClient != nil {
					for _, a := range dispatched {
						alertmanagerClient.SendAlert(ctx, a)
					}
				}
				// Fan out to Slack / Teams / webhook notifiers if configured.
				if fanout != nil {
					for _, a := range dispatched {
						fanout.Send(ctx, a)
					}
				}
				// Feature F: broadcast critical alerts to peer nodes (cross-node
				// alert amplification) and extract IOCs for gossip sharing.
				if gossipMgr != nil {
					for _, a := range dispatched {
						gossipMgr.BroadcastAlert(a)
						gossipMgr.ExtractFromAlert(a)
					}
				}
			}(alerts)
		}
	}
}

// gracefulShutdown orchestrates an ordered, time-bounded shutdown sequence:
//  1. Stop BPF collectors so no new events enter the pipeline.
//  2. Drain enforcement queue (up to 5 s) — let in-flight kill/block tasks finish.
//  3. Drain the correlation engine's async Rego evaluation queue.
//  4. Flush pending alerts from the correlation engine into the store.
//  5. Flush the alert store (WAL checkpoint for SQLite).
//  6. Flush pending Alertmanager webhook deliveries.
//  7. Cleanup nftables/iptables chains left by the enforcer (if active).
//  8. Shutdown the HTTP server.
//
// The entire procedure is bounded by a 30-second context.
func gracefulShutdown(
	engine *correlator.CorrelationEngine,
	collectors []collector.Collector,
	alertStore store.AlertStore,
	srv *exporter.Server,
	enf *enforcer.Enforcer,
	simCollector *simulate.Collector,
	alertmanagerClient *exporter.AlertmanagerClient,
	fanout *exporter.FanoutNotifier,
	shutdownDuration prometheus.Gauge,
	totalTimeout, drainEnforcementTimeout, drainRegoTimeout time.Duration,
) {
	if totalTimeout <= 0 {
		totalTimeout = 30 * time.Second
	}
	if drainEnforcementTimeout <= 0 {
		drainEnforcementTimeout = 5 * time.Second
	}
	if drainRegoTimeout <= 0 {
		drainRegoTimeout = 5 * time.Second
	}

	start := time.Now()
	slog.Info("graceful shutdown: starting", slog.String("budget", totalTimeout.String()))

	// Signal Kubernetes to stop routing traffic immediately so no new requests
	// arrive during drain. Must happen before any blocking drain steps.
	srv.SetReady(false)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), totalTimeout)
	defer shutdownCancel()

	// Print simulation report before anything else so it's always visible.
	if simCollector != nil {
		simCollector.PrintReport(os.Stdout)
	}

	// Step 1: close BPF ring-buffer readers to stop new events from entering
	// the pipeline. This must happen before draining queues downstream.
	slog.Info("graceful shutdown: stopping BPF collectors")
	for _, c := range collectors {
		if err := c.Close(); err != nil {
			slog.Warn("graceful shutdown: collector close error",
				slog.String("name", c.Name()), slog.Any("error", err))
		}
	}

	// Step 2: drain the enforcement worker queue so in-flight kill/block/throttle
	// tasks are not abandoned mid-execution.
	drainCtx, drainCancel := context.WithTimeout(shutdownCtx, drainEnforcementTimeout)
	slog.Info("graceful shutdown: draining enforcement queue")
	engine.DrainEnforceQueue(drainCtx)
	drainCancel()

	// Step 3: drain async Rego evaluation workers so every alert that was
	// submitted for OPA enrichment lands in the engine's pending buffer.
	regoCtx, regoCancel := context.WithTimeout(shutdownCtx, drainRegoTimeout)
	slog.Info("graceful shutdown: draining Rego evaluation queue")
	if err := engine.Drain(regoCtx); err != nil {
		slog.Warn("graceful shutdown: Rego drain timeout, some enrichments may be missing",
			slog.Any("error", err))
	}
	regoCancel()

	// Step 4: flush any pending alerts buffered in the correlation engine.
	slog.Info("graceful shutdown: flushing pending alerts")
	if pending := engine.Flush(); len(pending) > 0 {
		if err := alertStore.StoreBatch(shutdownCtx, pending); err != nil {
			slog.Warn("graceful shutdown: failed to flush pending alerts",
				slog.Int("count", len(pending)), slog.Any("error", err))
		} else {
			slog.Info("graceful shutdown: pending alerts flushed", slog.Int("count", len(pending)))
		}
		// Also forward flushed alerts to alertmanager and notifiers.
		if alertmanagerClient != nil {
			for _, a := range pending {
				alertmanagerClient.SendAlert(shutdownCtx, a)
			}
		}
		if fanout != nil {
			for _, a := range pending {
				fanout.Send(shutdownCtx, a)
			}
		}
	}

	// Step 5: flush the alert store (SQLite WAL checkpoint; no-op for other backends).
	slog.Info("graceful shutdown: flushing alert store")
	if err := alertStore.Flush(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown: alert store flush error", slog.Any("error", err))
	}

	// Step 6: flush pending Alertmanager webhook deliveries and wait for all
	// in-flight HTTP sends to complete.
	if alertmanagerClient != nil {
		slog.Info("graceful shutdown: flushing Alertmanager webhook")
		if err := alertmanagerClient.FlushContext(shutdownCtx); err != nil {
			slog.Warn("graceful shutdown: Alertmanager flush timeout",
				slog.Any("error", err))
		}
	}

	// Close the notification fanout so each backend can drain any internal buffers.
	if fanout != nil {
		slog.Info("graceful shutdown: closing notification fanout")
		if err := fanout.Close(); err != nil {
			slog.Warn("graceful shutdown: fanout close error", slog.Any("error", err))
		}
	}

	engine.Close()

	// Step 7: remove nftables/iptables rules the enforcer installed.
	if enf != nil {
		slog.Info("graceful shutdown: cleaning up enforcement chains")
		if err := enf.Cleanup(); err != nil {
			slog.Warn("graceful shutdown: enforcement cleanup error", slog.Any("error", err))
		}
		if err := enf.Close(); err != nil {
			slog.Warn("graceful shutdown: enforcer close error", slog.Any("error", err))
		}
	}

	// Step 8: drain the HTTP server.
	slog.Info("graceful shutdown: shutting down HTTP server")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown: HTTP server shutdown error", slog.Any("error", err))
	}

	elapsed := time.Since(start)
	if shutdownDuration != nil {
		shutdownDuration.Set(elapsed.Seconds())
	}
	slog.Info("graceful shutdown: complete", slog.Duration("elapsed", elapsed))
}

func setupLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
}

func generateToken() string {
	b := make([]byte, 16)
	// Use /dev/urandom directly — crypto/rand pulls in more dependencies.
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return "insecure-fallback-change-me"
	}
	defer f.Close()
	if _, err := f.Read(b); err != nil {
		return "insecure-fallback-change-me"
	}
	return fmt.Sprintf("%x", b)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("ebpf-guard %s (commit %s", Version, Commit)
			if BuildTime != "" {
				fmt.Printf(", built %s", BuildTime)
			}
			fmt.Println(")")
		},
	}
}

func newAlertsCmd(cfgPath *string) *cobra.Command {
	var (
		limit    int
		severity string
		since    string
	)

	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Query stored alerts",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfgManager, err := config.NewManagerSkipPermCheck(*cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			cfg := cfgManager.Get()

			st, err := store.New(store.Config{
				Backend: cfg.Store.Backend,
				SQLite:  store.SQLiteConfig{Path: cfg.Store.SQLite.Path, MaxOpenConns: 1},
			})
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer st.Close()

			filters := store.QueryFilters{Limit: limit}
			if severity != "" {
				filters.Severity = []types.Severity{types.Severity(severity)}
			}
			if since != "" {
				d, err := time.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("invalid --since duration: %w", err)
				}
				filters.Since = time.Now().Add(-d)
			}

			alerts, err := st.Query(context.Background(), filters)
			if err != nil {
				return fmt.Errorf("query alerts: %w", err)
			}

			if len(alerts) == 0 {
				fmt.Println("no alerts found")
				return nil
			}
			for _, a := range alerts {
				fmt.Printf("[%s] %s rule=%s pid=%d comm=%s\n",
					a.Severity, a.Timestamp.Format(time.RFC3339), a.RuleID, a.PID, a.Comm)
				if a.Message != "" {
					fmt.Printf("  %s\n", a.Message)
				}
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of alerts to return")
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity (warning, critical)")
	cmd.Flags().StringVar(&since, "since", "", "only show alerts within this duration (e.g. 1h, 30m)")
	return cmd
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show agent status",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("Use 'GET /health' on the running agent for live status.")
		},
	}
}

func newRulesCmd(cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List loaded detection rules",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfgManager, err := config.NewManagerSkipPermCheck(*cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			cfg := cfgManager.Get()

			rules, err := correlator.LoadRulesFromFile(cfg.Rules.Path)
			if err != nil {
				return fmt.Errorf("load rules: %w", err)
			}

			fmt.Printf("loaded %d rules from %s\n\n", len(rules), cfg.Rules.Path)
			for _, r := range rules {
				fmt.Printf("  %-20s  %-8s  action=%-10s  type=%d\n",
					r.ID, r.Severity, r.Action, r.EventType)
			}
			return nil
		},
	}
	cmd.AddCommand(newWizardCmd())
	cmd.AddCommand(newRulesImportCmd())
	return cmd
}

// newRulesImportCmd returns the "rules import" subcommand that converts rules
// from other formats (currently Sigma) into ebpf-guard YAML.
//
// Usage:
//
//	ebpf-guard rules import --format sigma ./sigma-rules/ --out ./rules/imported/
//	ebpf-guard rules import --format sigma rule.yml --out ./rules/imported/ --dry-run
func newRulesImportCmd() *cobra.Command {
	var (
		format string
		source string
		dirArg string
		outDir string
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "import [PATH]",
		Short: "Import detection rules from external formats (sigma)",
		Long: `import converts rules from other security formats into ebpf-guard YAML.

Supported formats:
  sigma   Sigma open-standard detection rules (https://sigmahq.io)

The input PATH may be a single .yaml/.yml file or a directory. For directories,
all .yaml/.yml files found directly in the directory are processed.
Alternatively, use --dir for the input directory and --source for the format.

Unknown Sigma fields are skipped with a WARN log; the rule is still imported
if at least one condition could be mapped. Fully unsupported rules are counted
separately and never written to the output file.

Examples:
  ebpf-guard rules import --format sigma ./sigma-rules/ --out rules/imported/
  ebpf-guard rules import --source sigma --dir ./sigma-rules/ --out rules/imported/
  ebpf-guard rules import --format sigma rule.yml --dry-run`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(_ *cobra.Command, args []string) error {
			// Resolve format: --source takes precedence over --format.
			if source != "" {
				format = source
			}
			if format == "" {
				return fmt.Errorf("--format or --source is required (e.g. --source sigma)")
			}

			// Resolve input path: --dir flag or positional argument.
			var inputPath string
			switch {
			case dirArg != "":
				inputPath = dirArg
			case len(args) == 1:
				inputPath = args[0]
			default:
				return fmt.Errorf("input path is required — provide as positional argument or via --dir")
			}

			if !strings.EqualFold(format, "sigma") {
				return fmt.Errorf("unsupported format %q — only 'sigma' is currently supported", format)
			}

			imp := migration.NewSigmaImporter()

			info, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("stat input path: %w", err)
			}

			var result *migration.SigmaImportResult
			if info.IsDir() {
				result, err = imp.ImportDir(inputPath)
			} else {
				result, err = imp.ImportFile(inputPath)
			}
			if err != nil {
				return fmt.Errorf("import sigma rules: %w", err)
			}

			fmt.Printf("Sigma import summary:\n")
			fmt.Printf("  Converted:   %d\n", result.Converted)
			fmt.Printf("  Unsupported: %d\n", result.Unsupported)
			fmt.Printf("  Disabled:    %d\n\n", result.Disabled)

			for _, r := range result.Results {
				switch r.Status {
				case "converted":
					fmt.Printf("  [OK]   %s\n", r.SourceRule)
				case "unsupported":
					fmt.Printf("  [SKIP] %s\n", r.SourceRule)
					for _, reason := range r.UnsupportedReasons {
						fmt.Printf("         - %s\n", reason)
					}
				case "disabled":
					fmt.Printf("  [OFF]  %s\n", r.SourceRule)
				}
			}

			out, err := imp.WriteOutput(result)
			if err != nil {
				return fmt.Errorf("serialize output: %w", err)
			}

			if dryRun {
				fmt.Printf("\n-- dry-run: not writing files --\n\n%s\n", string(out))
				return nil
			}

			if result.Converted == 0 {
				fmt.Printf("\nNo rules were converted.\n")
				return nil
			}

			if err := os.MkdirAll(outDir, 0o750); err != nil {
				return fmt.Errorf("create output dir: %w", err)
			}
			outPath := filepath.Join(outDir, "sigma-imported.yaml")
			if err := os.WriteFile(outPath, out, 0o640); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
			fmt.Printf("\nWritten %d rule(s) to %s\n", result.Converted, outPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "", "source format (sigma); alias: --source")
	cmd.Flags().StringVar(&source, "source", "", "source format (sigma); alias: --format")
	cmd.Flags().StringVar(&dirArg, "dir", "", "input directory containing source rule files (alternative to positional PATH)")
	cmd.Flags().StringVar(&outDir, "out", "rules/imported", "output directory for converted rules")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print generated YAML without writing files")
	return cmd
}

// newWizardCmd returns the "rules wizard" subcommand.
func newWizardCmd() *cobra.Command {
	var outputDir string

	cmd := &cobra.Command{
		Use:   "wizard",
		Short: "Interactively build a detection rule with a step-by-step TUI",
		Long: `wizard walks you through a series of questions and generates a
ready-to-use YAML rule that you can drop into your rules directory.

Examples:
  ebpf-guard rules wizard
  ebpf-guard rules wizard --output rules/custom/`,
		RunE: func(_ *cobra.Command, _ []string) error {
			yaml, err := tui.RunWizard()
			if err != nil {
				return fmt.Errorf("wizard: %w", err)
			}
			if yaml == "" {
				fmt.Println("Wizard cancelled — no rule generated.")
				return nil
			}

			if outputDir != "" {
				if err := os.MkdirAll(outputDir, 0o750); err != nil {
					return fmt.Errorf("create output dir: %w", err)
				}
				fname := filepath.Join(outputDir, "wizard-rule.yaml")
				if err := os.WriteFile(fname, []byte(yaml), 0o640); err != nil {
					return fmt.Errorf("write rule file: %w", err)
				}
				fmt.Printf("Rule saved to %s\n\nAdd it to your rules.path and reload:\n  ebpf-guard rules\n", fname)
			} else {
				fmt.Println("\n── Generated Rule YAML ────────────────────────────────")
				fmt.Println(yaml)
				fmt.Println("────────────────────────────────────────────────────────")
				fmt.Println("\nCopy the YAML above into your rules file, then reload the agent.")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "directory to write the generated rule YAML file")
	return cmd
}

// newRulesTestCmd returns the "rules test" subcommand that replays historical
// events from the event log through a rule and reports how many alerts would fire.
//
// Usage:
//
//	ebpf-guard rules test --rule my-rule.yaml --replay 24h
//	ebpf-guard rules test --rule rules/cryptominer.yaml --replay 1h --limit 50
func newRulesTestCmd(cfgPath *string) *cobra.Command {
	var (
		ruleFile    string
		replayWindow string
		eventsLog   string
		sampleLimit int
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Replay historical events through a rule and count how many alerts would fire",
		Long: `Test a detection rule against the historical event log without touching production.

ebpf-guard writes a JSONL event log when event_log.enabled=true in the config.
This command reads that log, applies your rule, and reports:
  - how many events were replayed
  - how many alerts would have fired (per rule)
  - a sample of the matching alerts

This lets you tune rule thresholds before enabling them in production.

Examples:
  ebpf-guard rules test --rule rules/cryptominer.yaml --replay 24h
  ebpf-guard rules test --rule my-rule.yaml --replay 1h --limit 50
  ebpf-guard rules test --rule rules/dns-threats.yaml --replay 7d --events-log /var/lib/ebpf-guard/events.jsonl`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ruleFile == "" {
				return fmt.Errorf("--rule is required")
			}

			window, err := time.ParseDuration(replayWindow)
			if err != nil {
				return fmt.Errorf("invalid --replay %q: %w (use e.g. 24h, 1h, 7d)", replayWindow, err)
			}

			// Resolve event log path: flag > config default.
			logPath := eventsLog
			if logPath == "" {
				cfgManager, cfgErr := config.NewManagerSkipPermCheck(*cfgPath)
				if cfgErr == nil {
					logPath = cfgManager.Get().EventLog.Path
				}
				if logPath == "" {
					logPath = "/var/lib/ebpf-guard/events.jsonl"
				}
			}

			rules, err := correlator.LoadRulesFromFile(ruleFile)
			if err != nil {
				return fmt.Errorf("load rule file %s: %w", ruleFile, err)
			}
			fmt.Printf("Loaded %d rule(s) from %s\n", len(rules), ruleFile)

			since := time.Now().Add(-window)
			fmt.Printf("Reading events since %s from %s…\n\n", since.Format(time.RFC3339), logPath)

			events, err := store.ReadEventsSince(logPath, since)
			if err != nil {
				return fmt.Errorf("read event log: %w", err)
			}

			engine := correlator.NewRuleEngine(rules)
			result := correlator.Replay(cmd.Context(), engine, events, window, logPath, sampleLimit)
			fmt.Print(result.PrintSummary())
			return nil
		},
	}

	cmd.Flags().StringVar(&ruleFile, "rule", "", "path to rule YAML file to test (required)")
	cmd.Flags().StringVar(&replayWindow, "replay", "24h", "time window to replay (e.g. 1h, 24h, 7d)")
	cmd.Flags().StringVar(&eventsLog, "events-log", "", "path to event log (default: from config)")
	cmd.Flags().IntVar(&sampleLimit, "limit", 20, "maximum number of sample alerts to display")
	return cmd
}

// newRulesCheckCmd returns the "rules check" subcommand that runs declarative
// YAML unit tests for detection rules without requiring a real kernel or agent.
//
// Usage:
//
//	ebpf-guard rules check ./tests/rules/
//	ebpf-guard rules check ./tests/rules/ --rules ./rules/
//	ebpf-guard rules check ./tests/rules/ --junit results.xml
//	ebpf-guard rules check ./tests/rules/ --watch
func newRulesCheckCmd() *cobra.Command {
	var (
		rulesDir  string
		junitOut  string
		watchMode bool
	)

	cmd := &cobra.Command{
		Use:   "check [PATH]",
		Short: "Run declarative YAML unit tests for detection rules",
		Long: `check discovers *_test.yaml files under PATH (or the given file), runs each
synthetic event through the rule engine, and reports pass/fail in TAP v13 format.

Each test suite YAML specifies a rules_path pointing to the rule file(s) to load.
You can also supply a global --rules directory that is merged with per-suite rules.

Output is TAP v13 on stdout. Use --junit to additionally write JUnit XML for CI.
Exit code is 0 when all tests pass, 1 when any test fails.

Examples:
  ebpf-guard rules check ./tests/rules/
  ebpf-guard rules check ./tests/rules/ --rules ./rules/
  ebpf-guard rules check ./tests/rules/ --junit results.xml
  ebpf-guard rules check ./tests/rules/process_inject_test.yaml
  ebpf-guard rules check ./tests/rules/ --watch`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			testPath := args[0]

			runner := &ruletest.Runner{RulesDir: rulesDir}

			runOnce := func() (ruletest.Summary, error) {
				tap := ruletest.NewTAPWriter(os.Stdout)
				sum, err := runner.RunPath(testPath, tap)
				if err != nil {
					return sum, err
				}
				fmt.Fprintf(os.Stdout, "\n# %d/%d passed", sum.Passed, sum.Total)
				if sum.Failed > 0 {
					fmt.Fprintf(os.Stdout, ", %d failed", sum.Failed)
				}
				fmt.Fprintln(os.Stdout)
				return sum, nil
			}

			if watchMode {
				watchDirs := []string{testPath}
				if rulesDir != "" {
					watchDirs = append(watchDirs, rulesDir)
				}
				// Run once immediately, then re-run on changes.
				_, _ = runOnce()
				return ruletest.Watch(watchDirs, func() { _, _ = runOnce() })
			}

			// Collect results for optional JUnit output.
			var allResults []ruletest.Result
			if junitOut != "" {
				// Run with result collection via a capturing tap writer.
				var buf strings.Builder
				tap := ruletest.NewTAPWriter(&buf)
				sum, err := runner.RunPath(testPath, tap)
				if err != nil {
					return err
				}
				fmt.Print(buf.String())
				fmt.Fprintf(os.Stdout, "\n# %d/%d passed", sum.Passed, sum.Total)
				if sum.Failed > 0 {
					fmt.Fprintf(os.Stdout, ", %d failed", sum.Failed)
				}
				fmt.Fprintln(os.Stdout)

				// Re-run to collect Result structs for JUnit (runner doesn't expose them directly).
				files, err := ruletest.Discover(testPath)
				if err != nil {
					return err
				}
				for _, f := range files {
					suite, rulesPath, lerr := ruletest.LoadSuite(f)
					if lerr != nil {
						return lerr
					}
					eng, berr := runner.BuildEngine(rulesPath)
					if berr != nil {
						return berr
					}
					allResults = append(allResults, ruletest.RunSuite(suite, eng)...)
				}
				f, ferr := os.Create(junitOut)
				if ferr != nil {
					return fmt.Errorf("create junit file: %w", ferr)
				}
				defer f.Close()
				if err := ruletest.WriteJUnit(f, allResults); err != nil {
					return fmt.Errorf("write junit: %w", err)
				}
				fmt.Fprintf(os.Stderr, "JUnit XML written to %s\n", junitOut)
				if sum.Failed > 0 {
					return fmt.Errorf("%d test(s) failed", sum.Failed)
				}
				return nil
			}

			sum, err := runOnce()
			if err != nil {
				return err
			}
			if sum.Failed > 0 {
				return fmt.Errorf("%d test(s) failed", sum.Failed)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&rulesDir, "rules", "", "directory of rule YAML files to merge with per-suite rules_path")
	cmd.Flags().StringVar(&junitOut, "junit", "", "write JUnit XML results to this file")
	cmd.Flags().BoolVar(&watchMode, "watch", false, "re-run tests on file changes (Ctrl+C to stop)")
	return cmd
}

// newLearnCmd returns the "learn" subcommand that observes container behaviour
// for a fixed duration and exports a minimal YAML rule set plus a seccomp profile.
//
// Usage:
//
//	ebpf-guard learn --duration 5m --output rules/generated/
//	ebpf-guard learn --duration 10m --namespace production --output rules/generated/
//	ebpf-guard learn --duration 5m --dry-run --output /tmp/profile/
func newLearnCmd() *cobra.Command {
	var (
		duration    string
		outputDir   string
		namespace   string
		containerID string
		commFilter  string
		logLevel    string
		dryRun      bool
	)

	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Observe container behaviour and generate a minimal rule profile",
		Long: `learn watches kernel events for --duration, builds an allowlist of observed
syscalls, network peers, and file directories, then writes:

  - autoprofile-<label>-rules.yaml   ebpf-guard allowlist rules
  - autoprofile-<label>-seccomp.json OCI seccomp profile (SCMP_ACT_ERRNO default)

Both files are placed in --output (default: rules/generated/).

Examples:
  ebpf-guard learn --duration 5m
  ebpf-guard learn --duration 10m --namespace production --output /tmp/profiles/
  ebpf-guard learn --duration 5m --comm nginx --dry-run`,
		RunE: func(_ *cobra.Command, _ []string) error {
			setupLogger(logLevel)
			return runLearn(duration, outputDir, namespace, containerID, commFilter, dryRun)
		},
	}

	cmd.Flags().StringVar(&duration, "duration", "5m", "observation window (e.g. 30s, 5m, 1h)")
	cmd.Flags().StringVar(&outputDir, "output", "rules/generated", "directory for generated files")
	cmd.Flags().StringVar(&namespace, "namespace", "", "only observe events in this Kubernetes namespace")
	cmd.Flags().StringVar(&containerID, "container", "", "only observe events from this container ID")
	cmd.Flags().StringVar(&commFilter, "comm", "", "only observe processes whose comm starts with this prefix")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "use synthetic events (no kernel probes required)")
	return cmd
}

func runLearn(durationStr, outputDir, namespace, containerID, commFilter string, dryRun bool) error {
	dur, err := time.ParseDuration(durationStr)
	if err != nil {
		return fmt.Errorf("invalid --duration %q: %w", durationStr, err)
	}
	if dur < time.Second {
		return fmt.Errorf("--duration must be at least 1s")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("ebpf-guard learn: starting",
		slog.Duration("duration", dur),
		slog.String("output", outputDir),
		slog.String("namespace", namespace),
		slog.String("container", containerID),
		slog.String("comm", commFilter),
		slog.Bool("dry_run", dryRun),
	)

	session := autolearn.NewSession(autolearn.SessionConfig{
		Duration:    dur,
		Namespace:   namespace,
		ContainerID: containerID,
		CommFilter:  commFilter,
		Logger:      slog.Default(),
	})

	eventCh := make(chan types.Event, 4096)

	var collectors []collector.Collector
	if dryRun {
		slog.Info("learn: using synthetic event generator")
		collectors = []collector.Collector{
			collector.NewSyntheticCollector(slog.Default(), 50*time.Millisecond),
		}
	}

	for _, c := range collectors {
		go func(c collector.Collector) {
			if err := c.Start(ctx, eventCh); err != nil && ctx.Err() == nil {
				slog.Error("learn: collector error", slog.String("name", c.Name()), slog.Any("error", err))
			}
		}(c)
	}

	fmt.Printf("Observing for %s — press Ctrl+C to stop early and export now.\n\n", dur)
	snap := session.Run(ctx, eventCh)

	for _, c := range collectors {
		_ = c.Close()
	}

	fmt.Println(snap.Summary())

	rulesPath, seccompPath, err := snap.ExportAll(outputDir)
	if err != nil {
		return fmt.Errorf("export profile: %w", err)
	}

	fmt.Printf("\nGenerated files:\n")
	fmt.Printf("  Rules:   %s\n", rulesPath)
	fmt.Printf("  Seccomp: %s\n", seccompPath)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Review and tune the generated rules.\n")
	fmt.Printf("  2. Copy rules to your rules directory and reload with hot-reload or restart.\n")
	fmt.Printf("  3. Apply the seccomp profile to your container runtime.\n")
	return nil
}

// newDashboardCmd returns the "dashboard" subcommand.
// It starts the full agent pipeline (with optional dry-run) and renders a live
// bubbletea TUI showing events, alerts, and rule statistics in real time.
func newDashboardCmd() *cobra.Command {
	var (
		cfgPath  string
		logLevel string
		dryRun   bool
	)

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Interactive live TUI dashboard — events, alerts, rule stats",
		Long: `dashboard starts the agent and renders a live terminal UI showing:

  • Tab 1 – Alerts:     incoming alerts with severity and rule
  • Tab 2 – Events:     raw kernel events (pid, comm, type)
  • Tab 3 – Top Rules:  rules ranked by trigger count with sparkbar
  • Tab 4 – Status:     aggregate counters and top processes

Use --dry-run to run without kernel eBPF probes (synthetic events).

Keybindings:
  Tab / 1-4   switch panel
  j/k or ↑/↓  scroll
  p            pause live updates
  q            quit`,
		RunE: func(_ *cobra.Command, _ []string) error {
			setupLogger(logLevel)
			return runDashboard(cfgPath, dryRun)
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	cmd.Flags().StringVar(&logLevel, "log-level", "warn", "log level (use warn/error to keep TUI clean)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "use synthetic events instead of real eBPF probes")
	return cmd
}

// newConfigCmd returns the "config" parent subcommand with validate/migrate children.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Config file validation and migration tools",
	}
	cmd.AddCommand(newConfigValidateCmd())
	cmd.AddCommand(newConfigMigrateCmd())
	return cmd
}

// newConfigValidateCmd returns the "config validate" subcommand.
func newConfigValidateCmd() *cobra.Command {
	var cfgPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a config file for deprecated or removed fields",
		Long: `validate reads the config file and reports:
  - Deprecated fields that have been renamed in a newer schema version
  - Removed fields that no longer have any effect

Exit code 0 if no issues are found, 1 if issues are detected.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runConfigValidate(cfgPath)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	return cmd
}

// newConfigMigrateCmd returns the "config migrate" subcommand.
func newConfigMigrateCmd() *cobra.Command {
	var (
		cfgPath   string
		targetVer string
		outPath   string
	)

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Auto-migrate a config file to a target schema version",
		Long: `migrate applies known rename and removal transformations and writes a
new config file compatible with the target version.

The original file is not modified. Specify --out to control the output path.
Note: YAML comments are not preserved in the migrated output.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runConfigMigrate(cfgPath, targetVer, outPath)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	cmd.Flags().StringVar(&targetVer, "to", "v0.2.0", "target config schema version")
	cmd.Flags().StringVar(&outPath, "out", "", "output file path (default: <config>.migrated.yaml)")
	return cmd
}

func runConfigValidate(cfgPath string) error {
	// Phase 1: check for deprecated / renamed / removed fields.
	issues, err := config.CheckConfigFile(cfgPath)
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	// Phase 2: full structural validation (store backend, sample_rate bounds, etc.).
	var validationErr error
	if cfgMgr, loadErr := config.NewManagerSkipPermCheck(cfgPath); loadErr != nil {
		validationErr = fmt.Errorf("load config for validation: %w", loadErr)
	} else {
		validationErr = config.ValidateConfig(cfgMgr.Get())
	}

	// Print OK status for all top-level sections with no issues.
	sections := []string{
		"server", "bpf", "rules", "correlator", "profiler",
		"exporter", "alerting", "kubernetes", "auth", "notifications",
		"store", "collectors", "enforcement", "watchdog", "policy",
		"compat", "gossip", "wasm", "osint", "event_log", "canary",
	}
	sectionHasIssue := make(map[string]bool)
	for _, iss := range issues {
		top := strings.SplitN(iss.Field, ".", 2)[0]
		sectionHasIssue[top] = true
	}
	for _, sec := range sections {
		if !sectionHasIssue[sec] {
			fmt.Printf("✓ %s: OK\n", sec)
		}
	}

	for _, iss := range issues {
		fmt.Printf("✗ %s: %s\n", iss.Field, iss.Message)
	}

	totalIssues := len(issues)
	if validationErr != nil {
		fmt.Printf("✗ validation: %s\n", validationErr)
		totalIssues++
	}

	if totalIssues == 0 {
		fmt.Printf("\n0 issues found.\n")
		return nil
	}
	fmt.Printf("\n%d issue(s) found. Run 'ebpf-guard config migrate' to auto-fix.\n", totalIssues)
	return fmt.Errorf("%d issue(s) found", totalIssues)
}

func runConfigMigrate(cfgPath, targetVer, outPath string) error {
	if outPath == "" {
		ext := filepath.Ext(cfgPath)
		base := strings.TrimSuffix(cfgPath, ext)
		outPath = base + ".migrated" + ext
	}
	if err := config.MigrateConfigFile(cfgPath, targetVer, outPath); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	fmt.Printf("Migration complete: %s → %s\n", cfgPath, outPath)
	fmt.Printf("Run 'ebpf-guard config validate --config %s' to verify.\n", outPath)
	return nil
}

func runDashboard(cfgPath string, dryRun bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfgManager, err := config.NewManagerSkipPermCheck(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg := cfgManager.Get()

	rules, _ := correlator.LoadRulesFromFile(cfg.Rules.Path)

	engineCfg := correlator.DefaultCorrelationEngineConfig()
	engineCfg.Rules = rules
	engineCfg.BufferSize = 4096
	engine := correlator.NewCorrelationEngineWithConfig(engineCfg)

	feed := tui.NewFeed()
	eventCh := make(chan types.Event, 4096)

	var collectors []collector.Collector
	if dryRun {
		collectors = []collector.Collector{
			collector.NewSyntheticCollector(slog.Default(), 80*time.Millisecond),
		}
	}

	for _, c := range collectors {
		go func(c collector.Collector) {
			if err := c.Start(ctx, eventCh); err != nil && ctx.Err() == nil {
				slog.Error("dashboard collector error", slog.String("name", c.Name()), slog.Any("error", err))
			}
		}(c)
	}

	// Forward events and alerts to the TUI feed.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-eventCh:
				if !ok {
					return
				}
				feed.PushEvent(event)
				alerts := engine.Ingest(ctx, event)
				for _, a := range alerts {
					feed.PushAlert(a)
				}
			}
		}
	}()

	return tui.Run(ctx, feed)
}

// ruleIDsFrom extracts the ID field from each rule.
func ruleIDsFrom(rules []correlator.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

// newAttackSimCmd returns the "attack-sim" subcommand (issue #124).
//
// Usage:
//
//	ebpf-guard attack-sim                            # list all scenarios
//	ebpf-guard attack-sim --run-all                  # synthetic run against loaded rules
//	ebpf-guard attack-sim --scenario container-escape-ptrace
//	ebpf-guard attack-sim --verify --agent http://localhost:8080 --token TOKEN --timeout 30s
func newAttackSimCmd(cfgPath *string) *cobra.Command {
	var (
		listOnly    bool
		runAll      bool
		scenarioID  string
		verifyMode  bool
		agentAddr   string
		bearerToken string
		timeoutStr  string
	)

	cmd := &cobra.Command{
		Use:   "attack-sim",
		Short: "Simulate attacks and verify detections fire",
		Long: `attack-sim reproduces the behaviors detected by the built-in rule sets using
safe synthetic events — no real malicious payloads, no outbound network traffic.

Modes:
  --list          Print all available scenarios and exit.
  --run-all       Feed every scenario through a local correlation engine loaded
                  from the configured rules file. Reports PASS/FAIL per scenario.
  --scenario ID   Run a single scenario (use --list to see IDs).
  --verify        Poll a live agent's /alerts API after running a scenario and
                  assert the expected rule fired (requires --agent).

Examples:
  ebpf-guard attack-sim --list
  ebpf-guard attack-sim --run-all
  ebpf-guard attack-sim --scenario dga-dns-query
  ebpf-guard attack-sim --scenario sensitive-file-read --verify \
    --agent http://localhost:8080 --token mytoken --timeout 30s`,
		RunE: func(_ *cobra.Command, _ []string) error {
			setupLogger("info")
			runner := attacker.NewRunner(nil, slog.Default())

			if listOnly {
				fmt.Printf("%-40s  %-12s  %s\n", "ID", "MITRE", "Name")
				fmt.Println(strings.Repeat("-", 72))
				for _, s := range runner.Scenarios() {
					fmt.Printf("%-40s  %-12s  %s\n", s.ID, s.MITRETech, s.Name)
				}
				return nil
			}

			cfgManager, err := config.NewManagerSkipPermCheck(*cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			rulesPath := cfgManager.Get().Rules.Path

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			if verifyMode {
				if agentAddr == "" {
					return fmt.Errorf("--verify requires --agent (e.g. --agent http://localhost:8080)")
				}
				if scenarioID == "" {
					return fmt.Errorf("--verify requires --scenario ID")
				}
				timeout := 30 * time.Second
				if timeoutStr != "" {
					timeout, err = time.ParseDuration(timeoutStr)
					if err != nil {
						return fmt.Errorf("invalid --timeout: %w", err)
					}
				}
				result, err := runner.Verify(ctx, scenarioID, agentAddr, bearerToken, timeout)
				if err != nil {
					return fmt.Errorf("verify: %w", err)
				}
				attacker.PrintResults([]attacker.ScenarioResult{result}, os.Stdout)
				if !result.Passed {
					return fmt.Errorf("scenario %q FAILED: missing rules %v", scenarioID, result.Missing)
				}
				return nil
			}

			var results []attacker.ScenarioResult
			if runAll {
				results, err = runner.RunSynthetic(ctx, rulesPath)
				if err != nil {
					return fmt.Errorf("run-all: %w", err)
				}
			} else if scenarioID != "" {
				result, err := runner.RunScenarioSynthetic(ctx, scenarioID, rulesPath)
				if err != nil {
					return err
				}
				results = []attacker.ScenarioResult{result}
			} else {
				// Default: list scenarios.
				fmt.Printf("%-40s  %-12s  %s\n", "ID", "MITRE", "Name")
				fmt.Println(strings.Repeat("-", 72))
				for _, s := range runner.Scenarios() {
					fmt.Printf("%-40s  %-12s  %s\n", s.ID, s.MITRETech, s.Name)
				}
				fmt.Println("\nUse --run-all to test all scenarios, or --scenario ID for one.")
				return nil
			}

			attacker.PrintResults(results, os.Stdout)

			// Return non-zero exit code when any scenario failed.
			for _, r := range results {
				if !r.Passed {
					return fmt.Errorf("one or more scenarios FAILED")
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&listOnly, "list", false, "list all available scenarios and exit")
	cmd.Flags().BoolVar(&runAll, "run-all", false, "run all scenarios through local rule engine")
	cmd.Flags().StringVar(&scenarioID, "scenario", "", "run a single scenario by ID")
	cmd.Flags().BoolVar(&verifyMode, "verify", false, "poll live agent API to confirm alert fired")
	cmd.Flags().StringVar(&agentAddr, "agent", "http://localhost:8080", "agent HTTP address for --verify mode")
	cmd.Flags().StringVar(&bearerToken, "token", "", "bearer token for the agent API")
	cmd.Flags().StringVar(&timeoutStr, "timeout", "30s", "how long to wait for alerts in --verify mode")
	return cmd
}

// newPluginsCmd returns the "plugins" parent command with "validate" as a subcommand.
//
// Usage:
//
//	ebpf-guard plugins validate ./rules/custom/my-plugin.wasm
//	ebpf-guard plugins validate ./rules/custom/ --dry-run
func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage and inspect WASM detection plugins",
	}
	cmd.AddCommand(newPluginsValidateCmd())
	return cmd
}

func newPluginsValidateCmd() *cobra.Command {
	var (
		dryRun     bool
		syntheticN int
	)

	cmd := &cobra.Command{
		Use:   "validate [PATH]",
		Short: "Check WASM plugin ABI compliance and optionally dry-run against synthetic events",
		Long: `validate loads one or more .wasm plugin files, checks their exported ABI symbols,
and reports any missing required or recommended exports.

If --dry-run is set (the default), a small set of synthetic events covering every
event type is fed through each plugin so you can confirm your detector fires.

PATH may be a single .wasm file or a directory of .wasm files.

Examples:
  ebpf-guard plugins validate rules/custom/my-plugin.wasm
  ebpf-guard plugins validate rules/custom/ --dry-run
  ebpf-guard plugins validate rules/custom/ --no-dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			ctx := cmd.Context()
			logger := slog.Default()

			var syntheticEvents []types.Event
			if dryRun {
				syntheticEvents = buildSyntheticEvents(syntheticN)
			}

			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("stat %s: %w", path, err)
			}

			var paths []string
			if info.IsDir() {
				entries, err := os.ReadDir(path)
				if err != nil {
					return fmt.Errorf("readdir %s: %w", path, err)
				}
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(e.Name(), ".wasm") {
						paths = append(paths, filepath.Join(path, e.Name()))
					}
				}
				if len(paths) == 0 {
					fmt.Println("no .wasm files found in", path)
					return nil
				}
			} else {
				paths = []string{path}
			}

			var anyFailed bool
			for _, p := range paths {
				res := wasm.ValidatePlugin(ctx, p, syntheticEvents, logger)
				fmt.Print(wasm.FormatValidationResult(res))
				if !res.OK {
					anyFailed = true
				}
			}

			if anyFailed {
				return fmt.Errorf("one or more plugins failed ABI validation")
			}
			fmt.Printf("\nAll %d plugin(s) passed ABI validation.\n", len(paths))
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", true, "run each plugin against synthetic events after ABI check")
	cmd.Flags().IntVar(&syntheticN, "events", 1, "number of synthetic events per type to generate for dry-run")
	return cmd
}

// buildSyntheticEvents generates one representative event per EventType for dry-run validation.
func buildSyntheticEvents(perType int) []types.Event {
	if perType <= 0 {
		perType = 1
	}
	var comm [16]byte
	copy(comm[:], "test")

	var events []types.Event
	for i := 0; i < perType; i++ {
		events = append(events,
			types.Event{Type: types.EventSyscall, PID: 1, Comm: comm,
				Syscall: &types.SyscallEvent{Nr: 59}},
			types.Event{Type: types.EventTCPConnect, PID: 2, Comm: comm,
				Network: &types.NetworkEvent{Dport: 4444, Family: types.AFInet}},
			types.Event{Type: types.EventFileAccess, PID: 3, Comm: comm,
				File: &types.FileEvent{}},
			types.Event{Type: types.EventDNS, PID: 4, Comm: comm,
				DNS: &types.DNSEvent{QName: "xkzpqwerty.evil.com"}},
			types.Event{Type: types.EventPrivesc, PID: 5, Comm: comm,
				Privesc: &types.PrivescEvent{OldCaps: 0, NewCaps: 1 << 21}},
			types.Event{Type: types.EventKmodLoad, PID: 6, Comm: comm,
				Kmod: &types.KmodEvent{ModName: "evil.ko", FromTmpfs: true}},
		)
	}
	return events
}
