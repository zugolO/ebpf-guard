// Package main is the entry point for the ebpf-guard security agent.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/zugolO/ebpf-guard/internal/attacker"
	"github.com/zugolO/ebpf-guard/internal/audit"
	"github.com/zugolO/ebpf-guard/internal/autolearn"
	internalbpf "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/canary"
	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/drift"
	"github.com/zugolO/ebpf-guard/internal/enforcer"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/gossip"
	"github.com/zugolO/ebpf-guard/internal/hidden"
	"github.com/zugolO/ebpf-guard/internal/k8s"
	"github.com/zugolO/ebpf-guard/internal/migration"
	"github.com/zugolO/ebpf-guard/internal/osint"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
	"github.com/zugolO/ebpf-guard/internal/runtime"
	"github.com/zugolO/ebpf-guard/internal/simple"
	"github.com/zugolO/ebpf-guard/internal/simulate"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/internal/tui"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/internal/wasm"
	"github.com/zugolO/ebpf-guard/internal/watchdog"
	"github.com/zugolO/ebpf-guard/pkg/types"
	rulesembed "github.com/zugolO/ebpf-guard/rules"
	"golang.org/x/sync/semaphore"
)

// Build-time variables set via ldflags. Version is the fallback reported by
// `go run`/`go build` and untagged builds; release builds override it with the
// git tag (see Makefile and .goreleaser.yml).
var (
	Version   = "0.10.0-alpha"
	Commit    = "unknown"
	BuildTime = ""
)

// pendingFlushInterval controls how often the production event loop drains
// alerts the correlation engine buffered via IngestAsync (see engine.Flush).
// Matches the correlator package's internal per-worker local flush cadence so
// alerts don't sit needlessly long on top of that existing batching delay.
const pendingFlushInterval = 100 * time.Millisecond

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		cfgPath          string
		logLevel         string
		dryRun           bool
		simulateMode     bool
		simulateDuration string
		shutdownTimeout  string
		zeroConfig       bool
		enableSimple     bool
	)

	root := &cobra.Command{
		Use:   "ebpf-guard",
		Short: "eBPF-based runtime security agent for Linux/Kubernetes",
		Long: `ebpf-guard attaches eBPF probes to collect kernel events, correlates them
against YAML detection rules, and exports alerts to Prometheus and Alertmanager.`,
		Version:      fmt.Sprintf("%s (commit %s)", Version, Commit),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cfgPath, logLevel, dryRun, simulateMode, simulateDuration, shutdownTimeout, zeroConfig, enableSimple)
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
	root.PersistentFlags().BoolVar(&zeroConfig, "zero-config", false,
		"run without a config file: uses embedded defaults and built-in rules (one-command deployment)")
	root.PersistentFlags().BoolVar(&enableSimple, "simple", false,
		"enable simple mode: auto-kill cryptominers, webshells, and reverse shells with safety rails")

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

func runAgent(cfgPath, logLevel string, dryRun bool, simulateMode bool, simulateDuration, shutdownTimeoutFlag string, zeroConfig bool, enableSimple bool) error {
	setupLogger(logLevel)

	slog.Info("ebpf-guard starting",
		slog.String("version", Version),
		slog.String("commit", Commit),
		slog.Bool("dry_run", dryRun),
		slog.Bool("zero_config", zeroConfig),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Config loading: embedded defaults or config file ──────────────────────
	var cfgManager *config.Manager
	var cfg *config.Config
	var rules []correlator.Rule

	if zeroConfig {
		slog.Info("zero-config mode: using embedded defaults and built-in rules")
		cfgManager = config.NewZeroConfigManager()
		cfg = cfgManager.Get()

		// Load all built-in rules from the embedded filesystem.
		embeddedFiles, embErr := rulesembed.LoadAll()
		if embErr != nil {
			slog.Warn("failed to load embedded rules, starting with empty rule set",
				slog.Any("error", embErr))
		} else {
			var ruleErr error
			rules, ruleErr = correlator.LoadRulesFromEmbedded(embeddedFiles)
			if ruleErr != nil {
				slog.Warn("failed to parse embedded rules, starting with empty rule set",
					slog.Any("error", ruleErr))
				rules = nil
			} else {
				slog.Info("embedded rules loaded",
					slog.Int("count", len(rules)),
					slog.Int("files", len(embeddedFiles)),
				)
			}
		}

		// Print friendly first-run summary.
		printZeroConfigBanner(cfg)
	} else {
		var err error
		cfgManager, err = config.NewManagerSkipPermCheck(cfgPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		cfg = cfgManager.Get()

		// Load rules from file or directory (config defaults to rules/ dir)
		rules, err = loadRules(cfg.Rules.Path)
		if err != nil {
			slog.Warn("failed to load rules file, starting with empty rule set",
				slog.String("path", cfg.Rules.Path),
				slog.Any("error", err))
			rules = nil
		} else {
			slog.Info("rules loaded", slog.Int("count", len(rules)))
		}
	}

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

	// Feature E: hidden process detection via BPF iter/task vs /proc diff.
	var hiddenDetector *hidden.Detector
	if cfg.HiddenProcess.Enabled {
		hiddenDetector = hidden.New(slog.Default(), hidden.Config{
			Enabled:       true,
			CheckInterval: cfg.HiddenProcess.CheckInterval,
			AlertSeverity: cfg.HiddenProcess.AlertSeverity,
		})
		slog.Info("hidden: detector initialised",
			slog.Duration("interval", cfg.HiddenProcess.CheckInterval))
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
		engineCfg.BufferSize = 256
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

	// samplingMux fans BPF-side sampling changes out to the per-collector
	// SamplingControllers. It is shared by the collectors' status reporters
	// (which register each controller as its collector comes up) and the CPU
	// pressure watcher (which adjusts rates under load).
	samplingMux := watchdog.NewMultiBPFController(slog.Default())

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
			Allowlist: profiler.SyscallAllowlistConfig{
				Enabled:         cfg.Profiler.SyscallAllowlist.Enabled,
				Mode:            cfg.Profiler.SyscallAllowlist.Mode,
				EnforcingAction: cfg.Profiler.SyscallAllowlist.EnforcingAction,
				PerWorkload:     cfg.Profiler.SyscallAllowlist.PerWorkload,
				LearningPeriod:  cfg.Profiler.SyscallAllowlist.LearningPeriod,
				MinSamples:      cfg.Profiler.SyscallAllowlist.MinSamples,
				SparseThreshold: cfg.Profiler.SyscallAllowlist.SparseThreshold,
				GlobalAllow:     cfg.Profiler.SyscallAllowlist.GlobalAllow,
				GlobalDeny:      cfg.Profiler.SyscallAllowlist.GlobalDeny,
				PersistPath:     cfg.Profiler.SyscallAllowlist.PersistPath,
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

	// CPU pressure auto-tuning: adaptively shed noisy collectors (file first,
	// then syscall/network) when the agent's own CPU usage exceeds the budget,
	// restoring them once the spike subsides. Independent of the profiler.
	// The construction/registration/start wiring lives in watchdog so it can be
	// unit-tested; here we only map config fields.
	cp := cfg.Watchdog.CPUPressure
	watchdog.SetupCPUPressureWatcher(ctx, watchdog.CPUConfig{
		Enabled:           cp.Enabled,
		CheckInterval:     time.Duration(cp.CheckInterval) * time.Second,
		CPULimitPercent:   cp.CPULimitPercent,
		FileShedThreshold: cp.FileShedThreshold,
		AllShedThreshold:  cp.AllShedThreshold,
		RecoveryThreshold: cp.RecoveryThreshold,
		WindowSize:        cp.WindowSize,
	}, slog.Default(), samplingMux, prometheus.DefaultRegisterer)

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

	// ── OSINT threat-intel feed sync ──────────────────────────────────────────
	// Fetches IoCs from configured MISP/OpenCTI/VirusTotal sources, generates
	// YAML rules into OutputDir (picked up by the hot-reload watcher), and
	// optionally loads IP/CIDR IoCs directly into kernel BPF blocklist maps.
	// Runs behind the osint.enabled flag; graceful no-op if disabled or if
	// kernel maps are unavailable (SyncToKernelMaps requires #179).
	if cfg.OSINT.Enabled {
		osintMgr, osintErr := osint.NewManager(cfg.OSINT)
		if osintErr != nil {
			slog.Warn("osint: failed to initialise manager, OSINT sync disabled",
				slog.Any("error", osintErr))
		} else if osintMgr != nil {
			if cfg.OSINT.SyncToKernelMaps {
				ksCfg := osint.KernelSyncerConfig{
					Updater:    nil, // wired when kernel blocklist maps are available (#179)
					MaxEntries: cfg.OSINT.MaxKernelEntries,
					Registerer: prometheus.DefaultRegisterer,
				}
				if ks, ksErr := osint.NewKernelSyncer(ksCfg); ksErr != nil {
					slog.Warn("osint: kernel syncer init failed, kernel map sync disabled",
						slog.Any("error", ksErr))
				} else {
					osintMgr.WithKernelSyncer(ks)
					slog.Info("osint: kernel map sync enabled (no-op until blocklist maps are available)")
				}
			}
			go func() {
				if err := osintMgr.Run(ctx); err != nil {
					slog.Error("osint: manager exited with error", slog.Any("error", err))
				}
			}()
			slog.Info("osint: feed sync active",
				slog.String("output_dir", cfg.OSINT.OutputDir),
				slog.Bool("kernel_sync", cfg.OSINT.SyncToKernelMaps))
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
	// In simple mode, enforcement and kill are force-enabled regardless of config.
	var enf *enforcer.Enforcer
	forceEnforce := enableSimple || cfg.SimpleMode.Enabled
	if cfg.Enforcement.Enabled || forceEnforce {
		enableKill := cfg.Enforcement.EnableKill || forceEnforce
		enfCfg := enforcer.Config{
			DryRun:                  cfg.Enforcement.DryRun,
			BlockBackend:            enforcer.BlockBackend(cfg.Enforcement.BlockBackend),
			EnableBlock:             cfg.Enforcement.EnableBlock,
			EnableKill:              enableKill,
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
	memRetentionPeriod, _ := time.ParseDuration(cfg.Store.Memory.RetentionPeriod)

	batchFlushInterval, _ := time.ParseDuration(cfg.Store.Batching.FlushInterval)

	alertStore, err := store.NewWithContext(ctx, store.Config{
		Backend: cfg.Store.Backend,
		Memory: store.MemoryStoreOptions{
			MaxAlerts:       cfg.Store.Memory.MaxAlerts,
			RetentionPeriod: memRetentionPeriod,
		},
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
		Batching: store.BatchingStoreConfig{
			BatchSize:     cfg.Store.Batching.BatchSize,
			FlushInterval: batchFlushInterval,
			MaxBuffer:     cfg.Store.Batching.MaxBuffer,
		},
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
			t, err := generateToken()
			if err != nil {
				return fmt.Errorf("auth: generate admin token: %w", err)
			}
			adminToken = t
			slog.Info("auth: generated admin token — save this, it will not be shown again",
				slog.String("token", adminToken))
		}
		if viewerToken == "" && len(cfg.Auth.Tokens) == 0 {
			t, err := generateToken()
			if err != nil {
				return fmt.Errorf("auth: generate viewer token: %w", err)
			}
			viewerToken = t
			slog.Info("auth: generated viewer token — save this, it will not be shown again",
				slog.String("token", viewerToken))
		}
		// Write auto-generated tokens to /run/ebpf-guard/token so operators
		// can retrieve them without restarting the agent with explicit config.
		if err := writeTokenFile(adminToken, viewerToken); err != nil {
			slog.Warn("auth: cannot write token file", "error", err)
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
	srv.SetCORSAllowedOrigins(cfg.Server.CORSAllowedOrigins)
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

	// ── Setup alert explainer ────────────────────────────────────────────────
	// Wired to the REST API so GET /api/v1/alerts/{id}/explain returns
	// human-readable explanations with MITRE ATT&CK mappings.
	// In simple mode, the default style is "plain" for non-security users.
	srv.SetupExplainer("") // Uses embedded default templates (empty dir = fallback to defaults)
	if enableSimple || cfg.SimpleMode.Enabled {
		srv.SetExplainerStyle("plain")
		slog.Info("explainer: plain-language mode active (simple mode)")
	}

	// ── Alertmanager webhook client ──────────────────────────────────────────
	var alertmanagerClient *exporter.AlertmanagerClient
	if cfg.Alerting.Enabled {
		resetTimeout := time.Duration(cfg.Alerting.CircuitBreakerResetTimeout) * time.Second
		if resetTimeout <= 0 {
			resetTimeout = 30 * time.Second
		}
		alertmanagerClient = exporter.NewAlertmanagerClientFullWithOptions(
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
			cfg.Alerting.StrictSSRF,
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
		cfg.Notifications.SyslogCEF.Enabled ||
		cfg.Notifications.Discord.Enabled ||
		cfg.Notifications.Telegram.Enabled ||
		cfg.Notifications.UnixSocket.Enabled
	if notifEnabled {
		var fanoutErr error
		fanout, fanoutErr = exporter.NewFanoutNotifier(exporter.FanoutConfig{
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
			Discord: exporter.DiscordConfig{
				Enabled:     cfg.Notifications.Discord.Enabled,
				WebhookURL:  cfg.Notifications.Discord.WebhookURL,
				MinSeverity: cfg.Notifications.Discord.MinSeverity,
			},
			Telegram: exporter.TelegramConfig{
				Enabled:     cfg.Notifications.Telegram.Enabled,
				BotToken:    cfg.Notifications.Telegram.BotToken,
				ChatID:      cfg.Notifications.Telegram.ChatID,
				MinSeverity: cfg.Notifications.Telegram.MinSeverity,
			},
			UnixSocket: exporter.UnixSocketConfig{
				Enabled: cfg.Notifications.UnixSocket.Enabled,
				Path:    cfg.Notifications.UnixSocket.Path,
			},
			FalcoOutput: cfg.Compat.FalcoOutput,
			StrictSSRF:  cfg.Notifications.StrictSSRF,
		}, 10*time.Second, slog.Default())
		if fanoutErr != nil {
			return fmt.Errorf("notifications: %w", fanoutErr)
		}
	}

	// ── Simple mode: auto-enforce for indie developers ─────────────────────
	var simpleEngine *simple.Mode
	if enableSimple || cfg.SimpleMode.Enabled {
		scfg := simple.Config{
			Enabled:           true,
			DryRun:            cfg.SimpleMode.DryRun,
			DryRunDuration:    parseDuration(cfg.SimpleMode.DryRunDuration, 24*time.Hour),
			MaxKillsPerMinute: cfg.SimpleMode.MaxKillsPerMinute,
			AllowlistPIDs:     cfg.SimpleMode.AllowlistPIDs,
			AllowlistComms:    cfg.SimpleMode.AllowlistComms,
		}
		simpleEngine = simple.New(scfg, slog.Default())
		slog.Info("simple mode: auto-enforcement enabled",
			slog.Bool("dry_run", simpleEngine.IsDryRun()),
			slog.Int("max_kills_per_minute", scfg.MaxKillsPerMinute))
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
	} else {
		// Core eBPF ring-buffer collectors.
		if sc, scErr := collector.NewSyscallCollector(slog.Default()); scErr != nil {
			slog.Warn("syscall: collector creation failed", slog.Any("error", scErr))
		} else {
			sc.WithStatusReporter(collector.StatusReporterFunc(func(name string, up bool) {
				if name != "syscall" || !up {
					return
				}
				if cfg.BPF.KernelFilter.Enabled {
					enableKernelFilter(sc, cfg.BPF.KernelFilter)
				}
				if cfg.BPF.Sampling.Enabled {
					enableSampling("syscall", sc.SamplingConfigMap(), cfg.BPF.Sampling, samplingMux, "syscall")
				}
			}))
			collectors = append(collectors, sc.WithBackpressureStrategy(bpStrategy))
			slog.Info("syscall: collector enabled")
		}

		if nc, ncErr := collector.NewNetworkCollector(slog.Default()); ncErr != nil {
			slog.Warn("network: collector creation failed", slog.Any("error", ncErr))
		} else {
			if cfg.BPF.Sampling.Enabled {
				nc.WithStatusReporter(collector.StatusReporterFunc(func(name string, up bool) {
					if name != "network" || !up {
						return
					}
					enableSampling("network", nc.SamplingConfigMap(), cfg.BPF.Sampling, samplingMux, "network")
				}))
			}
			collectors = append(collectors, nc.WithBackpressureStrategy(bpStrategy))
			slog.Info("network: collector enabled")
		}

		if fc, fcErr := collector.NewFileaccessCollector(slog.Default()); fcErr != nil {
			slog.Warn("fileaccess: collector creation failed", slog.Any("error", fcErr))
		} else {
			fo := cfg.Collectors.FileOps
			fc.WithFileOps(fo.TrackOpen, fo.TrackRead, fo.TrackWrite)
			if cfg.BPF.Sampling.Enabled {
				fc.WithStatusReporter(collector.StatusReporterFunc(func(name string, up bool) {
					if name != "fileaccess" || !up {
						return
					}
					enableSampling("fileaccess", fc.SamplingConfigMap(), cfg.BPF.Sampling, samplingMux, "file")
				}))
			}
			collectors = append(collectors, fc.WithBackpressureStrategy(bpStrategy))
			slog.Info("fileaccess: collector enabled",
				slog.Bool("track_open", fo.TrackOpen),
				slog.Bool("track_read", fo.TrackRead),
				slog.Bool("track_write", fo.TrackWrite),
			)
		}

		if dc, dcErr := collector.NewDNSCollector(cfg.Collectors.DNS.Enabled); dcErr != nil {
			slog.Warn("dns: collector creation failed", slog.Any("error", dcErr))
		} else {
			if err := dc.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
				slog.Warn("dns: register metrics failed", slog.Any("error", err))
			}
			collectors = append(collectors, dc.WithBackpressureStrategy(bpStrategy))
			slog.Info("dns: collector enabled", slog.Bool("enabled", cfg.Collectors.DNS.Enabled))
		}

		if cfg.Collectors.TLS.Enabled {
			if tc, tcErr := collector.NewTLSCollector(slog.Default(), true); tcErr != nil {
				slog.Warn("tls: collector creation failed", slog.Any("error", tcErr))
			} else {
				collectors = append(collectors, tc.WithBackpressureStrategy(bpStrategy))
				slog.Info("tls: collector enabled")
			}
		}

		if cfg.Collectors.HTTPPlaintext.Enabled {
			if hc, hcErr := collector.NewHTTPCollector(slog.Default(), true, cfg.Collectors.HTTPPlaintext.ServerComms); hcErr != nil {
				slog.Warn("http_plaintext: collector creation failed", slog.Any("error", hcErr))
			} else {
				collectors = append(collectors, hc.WithBackpressureStrategy(bpStrategy))
				slog.Info("http_plaintext: collector enabled")
			}
		}

		lsmCfg := collector.LSMConfig{Enabled: "auto"}
		if cfg.Enforcement.BlockBackend == "lsm" {
			lsmCfg.Enabled = "true"
		}
		if lc, lcErr := collector.NewLSMCollector(lsmCfg, slog.Default()); lcErr != nil {
			slog.Warn("lsm: collector creation failed (kernel 5.7+ required)", slog.Any("error", lcErr))
		} else {
			collectors = append(collectors, lc)
			slog.Info("lsm: collector enabled")
		}

		if kc, kcErr := collector.NewKmodCollector(slog.Default()); kcErr != nil {
			slog.Warn("kmod: collector creation failed", slog.Any("error", kcErr))
		} else {
			collectors = append(collectors, kc.WithBackpressureStrategy(bpStrategy))
			slog.Info("kmod: collector enabled")
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
	if cfg.Collectors.AzureMonitor.Enabled {
		az := collector.NewAzureMonitorCollector(slog.Default(), cfg.Collectors.AzureMonitor, bpStrategy)
		collectors = append(collectors, az)
		slog.Info("azure_monitor: collector enabled",
			slog.String("subscription", cfg.Collectors.AzureMonitor.SubscriptionID))
	}
	if cfg.Collectors.IOUring.Enabled {
		ioc, iocErr := collector.NewIOUringCollector(slog.Default())
		if iocErr != nil {
			slog.Warn("iouring: collector creation failed, skipping", slog.Any("error", iocErr))
		} else {
			ioc = ioc.WithBackpressureStrategy(bpStrategy)
			collectors = append(collectors, ioc)
			slog.Info("iouring: collector enabled")
		}
	}
	if cfg.Collectors.BPFMonitor.Enabled {
		bmc, bmErr := collector.NewBPFMonitorCollector(slog.Default())
		if bmErr != nil {
			slog.Warn("bpf_monitor: collector creation failed, skipping", slog.Any("error", bmErr))
		} else {
			bmc = bmc.WithBackpressureStrategy(bpStrategy)
			collectors = append(collectors, bmc)
			slog.Info("bpf_monitor: collector enabled")
		}
	}
	if cfg.Collectors.TLSFingerprint.Enabled {
		tfc, tfErr := collector.NewTLSFingerprintCollector(slog.Default())
		if tfErr != nil {
			slog.Warn("tls_fingerprint: collector creation failed, skipping", slog.Any("error", tfErr))
		} else {
			tfc = tfc.WithBackpressureStrategy(bpStrategy)
			collectors = append(collectors, tfc)
			slog.Info("tls_fingerprint: collector enabled")
		}
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
			newRules, err := loadRules(newCfg.Rules.Path)
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

	// Start hidden process detection loop (issue #155).
	if hiddenDetector != nil {
		hiddenAlertFn := func(a types.Alert) {
			if err := alertStore.StoreBatch(ctx, []types.Alert{a}); err != nil {
				slog.Warn("hidden: store alert error", slog.Any("error", err))
			}
			if alertmanagerClient != nil {
				alertmanagerClient.SendAlert(ctx, a)
			}
			if fanout != nil {
				fanout.Send(ctx, a)
			}
		}
		if err := hiddenDetector.Start(ctx, hiddenAlertFn); err != nil {
			slog.Warn("hidden: failed to start detection loop", slog.Any("error", err))
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

	// ── Kubernetes pod enricher ─────────────────────────────────────────────
	// Adds full pod metadata (namespace, labels, annotations, pod name) from the
	// API server. Scoped to this node via NODE_NAME to bound memory. Runs first
	// in the enrichment chain so the runtime enricher only fills container fields.
	// No-ops gracefully off-cluster (NewEnricher returns an error).
	var k8sEnricher *k8s.Enricher
	if cfg.Kubernetes.Enabled {
		ke, keErr := k8s.NewEnricher(k8s.EnricherConfig{
			KubeconfigPath: cfg.Kubernetes.KubeconfigPath,
			ResyncPeriod:   time.Duration(cfg.Kubernetes.ResyncPeriod) * time.Second,
			NodeName:       os.Getenv("NODE_NAME"),
		}, slog.Default())
		if keErr != nil {
			slog.Warn("k8s enricher: unavailable, pod metadata will not be added",
				slog.Any("error", keErr))
		} else {
			k8sEnricher = ke
			go func() {
				if err := k8sEnricher.Start(ctx); err != nil {
					slog.Warn("k8s enricher stopped", slog.Any("error", err))
				}
			}()
			defer func() { _ = k8sEnricher.Stop() }()
			slog.Info("k8s enricher active (pod metadata enrichment)")
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

	// Container drift detector — when enabled, compares runtime behaviour against
	// per-container baselines. In ImageManifest mode, the baseline is pre-seeded
	// from the container image layers via overlayfs lowerdir walk.
	var driftDetector *drift.Detector
	var driftSeq atomic.Uint64
	if cfg.Drift.Enabled {
		baselineWindow, _ := time.ParseDuration(cfg.Drift.BaselineWindow)
		if baselineWindow <= 0 {
			baselineWindow = 5 * time.Minute
		}
		allowlistExec := make(map[string]struct{}, len(cfg.Drift.AllowlistExec))
		for _, p := range cfg.Drift.AllowlistExec {
			allowlistExec[p] = struct{}{}
		}
		driftDetector = drift.NewDetector(drift.DetectorConfig{
			BaselineWindow: baselineWindow,
			Logger:         slog.Default(),
			ImageManifest:  cfg.Drift.ImageManifest,
			EnforceMode:    cfg.Drift.EnforceMode,
			AllowlistExec:  allowlistExec,
		})
		slog.Info("drift: detector enabled",
			slog.Duration("baseline_window", baselineWindow),
			slog.Bool("image_manifest", cfg.Drift.ImageManifest),
			slog.String("enforce_mode", cfg.Drift.EnforceMode),
			slog.Int("allowlist_exec", len(allowlistExec)),
		)

		// Periodic purge of stale container baselines.
		purgeInterval, _ := time.ParseDuration(cfg.Drift.PurgeInterval)
		if purgeInterval <= 0 {
			purgeInterval = 10 * time.Minute
		}
		purgeTTL, _ := time.ParseDuration(cfg.Drift.PurgeTTL)
		if purgeTTL <= 0 {
			purgeTTL = 30 * time.Minute
		}
		go func() {
			ticker := time.NewTicker(purgeInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					removed := driftDetector.PurgeStale(purgeTTL)
					if removed > 0 {
						slog.Debug("drift: purged stale baselines", slog.Int("removed", removed))
					}
				}
			}
		}()
	}

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

	// metricsNodeName labels the ebpf_guard_events_total / ebpf_guard_alerts_total
	// node dimension so the fleet-wide Grafana dashboard can attribute events and
	// alerts to a node even when Kubernetes enrichment is disabled (bare-metal/VM
	// fleets). Prefers per-event Enrichment.NodeName (set by the k8s enricher) and
	// falls back to this agent's own node identity.
	metricsNodeName := resolveMetricsNodeName()

	// dispatchAlerts fans a batch of alerts out to every configured sink: the
	// simple-mode auto-enforcer, attack-simulation collector, alert store,
	// Alertmanager webhook, notification fanout, and cross-node gossip.
	dispatchAlerts := func(dispatched []types.Alert) {
		for _, a := range dispatched {
			podName, namespace, node := a.Enrichment.PodName, a.Enrichment.Namespace, a.Enrichment.NodeName
			if node == "" {
				node = metricsNodeName
			}
			exporter.RecordAlert(a.RuleID, string(a.Severity), namespace, podName, node)
		}
		// Simple mode: auto-enforce high-confidence threats.
		if simpleEngine != nil && enf != nil {
			simpleEngine.ProcessAlerts(dispatched, enf)
		}
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
	}

	// dispatchAsync runs dispatchAlerts in a bounded goroutine pool to prevent
	// unbounded goroutine growth under burst alert rates; drops (and records)
	// the batch if the pool is saturated.
	dispatchAsync := func(dispatched []types.Alert) {
		if len(dispatched) == 0 {
			return
		}
		if !workerSem.TryAcquire(1) {
			exporter.RecordQueueOverflow()
			return
		}
		n := activeWorkers.Add(1)
		exporter.SetGoroutinePoolActive(n)
		go func(a []types.Alert) {
			defer func() {
				workerSem.Release(1)
				exporter.SetGoroutinePoolActive(activeWorkers.Add(-1))
			}()
			dispatchAlerts(a)
		}(dispatched)
	}

	// Background: periodically drain alerts the correlation engine accumulated
	// via IngestAsync (rule matches, anomaly detection, Rego enrichment) and
	// dispatch them. Without this, engine.pending would only ever be drained
	// once at shutdown — growing unboundedly for the life of the process and
	// re-storing every alert a second time on the way out.
	go func() {
		ticker := time.NewTicker(pendingFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dispatchAsync(engine.Flush())
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

			// Enrich before rule evaluation so conditions on pod/container fields
			// can match. K8s pod metadata first (namespace, labels, pod name),
			// then the runtime enricher fills container fields (name, image) and
			// any node-local pod identity the k8s enricher could not resolve.
			if k8sEnricher != nil {
				k8sEnricher.EnrichEvent(&event)
			}
			if runtimeEnricher != nil {
				runtimeEnricher.EnrichEvent(&event)
			}

			// Fleet-wide event metric: type/pod/namespace/node so the Grafana fleet
			// dashboard can aggregate events/sec across the whole cluster, not just
			// this agent's own scrape target.
			var evtPod, evtNamespace, evtNode string
			if event.Enrichment != nil {
				evtPod, evtNamespace, evtNode = event.Enrichment.PodName, event.Enrichment.Namespace, event.Enrichment.NodeName
			}
			if evtNode == "" {
				evtNode = metricsNodeName
			}
			exporter.RecordEventWithLabels(exporter.EventTypeLabel(event.Type), evtPod, evtNamespace, evtNode)

			// Route to the PID-partitioned ingest worker pool so rule evaluation,
			// lineage tracking, and anomaly scoring are spread across goroutines
			// instead of serializing on this one. Resulting alerts land in
			// engine.pending and are drained by the periodic flush above — do
			// NOT also dispatch a return value here, or every alert double-fires.
			engine.IngestAsync(ctx, event)

			// Drift detection runs independently of the correlation engine's
			// pending buffer, so its alerts are dispatched immediately.
			if driftDetector != nil {
				driftAlerts := driftDetector.Ingest(event)
				if len(driftAlerts) > 0 {
					alerts := make([]types.Alert, 0, len(driftAlerts))
					for _, da := range driftAlerts {
						seq := driftSeq.Add(1)
						alerts = append(alerts, drift.DriftAlertToTypes(da, seq, cfg.Drift.EnforceMode))
					}
					dispatchAsync(alerts)
				}
			}
		}
	}
}

// gracefulShutdown orchestrates an ordered, time-bounded shutdown sequence:
//  1. Stop BPF collectors so no new events enter the pipeline.
//  2. Drain the PID-partitioned ingest worker pool so every event already
//     queued via IngestAsync finishes processing (and its alerts land in
//     pending) before anything downstream is drained or flushed.
//  3. Drain enforcement queue (up to 5 s) — let in-flight kill/block tasks finish.
//  4. Drain the correlation engine's async Rego evaluation queue.
//  5. Flush pending alerts from the correlation engine into the store.
//  6. Flush the alert store (WAL checkpoint for SQLite).
//  7. Flush pending Alertmanager webhook deliveries.
//  8. Cleanup nftables/iptables chains left by the enforcer (if active).
//  9. Shutdown the HTTP server.
//
// enableKernelFilter populates the syscall collector's BPF-side content
// filter (comm denylist + syscall allowlist) and turns it on. Without this,
// raw_syscalls/sys_enter and sys_exit forward every syscall on the host to
// the ring buffer — on a busy node that overwhelms the event channel within
// seconds. Called once the collector reports its BPF maps are loaded.
func enableKernelFilter(sc *collector.SyscallCollector, fc config.KernelFilterConfig) {
	commMap, syscallMap, cfgMap := sc.KernelFilterMaps()
	kf, err := internalbpf.NewKernelFilterController(commMap, syscallMap, cfgMap)
	if err != nil {
		slog.Warn("kernel_filter: maps unavailable, syscalls forwarded unfiltered", slog.Any("error", err))
		return
	}

	nrs := fc.MonitoredSyscalls
	if len(nrs) == 0 {
		nrs = internalbpf.DefaultMonitoredSyscalls()
	}
	for _, nr := range nrs {
		if err := kf.SetSyscallFilter(nr, true); err != nil {
			slog.Warn("kernel_filter: set syscall filter failed", slog.Int("nr", nr), slog.Any("error", err))
		}
	}

	denylist := internalbpf.BuildCommDenylist(fc.CommDenylist, fc.NoisyDaemonDenylist, fc.DisableDefaultDaemonDenylist)
	for _, comm := range denylist {
		if err := kf.SetCommFilter(comm, false); err != nil {
			slog.Warn("kernel_filter: set comm filter failed", slog.String("comm", comm), slog.Any("error", err))
		}
	}

	if err := kf.Enable(); err != nil {
		slog.Error("kernel_filter: failed to enable BPF-side filtering", slog.Any("error", err))
		return
	}
	slog.Info("kernel_filter: enabled BPF-side syscall/comm filtering",
		slog.Int("monitored_syscalls", len(nrs)),
		slog.Int("comm_denylist", len(denylist)),
		slog.Bool("daemon_denylist_disabled", fc.DisableDefaultDaemonDenylist))
}

// enableSampling applies the configured static BPF-side sample rate to the
// given collector's sampling_config map and turns sampling on. Each compiled
// BPF object (syscall, network, fileaccess) has its own independent copy of
// this map — only the rate field relevant to that program's event type has
// any effect there, so it's safe to write the same full rate set to all
// three. Without this, sys_enter_read/sys_enter_write fire on every syscall
// system-wide and flood the event channel within seconds.
func enableSampling(name string, configMap *ebpf.Map, sc config.SamplingConfig, mux *watchdog.MultiBPFController, eventType string) {
	ctrl, err := internalbpf.NewSamplingController(configMap)
	if err != nil {
		slog.Warn("sampling: map unavailable, events forwarded unsampled",
			slog.String("collector", name), slog.Any("error", err))
		return
	}

	cfg := internalbpf.SamplingConfig{
		SyscallRate: sc.SyscallRate,
		NetworkRate: sc.NetworkRate,
		FileRate:    sc.FileRate,
		Enabled:     1,
	}
	if err := ctrl.UpdateConfig(cfg); err != nil {
		slog.Error("sampling: failed to apply BPF-side sample rate",
			slog.String("collector", name), slog.Any("error", err))
		return
	}
	// Expose this controller to the CPU pressure watcher so it can adaptively
	// reduce this collector's sampling rate under load.
	if mux != nil {
		mux.Register(eventType, ctrl)
	}
	slog.Info("sampling: enabled BPF-side static sample rate",
		slog.String("collector", name),
		slog.Uint64("syscall_rate", uint64(sc.SyscallRate)),
		slog.Uint64("network_rate", uint64(sc.NetworkRate)),
		slog.Uint64("file_rate", uint64(sc.FileRate)))
}

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

	// Step 2: drain the PID-partitioned ingest worker pool. Events dispatched
	// via IngestAsync before collectors stopped may still be queued in a
	// worker's channel; wait for them to finish processing so their alerts
	// (and any enforcement/Rego tasks they submit) exist before the queues
	// below are drained. Skipping this would let those events surface only
	// after Close() runs much later — past the point where anything flushes
	// pending to the store again.
	slog.Info("graceful shutdown: draining ingest worker pool")
	engine.DrainIngestPool(shutdownCtx)

	// Step 3: drain the enforcement worker queue so in-flight kill/block/throttle
	// tasks are not abandoned mid-execution.
	drainCtx, drainCancel := context.WithTimeout(shutdownCtx, drainEnforcementTimeout)
	slog.Info("graceful shutdown: draining enforcement queue")
	engine.DrainEnforceQueue(drainCtx)
	drainCancel()

	// Step 4: drain async Rego evaluation workers so every alert that was
	// submitted for OPA enrichment lands in the engine's pending buffer.
	regoCtx, regoCancel := context.WithTimeout(shutdownCtx, drainRegoTimeout)
	slog.Info("graceful shutdown: draining Rego evaluation queue")
	if err := engine.Drain(regoCtx); err != nil {
		slog.Warn("graceful shutdown: Rego drain timeout, some enrichments may be missing",
			slog.Any("error", err))
	}
	regoCancel()

	// Step 5: flush any pending alerts buffered in the correlation engine.
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

	// Step 6: flush the alert store (SQLite WAL checkpoint; no-op for other backends).
	slog.Info("graceful shutdown: flushing alert store")
	if err := alertStore.Flush(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown: alert store flush error", slog.Any("error", err))
	}

	// Step 7: flush pending Alertmanager webhook deliveries and wait for all
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

	// Step 8: remove nftables/iptables rules the enforcer installed.
	if enf != nil {
		slog.Info("graceful shutdown: cleaning up enforcement chains")
		if err := enf.Cleanup(); err != nil {
			slog.Warn("graceful shutdown: enforcement cleanup error", slog.Any("error", err))
		}
		if err := enf.Close(); err != nil {
			slog.Warn("graceful shutdown: enforcer close error", slog.Any("error", err))
		}
	}

	// Step 9: drain the HTTP server.
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

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cannot generate auth token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// tokenFileDir is the directory writeTokenFile writes the generated-token
// file into. It is a var (not a const) so tests can point it at a temp
// directory instead of the real /run/ebpf-guard.
var tokenFileDir = "/run/ebpf-guard" // #nosec G101 -- filesystem directory path for the token file, not a credential value

// writeTokenFile writes auto-generated tokens to <tokenFileDir>/token
// with mode 0600, so operators can retrieve the credentials.
// If no tokens are auto-generated (both are empty), this is a no-op.
func writeTokenFile(adminToken, viewerToken string) error {
	if adminToken == "" && viewerToken == "" {
		return nil
	}
	tokenDir := tokenFileDir
	tokenPath := tokenDir + "/token"
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", tokenDir, err)
	}
	var content string
	if adminToken != "" {
		content += "admin=" + adminToken + "\n"
	}
	if viewerToken != "" {
		content += "viewer=" + viewerToken + "\n"
	}
	if err := os.WriteFile(tokenPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("write %s: %w", tokenPath, err)
	}
	slog.Info("auth: tokens written to file", "path", tokenPath)
	return nil
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

			rules, err := loadRules(cfg.Rules.Path)
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
		Short: "Import detection rules from external formats (sigma, ecs, falco)",
		Long: `import converts rules from other security formats into ebpf-guard YAML.

Supported formats:
  sigma   Sigma open-standard detection rules (https://sigmahq.io)
  ecs     Elastic Common Schema-based detection rules (Elastic Security)
  falco   Falco detection rules (https://falco.org / falcosecurity/rules),
          including and/or/not boolean logic, macro: and list: expansion

The input PATH may be a single .yaml/.yml file or a directory. For directories,
all .yaml/.yml files found directly in the directory are processed.
Alternatively, use --dir for the input directory and --source for the format.

Unknown fields are skipped with a WARN log; the rule is still imported
if at least one condition could be mapped. Fully unsupported rules are counted
separately and never written to the output file.

Examples:
  ebpf-guard rules import --format sigma ./sigma-rules/ --out rules/imported/
  ebpf-guard rules import --source sigma --dir ./sigma-rules/ --out rules/imported/
  ebpf-guard rules import --format sigma rule.yml --dry-run
  ebpf-guard rules import --format ecs ./elastic-rules/ --out rules/imported/
  ebpf-guard rules import --format ecs rule.yml --dry-run
  ebpf-guard rules import --format falco ./falco-rules/ --out rules/imported/
  ebpf-guard rules import --format falco rule.yaml --dry-run`,
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

			if !strings.EqualFold(format, "sigma") && !strings.EqualFold(format, "ecs") && !strings.EqualFold(format, "falco") {
				return fmt.Errorf("unsupported format %q — only 'sigma', 'ecs' and 'falco' are currently supported", format)
			}

			info, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("stat input path: %w", err)
			}

			if strings.EqualFold(format, "ecs") {
				return runECSImport(inputPath, info, outDir, dryRun)
			}

			if strings.EqualFold(format, "falco") {
				return runFalcoImport(inputPath, info, outDir, dryRun)
			}

			imp := migration.NewSigmaImporter()

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

	cmd.Flags().StringVar(&format, "format", "", "source format (sigma, ecs, falco); alias: --source")
	cmd.Flags().StringVar(&source, "source", "", "source format (sigma, ecs, falco); alias: --format")
	cmd.Flags().StringVar(&dirArg, "dir", "", "input directory containing source rule files (alternative to positional PATH)")
	cmd.Flags().StringVar(&outDir, "out", "rules/imported", "output directory for converted rules")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print generated YAML without writing files")
	return cmd
}

// runFalcoImport handles the Falco import logic for the rules import subcommand.
func runFalcoImport(inputPath string, info os.FileInfo, outDir string, dryRun bool) error {
	imp := migration.NewFalcoImporter()

	var result *migration.ImportResult
	var err error
	if info.IsDir() {
		result, err = imp.ImportDir(inputPath)
	} else {
		result, err = imp.ImportFile(inputPath)
	}
	if err != nil {
		return fmt.Errorf("import falco rules: %w", err)
	}

	fmt.Printf("Falco import summary:\n")
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
	outPath := filepath.Join(outDir, "falco-imported.yaml")
	if err := os.WriteFile(outPath, out, 0o600); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	fmt.Printf("\nWritten %d rule(s) to %s\n", result.Converted, outPath)
	return nil
}

// runECSImport handles the ECS import logic for the rules import subcommand.
func runECSImport(inputPath string, info os.FileInfo, outDir string, dryRun bool) error {
	imp := migration.NewECSImporter()

	var result *migration.ECSImportResult
	var err error
	if info.IsDir() {
		result, err = imp.ImportDir(inputPath)
	} else {
		result, err = imp.ImportFile(inputPath)
	}
	if err != nil {
		return fmt.Errorf("import ecs rules: %w", err)
	}

	fmt.Printf("ECS import summary:\n")
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
	outPath := filepath.Join(outDir, "ecs-imported.yaml")
	if err := os.WriteFile(outPath, out, 0o640); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	fmt.Printf("\nWritten %d rule(s) to %s\n", result.Converted, outPath)
	return nil
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
		ruleFile     string
		replayWindow string
		eventsLog    string
		sampleLimit  int
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

	// session.Run returns on its own deadline timer without cancelling ctx,
	// so collectors' Start loops (which only exit on ctx.Done()) are still
	// running here. Cancel before Close(): SyntheticCollector.Close blocks on
	// its internal "stopped" channel, which only closes once Start observes
	// ctx.Done() — without this, Close() (and thus the whole command) would
	// hang forever after "session complete".
	cancel()
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
		cfgPath       string
		logLevel      string
		dryRun        bool
		fleet         string
		fleetToken    string
		fleetInterval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Interactive live TUI dashboard — events, alerts, rule stats",
		Long: `dashboard starts the agent and renders a live terminal UI showing:

  • Tab 1 – Alerts:     incoming alerts with severity and rule
  • Tab 2 – Events:     raw kernel events (pid, comm, type)
  • Tab 3 – Top Rules:  rules ranked by trigger count with sparkbar
  • Tab 4 – Status:     aggregate counters and top processes
  • Tab 5 – Fleet:      per-agent health (fleet mode only)

Use --dry-run to run without kernel eBPF probes (synthetic events).

Fleet mode (--fleet) turns the dashboard into a client-side fan-out viewer:
instead of running local collectors, it polls the REST API of every agent
endpoint given and merges their alert streams into one view, tagging each
alert with its source node/pod so an operator gets a single pane across the
whole DaemonSet without a central aggregation service.

  ebpf-guard dashboard --fleet http://node-a:9090,http://node-b:9090 --fleet-token "$TOKEN"

Keybindings:
  Tab / 1-5   switch panel
  j/k or ↑/↓  scroll
  p            pause live updates
  q            quit`,
		RunE: func(_ *cobra.Command, _ []string) error {
			setupLogger(logLevel)
			if fleet != "" {
				endpoints := util.SplitAndTrim(fleet, ",")
				if len(endpoints) == 0 {
					return fmt.Errorf("--fleet requires at least one endpoint")
				}
				return runFleetDashboard(endpoints, fleetToken, fleetInterval)
			}
			return runDashboard(cfgPath, dryRun)
		},
	}

	cmd.Flags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	cmd.Flags().StringVar(&logLevel, "log-level", "warn", "log level (use warn/error to keep TUI clean)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "use synthetic events instead of real eBPF probes")
	cmd.Flags().StringVar(&fleet, "fleet", "", "comma-separated list of agent base URLs to fan out to (e.g. http://node-a:9090,http://node-b:9090); enables fleet mode")
	cmd.Flags().StringVar(&fleetToken, "fleet-token", os.Getenv("EBPF_GUARD_TOKEN"), "bearer token used to authenticate against every fleet agent (default: $EBPF_GUARD_TOKEN)")
	cmd.Flags().DurationVar(&fleetInterval, "fleet-interval", 3*time.Second, "how often to poll each fleet agent for new alerts and health")
	return cmd
}

// resolveMetricsNodeName determines this agent's own node identity for the
// "node" label on ebpf_guard_events_total / ebpf_guard_alerts_total, used only
// as a fallback when an event/alert carries no Kubernetes-enriched NodeName.
//
// It prefers the NODE_NAME env var (set from the DaemonSet's downward API). It
// deliberately does NOT fall back to os.Hostname() when running inside
// Kubernetes: there the hostname is the pod name, not the node, so using it
// would mislabel every series with a per-pod value and inflate cardinality.
// Off-cluster (bare-metal/VM) the hostname is the correct node identity.
func resolveMetricsNodeName() string {
	if n := os.Getenv("NODE_NAME"); n != "" {
		return n
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		// In-cluster without NODE_NAME: the hostname is the pod name, which is
		// wrong for the node label. Leave it empty rather than mislabel.
		slog.Warn("metrics: running in Kubernetes without NODE_NAME set; " +
			"the 'node' metric label will be empty. Set NODE_NAME via the " +
			"downward API (fieldRef: spec.nodeName) to populate it.")
		return ""
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return ""
}

// runFleetDashboard starts the fleet-mode TUI: no local collectors or
// correlation engine, just a client-side fan-out poller reading every
// endpoint's REST API and merging alerts into one live dashboard.
func runFleetDashboard(endpoints []string, token string, interval time.Duration) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	feed := tui.NewFeed()
	return tui.RunFleet(ctx, feed, tui.FleetConfig{
		Endpoints:    endpoints,
		Token:        token,
		PollInterval: interval,
	})
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

	rules, _ := loadRules(cfg.Rules.Path)

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
  --verify        Poll a live agent's /api/v1/alerts API after running a scenario and
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

// printZeroConfigBanner prints a human-friendly first-run summary to stderr
// so that users running `curl | sh` or `docker run` immediately see what is
// being monitored and where alerts go.
func printZeroConfigBanner(cfg *config.Config) {
	addr := cfg.Server.BindAddress
	if addr == "" {
		addr = ":9090"
	}
	adminToken := cfg.Auth.AdminToken
	if adminToken == "" && len(cfg.Auth.Tokens) > 0 {
		adminToken = cfg.Auth.Tokens[0].Token
	}

	fmt.Fprintf(os.Stderr, `
╔══════════════════════════════════════════════════════════════╗
║           ebpf-guard %s — ready                            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Zero-config mode — embedded defaults active.                ║
║  No config file or rules directory needed.                   ║
║                                                              ║
║  What is being monitored:                                    ║
║    • Syscalls (exec, privesc, container escape)              ║
║    • Network connections (C2, data exfil)                    ║
║    • File access (sensitive files, binaries)                 ║
║    • Process lineage (web shell, reverse shell)              ║
║                                                              ║
║  Where alerts go:                                            ║
║    • Metrics:  http://localhost%s%s                         ║
║    • Health:   http://localhost%s%s                         ║
║    • Store:    in-memory (restart = data lost)               ║
║                                                              ║
`, Version,
		addr, cfg.Server.MetricsPath,
		addr, cfg.Server.HealthPath,
	)

	if adminToken != "" {
		fmt.Fprintf(os.Stderr, "║  Auth token (admin): %s... (save this!)                 ║\n",
			adminToken[:min(12, len(adminToken))])
	}
	fmt.Fprintf(os.Stderr, `║                                                              ║
║  To add Alertmanager, Discord, or Telegram:                   ║
║    Create a config file and run without --zero-config         ║
║    See: https://github.com/zugolO/ebpf-guard                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

`)
}

// parseDuration parses a duration string or returns the default on failure.
func parseDuration(s string, defaultDur time.Duration) time.Duration {
	if s == "" || s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultDur
	}
	return d
}

// loadRules loads rules from a file or directory path.
func loadRules(path string) ([]correlator.Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat rules path: %w", err)
	}
	if info.IsDir() {
		return correlator.LoadRulesFromDir(path)
	}
	return correlator.LoadRulesFromFile(path)
}
