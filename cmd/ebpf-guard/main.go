// Package main is the entry point for the ebpf-guard security agent.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
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
		profileFlag      string
	)

	root := &cobra.Command{
		Use:   "ebpf-guard",
		Short: "eBPF-based runtime security agent for Linux/Kubernetes",
		Long: `ebpf-guard attaches eBPF probes to collect kernel events, correlates them
against YAML detection rules, and exports alerts to Prometheus and Alertmanager.`,
		Version:      fmt.Sprintf("%s (commit %s)", Version, Commit),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cfgPath, logLevel, dryRun, simulateMode, simulateDuration, shutdownTimeout, zeroConfig, enableSimple, profileFlag)
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
	root.PersistentFlags().StringVar(&profileFlag, "profile", os.Getenv("EBPF_GUARD_PROFILE"),
		"hardware-aware tuning preset: lite, balanced, or production (default: $EBPF_GUARD_PROFILE, "+
			"or autodetect from nproc/meminfo if that's unset too)")

	rulesCmd := newRulesCmd(&cfgPath)
	rulesCmd.AddCommand(newRulesTestCmd(&cfgPath))
	rulesCmd.AddCommand(newRulesCheckCmd())

	configCmd := newConfigCmd()

	root.AddCommand(
		newAlertsCmd(&cfgPath),
		newStatusCmd(&cfgPath),
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

// convertRulesToDebugState converts correlator rules to exporter RuleState for the debug endpoint.
func convertRulesToDebugState(rules []correlator.Rule) []exporter.RuleState {
	states := make([]exporter.RuleState, 0, len(rules))
	for _, rule := range rules {
		states = append(states, exporter.RuleState{
			ID:          rule.ID,
			Name:        rule.Name,
			EventType:   rule.EventType.String(),
			Severity:    string(rule.Severity),
			Action:      string(rule.Action),
			Description: rule.Description,
		})
	}
	return states
}

func runAgent(cfgPath, logLevel string, dryRun bool, simulateMode bool, simulateDuration, shutdownTimeoutFlag string, zeroConfig bool, enableSimple bool, profileFlag string) error {
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
		cfgManager = config.NewZeroConfigManagerWithProfile(profileFlag)
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
		cfgManager, err = config.NewManagerSkipPermCheckWithProfile(cfgPath, profileFlag)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		cfg = cfgManager.Get()

		// Load rules from file or directory (config defaults to rules/ dir),
		// merging in the local-tuning overlay if configured.
		rules, err = loadRulesWithTuning(cfg.Rules.Path, cfg.Rules.LocalTuningPath)
		if err != nil {
			slog.Warn("failed to load rules file, starting with empty rule set",
				slog.String("path", cfg.Rules.Path),
				slog.Any("error", err))
			rules = nil
		} else {
			slog.Info("rules loaded", slog.Int("count", len(rules)))
		}
	}

	// ── Hardware-aware profile (issue #287) ────────────────────────────────────
	// Log the resolved lite/balanced/production preset and apply GOMEMLIMIT/GOGC
	// tuning so a single-core/1-2GB VPS runs `lite` without any manual config.
	hwProfile := cfgManager.HardwareProfile()
	slog.Info("hardware profile resolved",
		slog.String("profile", hwProfile.Profile),
		slog.String("source", hwProfile.Source),
		slog.String("reason", hwProfile.Reason),
		slog.Int("cpus", hwProfile.Hardware.CPUs),
		slog.Int("mem_total_mb", hwProfile.Hardware.MemTotalMB),
		slog.Int("bpf_events_map", hwProfile.Applied.EventsMap),
		slog.Int("bpf_processes_map", hwProfile.Applied.ProcessesMap),
		slog.Int("bpf_connections_map", hwProfile.Applied.ConnectionsMap),
		slog.Int("profiler_max_tracked_pids", hwProfile.Applied.MaxTrackedPIDs),
		slog.Bool("sequence_profiler", hwProfile.Applied.SequenceEnabled),
		slog.Bool("lineage_tracker", hwProfile.Applied.LineageEnabled),
	)
	applyRuntimeTuning(hwProfile)

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

	// Wave 5.9.2b (finding #39): a rule that constrains event_type: syscall by
	// a numeric "nr" outside the in-kernel allowlist can never fire — the event
	// is dropped before it reaches the rule engine. 27 rules accumulated in
	// this state silently before this check existed. Report them once at
	// startup rather than let them decay unnoticed again.
	if len(rules) > 0 {
		allowlist := cfg.BPF.KernelFilter.MonitoredSyscalls
		if len(allowlist) == 0 {
			allowlist = internalbpf.DefaultMonitoredSyscalls()
		}
		if cfg.BPF.KernelFilter.Enabled {
			if unreachable := correlator.NewRuleEngine(rules).UnreachableSyscallRules(allowlist); len(unreachable) > 0 {
				slog.Warn("rules: syscall rules with no reachable nr in the kernel allowlist",
					slog.Int("count", len(unreachable)),
					slog.Any("rule_ids", unreachable))
			}
		}
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

	// Learning takes as long as configured regardless of how long this process
	// happens to run for; a short-lived run (a manual test, a CI smoke test)
	// against a long learning_period will never leave the learning phase, and
	// without this warning that reads as "profiler broken" rather than "still
	// learning". See ISSUES-attack-run-2026-08-03.md P1-4.
	if cfg.Profiler.Enabled && engineCfg.LearningPeriod > 10*time.Minute {
		slog.Warn("profiler: learning_period is long relative to typical test/attack-sim runs; anomaly detection will stay in the learning phase (no anomaly alerts) until it elapses",
			slog.Duration("learning_period", engineCfg.LearningPeriod))
	}
	engineCfg.IncidentTrustedComms = cfg.Correlator.TrustedComms
	engineCfg.EnableRateLimit = cfg.Rules.RateLimitAlerts
	engineCfg.RateLimitWindow = time.Duration(cfg.Rules.RateLimitWindow) * time.Second
	engineCfg.MaxAlertsPerWindow = cfg.Rules.MaxAlertsPerWindow
	if cfg.Correlator.MaxAlertsPerSecond > 0 {
		engineCfg.MaxAlertsPerSecond = cfg.Correlator.MaxAlertsPerSecond
	}
	// 5.8e (находка №18): self-exclusion is on by default and the default lives
	// in viper (correlator.self_exclude.enabled, config.setDefaults), not in the
	// zero value of this bool — so the config value is copied over
	// unconditionally and an operator's explicit `false` takes effect.
	engineCfg.SelfExcludeEnabled = cfg.Correlator.SelfExclude.Enabled
	// 5.9a: observer-tree exclusion is test-only and off by default (the
	// zero value already matches), copied over the same unconditional way as
	// self-exclusion above so an operator's explicit config value takes
	// effect either direction.
	engineCfg.ObserverExcludeEnabled = cfg.Correlator.ObserverExclude.Enabled

	// Wire the anomaly score reporter so profiler scores are published to
	// ebpf_guard_profiler_anomaly_score via the cardinality-guarded gauge.
	engineCfg.AnomalyScoreReporter = exporter.SetAnomalyScoreWithGuard

	// Drift-baseline observe mode (issue #286): suppresses class: drift rule
	// matches (container/FIM drift monitoring) during a per-workload learning
	// window, then alerts only on matches that deviate from the learned
	// baseline. Independent of the general anomaly profiler above — it only
	// affects rules explicitly tagged class: drift.
	var driftProfiler *profiler.DriftBaselineProfiler
	if cfg.Profiler.DriftBaseline.Enabled {
		driftProfiler = profiler.NewDriftBaselineProfiler(profiler.DriftBaselineConfig{
			Enabled:                cfg.Profiler.DriftBaseline.Enabled,
			LearningPeriod:         cfg.Profiler.DriftBaseline.LearningPeriod,
			MinSamples:             cfg.Profiler.DriftBaseline.MinSamples,
			PerWorkload:            cfg.Profiler.DriftBaseline.PerWorkload,
			MaxWorkloads:           cfg.Profiler.DriftBaseline.MaxWorkloads,
			EnforceDeadlinePeriods: cfg.Profiler.DriftBaseline.EnforceDeadlinePeriods,
		}, slog.Default())
		if err := driftProfiler.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
			slog.Warn("drift baseline: failed to register metrics", slog.Any("error", err))
		}
		engineCfg.DriftBaselineProfiler = driftProfiler
	}

	// samplingMux fans BPF-side sampling changes out to the per-collector
	// SamplingControllers. It is shared by the collectors' status reporters
	// (which register each controller as its collector comes up) and the CPU
	// pressure watcher (which adjusts rates under load).
	samplingMux := watchdog.NewMultiBPFController(slog.Default())
	if err := samplingMux.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
		slog.Warn("sampling: failed to register effective-rate metric", slog.Any("error", err))
	}

	var prof *profiler.Profiler
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
		prof = profiler.NewProfilerWithContext(ctx, profCfg, slog.Default())
		engineCfg.LineageTracker = prof.GetLineageTracker()
		if err := prof.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
			slog.Warn("profiler: failed to register Prometheus metrics",
				slog.Any("error", err))
		}
		if wpm := prof.GetDetector().GetProfileManager(); wpm != nil {
			if err := wpm.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
				slog.Warn("profiler: failed to register workload profile metrics",
					slog.Any("error", err))
			}
		}

		// Restore the syscall allowlist from a previous run. The allowlist
		// profiler is recorded/checked synchronously per-event through
		// ce.allowlistProfiler (the same instance as prof's), so it can be
		// restored here safely. Anomaly-detector (EWMA) state cannot: it is
		// restored further down, after the correlation engine (and its
		// per-worker detector pool) exists. See the P0-3 note there.
		if cfg.Profiler.StatePersistence.Enabled {
			prof.LoadAllowlistState(cfg.Profiler.StatePersistence.Path)
		}

		if cfg.Watchdog.MemoryPressure.Enabled {
			memCfg := watchdog.MemoryConfig{
				Enabled:                  true,
				CheckInterval:            time.Duration(cfg.Watchdog.MemoryPressure.CheckInterval) * time.Second,
				LowMemoryThreshold:       cfg.Watchdog.MemoryPressure.LowMemoryThreshold,
				RecoveryThreshold:        cfg.Watchdog.MemoryPressure.RecoveryThreshold,
				DisableSequenceThreshold: cfg.Watchdog.MemoryPressure.DisableSequenceThreshold,
				DisableAllThreshold:      cfg.Watchdog.MemoryPressure.DisableAllThreshold,
			}
			seqProfilers := []watchdog.ControllableProfiler{prof.GetSequenceProfiler()}
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
	cpuWatcher := watchdog.SetupCPUPressureWatcher(ctx, watchdog.CPUConfig{
		Enabled:                   cp.Enabled,
		CheckInterval:             time.Duration(cp.CheckInterval) * time.Second,
		CPULimitPercent:           cp.CPULimitPercent,
		FileShedThreshold:         cp.FileShedThreshold,
		AllShedThreshold:          cp.AllShedThreshold,
		RecoveryThreshold:         cp.RecoveryThreshold,
		WindowSize:                cp.WindowSize,
		MinDwell:                  time.Duration(cp.MinDwell) * time.Second,
		ScaleThresholdsByCPUCount: cp.ScaleByCPUCount,
		// Write through a named arbiter view so a CPU-pressure recovery
		// restores the operator's configured base rate (not a hardcoded 1.0)
		// and never overwrites another controller's active degradation (#304).
	}, slog.Default(), samplingMux.Controller("cpu_pressure"), prometheus.DefaultRegisterer)

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
			if err := enf.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
				slog.Warn("enforcer: failed to register Prometheus metrics",
					slog.Any("error", err))
			}
			slog.Info("enforcer: active",
				slog.String("backend", cfg.Enforcement.BlockBackend),
				slog.Bool("dry_run", cfg.Enforcement.DryRun))
		}
	}

	engine := correlator.NewCorrelationEngineWithConfig(engineCfg)
	if err := engine.RegisterMetrics(prometheus.DefaultRegisterer); err != nil {
		slog.Warn("correlation engine: failed to register Prometheus metrics",
			slog.Any("error", err))
	}

	// 5.9a: poll the harness's root-PID file rather than read it once at
	// startup, because the measurement harness (idle-run.sh) is started
	// separately from — and typically well after — this process, so its PID
	// isn't known yet when the config is loaded. Polling interval (2s) is a
	// tradeoff: fast enough that the exclusion window opens well within one
	// idle-run.sh snapshot interval (300s default), slow enough not to add
	// its own read() noise to the very measurement it is trying to clean up.
	// 5.9.2g: in-kernel measurement-harness exclusion. Every BPF object has its
	// OWN observer_root_pid map (the same per-object arrangement that made
	// P0-22 populate comm_filter_map once per collector), so the registry holds
	// one controller per collector rather than a single global one, and the
	// root PID is published to all of them. Collectors register from their own
	// status-reporter goroutines as they come up, concurrently with the poller
	// below — hence the mutex and the replay of the last known root.
	observerFilters := &observerFilterRegistry{}

	// ringbufFullTrackers holds the ringbuf_full_counters map for each
	// collector sharing the `events` ring buffer (syscall, network,
	// fileaccess), so the periodic stats loop below can publish
	// ebpf_guard_events_dropped_total{collector,reason="ringbuf_full"} — the
	// kernel-side loss counter added by 5.9.6a (№71) so a full ring buffer is
	// no longer silently absorbed. See kernelCounterRegistry for the drain.
	ringbufFullTrackers := &kernelCounterRegistry{
		sink: func(collector string, delta uint64) {
			exporter.RecordDroppedN(collector, "ringbuf_full", delta)
		},
	}
	// emittedTrackers holds the events_emitted_counters map for the same
	// three collectors — the kernel-side count of successful reserves,
	// the left-hand side of 5.9.6b's (№72) event balance identity.
	emittedTrackers := &kernelCounterRegistry{
		sink: exporter.RecordEmittedKernelN,
	}

	if cfg.Correlator.ObserverExclude.Enabled {
		rootPIDFile := cfg.Correlator.ObserverExclude.RootPIDFile
		slog.Info("correlator: observer-root-pid poller starting (5.9a, test-only)",
			slog.String("root_pid_file", rootPIDFile))
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			var lastPID uint64
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					data, readErr := os.ReadFile(rootPIDFile)
					if readErr != nil {
						continue
					}
					pid, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
					if parseErr != nil || pid == 0 {
						continue
					}
					if pid != lastPID {
						slog.Info("correlator: observer root PID updated",
							slog.Uint64("root_pid", pid))
						lastPID = pid
					}
					// The userspace filter stays configured as the fallback:
					// if no BPF object accepted the root (verifier rejection,
					// stub build, collector not up yet), observerFilters.
					// publish reports 0 and the engine keeps doing the walk.
					engine.SetObserverRoot(uint32(pid))                                    /* #nosec G115 -- bounded by ParseUint bitSize 32 */
					engine.SetObserverKernelSide(observerFilters.publish(uint32(pid)) > 0) /* #nosec G115 -- bounded by ParseUint bitSize 32 */
				}
			}
		}()
	}

	// Restore learned EWMA anomaly-detector state from a previous run so
	// restarts (common in a Kubernetes DaemonSet) don't reset the learning
	// timer to zero every time. See ISSUES-attack-run-2026-08-03.md P0-3.
	//
	// This must run against engine.SaveState/LoadState, not prof.SaveState/
	// LoadState: once anomaly detection is enabled, IngestAsync routes events
	// exclusively through the engine's per-worker detector pool
	// (CorrelationEngine.anomalyDetectors()), never through prof's own
	// detector. It also must run here, after NewCorrelationEngineWithConfig,
	// not before: the engine constructs its detector pool and switches every
	// detector onto one shared *BaselineLearner as part of that call, and
	// loading state earlier would be immediately overwritten by that
	// construction (SetSharedLearner resets learningComplete on every
	// detector it touches).
	if prof != nil && cfg.Profiler.StatePersistence.Enabled {
		learningPeriod := time.Duration(cfg.Profiler.LearningPeriod) * time.Second
		if ready, loadErr := engine.LoadState(cfg.Profiler.StatePersistence.Path, learningPeriod); loadErr != nil {
			slog.Warn("profiler: failed to load persisted state, starting fresh",
				slog.String("path", cfg.Profiler.StatePersistence.Path),
				slog.Any("error", loadErr))
			exporter.ProfilerStateRestored.Set(0)
		} else {
			slog.Info("profiler: restored persisted state",
				slog.String("path", cfg.Profiler.StatePersistence.Path),
				slog.Bool("learning_complete", ready))
			exporter.ProfilerStateRestored.Set(1)
		}

		saveInterval := time.Duration(cfg.Profiler.StatePersistence.SaveIntervalSeconds) * time.Second
		if saveInterval <= 0 {
			saveInterval = 5 * time.Minute
		}
		go func() {
			ticker := time.NewTicker(saveInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if saveErr := engine.SaveState(cfg.Profiler.StatePersistence.Path); saveErr != nil {
						slog.Warn("profiler: periodic state autosave failed",
							slog.Any("error", saveErr))
					}
					if saveErr := prof.SaveAllowlistState(cfg.Profiler.StatePersistence.Path); saveErr != nil {
						slog.Warn("profiler: periodic allowlist autosave failed",
							slog.Any("error", saveErr))
					}
				}
			}
		}()
	}

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
		// Reuse tokens persisted by a previous run (see writeTokenFile) instead
		// of rotating credentials on every restart — rotating broke Prometheus
		// scraping and any client holding the old token. Only tokens not set
		// explicitly in the config are loaded from the persist file, so an
		// explicit auth.admin_token / auth.viewer_token always wins.
		pAdmin, pViewer, pErr := readTokenFile()
		if pErr != nil {
			slog.Warn("auth: cannot read persisted token file", "error", pErr)
		}
		if adminToken == "" && len(cfg.Auth.Tokens) == 0 {
			adminToken = pAdmin
		}
		if viewerToken == "" && len(cfg.Auth.Tokens) == 0 {
			viewerToken = pViewer
		}
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
	srv.SetTimeouts(cfg.Server.ReadTimeout, cfg.Server.WriteTimeout)
	srv.SetCORSAllowedOrigins(cfg.Server.CORSAllowedOrigins)
	srv.SetAlertStore(alertStore)
	srv.SetRulesProvider(func() []correlator.Rule {
		return engine.GetRules()
	})
	srv.SetIncidentTracker(engine.IncidentTracker())
	// Wires POST /api/v1/tuning/exceptions to append operator-generated
	// exceptions (from the dashboard's false-positive flow, issue #308) into
	// the same overlay file the rule loader already reads on startup/reload.
	srv.SetLocalTuningPath(cfg.Rules.LocalTuningPath)

	if gossipMgr != nil {
		srv.RegisterGossipRoutes(gossip.Handler(gossipMgr))
	}

	// Agent-health snapshot for GET /api/v1/status (issue #309): lets a VPS
	// operator without Prometheus/Grafana see load-shedding, drift-learning
	// progress, effective sampling rates, and the hardware profile without
	// parsing /metrics on the client.
	srv.SetAgentHealthProvider(func() exporter.AgentHealth {
		health := exporter.AgentHealth{HardwareProfile: hwProfile.Profile}
		if cpuWatcher != nil {
			health.CPUPressureLevel = cpuWatcher.PressureLevel()
			health.CPUPressurePercent = cpuWatcher.PressurePercent()
			health.VisibilityReduced = cpuWatcher.IsThrottling()
		}
		// P0-25: sampling throttling is not the only way visibility degrades.
		// Run #4 lost 52% of network events with sampling untouched, and this
		// field still read false. Queue drops must raise it too.
		if srv.VisibilityReduced() {
			health.VisibilityReduced = true
		}
		if rates := samplingMux.EffectiveRates(); len(rates) > 0 {
			health.SamplingRates = rates
		}
		if driftProfiler != nil {
			health.DriftLearningWorkloads = driftProfiler.LearningWorkloads()
			health.DriftStuckWorkloads = driftProfiler.StuckLearningWorkloads()
			health.DriftProfilesActive = driftProfiler.ProfileCount()
		}
		health.LearningComplete = engine.IsLearningComplete()
		health.LearningProgress = engine.LearningProgress()
		health.LearningSecondsRemaining = engine.LearningTimeRemaining().Seconds()
		health.LearningSamples = engine.LearningSampleCount()
		return health
	})

	if dbg := srv.GetDebugHandler(); dbg != nil {
		dbg.SetHardwareProfile(exporter.HardwareProfileState{
			Profile:         hwProfile.Profile,
			Source:          hwProfile.Source,
			Reason:          hwProfile.Reason,
			CPUs:            hwProfile.Hardware.CPUs,
			MemTotalMB:      hwProfile.Hardware.MemTotalMB,
			EventsMap:       hwProfile.Applied.EventsMap,
			ProcessesMap:    hwProfile.Applied.ProcessesMap,
			ConnectionsMap:  hwProfile.Applied.ConnectionsMap,
			MaxTrackedPIDs:  hwProfile.Applied.MaxTrackedPIDs,
			SequenceEnabled: hwProfile.Applied.SequenceEnabled,
			LineageEnabled:  hwProfile.Applied.LineageEnabled,
		})

		// Providers are closures, not snapshots: /debug/state must agree with
		// /metrics at request time (P1-10).
		dbg.SetEngineProvider(exporter.EngineStatsFunc(func() exporter.EngineStats {
			st := engine.GetStats()
			return exporter.EngineStats{
				TotalEvents:        st.ProcessedEvents,
				TotalAlerts:        st.AlertsGenerated,
				AlertsDropped:      st.AlertsDropped,
				RulesLoaded:        len(engine.GetRules()),
				ObserverRootPID:    engine.ObserverRoot(),
				ObserverKernelSide: engine.ObserverKernelSide(),
			}
		}))

		if prof != nil {
			// P1-10 (question 7): the live detector state lives in the engine's
			// per-worker ingest pool, not main.go's solo *profiler.Profiler.
			// Run #4 shipped profiler_stats=0/0/0/0 in /debug/state precisely
			// because this closure read prof.GetStats() off an object that
			// never receives events under IngestAsync. Aggregate over the pool
			// at request time so /debug/state agrees with /metrics.
			dbg.SetProfilerProvider(exporter.ProfilerStatsFunc(func() exporter.ProfilerStats {
				st := engine.ProfilerStats()
				return exporter.ProfilerStats{
					LearningComplete:    st.LearningComplete,
					LearningProgress:    st.LearningProgress,
					ProfilesActive:      st.ProfilesActive,
					AnomaliesTotal:      st.AnomaliesTotal,
					LearningSampleCount: st.LearningSampleCount,
				}
			}))
		}

		dbg.SetRules(convertRulesToDebugState(engine.GetRules()))
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

	// P0-25: Separate event queues by priority to prevent network/dns event loss.
	// High-priority events (network, dns) get dedicated queues to protect security signal.
	// Low-priority events (file, syscall) share a queue but are isolated from network/dns.
	highPriorityEventCh := make(chan types.Event, eventQueueDepth)
	lowPriorityEventCh := make(chan types.Event, eventQueueDepth)

	// Track queue depths for both priority levels
	engine.SetQueueDepthFn(func() int { return len(highPriorityEventCh) + len(lowPriorityEventCh) }, func() int { return cap(highPriorityEventCh) + cap(lowPriorityEventCh) })
	exporter.RecordQueueDepth(0, eventQueueDepth*2)

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

	// P1-18b: set by enablePathFilter once the fileaccess collector reports
	// up; polled by the periodic stats loop below to publish the in-kernel
	// path-filter drop count. atomic.Pointer because SetUp fires from the
	// collector's own goroutine, concurrently with the poller starting.
	var pathFilterCtrl atomic.Pointer[internalbpf.PathFilterController]

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
				ringbufFullTrackers.register("syscall", sc.RingbufFullMap())
				emittedTrackers.register("syscall", sc.EmittedMap())
				if cfg.BPF.KernelFilter.Enabled {
					comm, sys, kfCfg, agentPID := sc.KernelFilterMaps()
					enableKernelFilter("syscall", kernelFilterMapSet{comm, sys, kfCfg, agentPID}, cfg.BPF.KernelFilter)
				}
				if cfg.BPF.Sampling.Enabled {
					enableSampling("syscall", sc.SamplingConfigMap(), cfg.BPF.Sampling, samplingMux, "syscall")
				}
				if cfg.Correlator.ObserverExclude.Enabled {
					observerRoot, observerCounters := sc.ObserverFilterMaps()
					observerFilters.register("syscall", observerRoot, observerCounters)
				}
			}))
			// 5.9.2c (finding #40): same effective allowlist the "unreachable
			// rules" check above and enableKernelFilter both use, so the
			// nr_not_monitored diagnostic and the actual in-kernel filter
			// can never disagree about what "monitored" means.
			diagAllowlist := cfg.BPF.KernelFilter.MonitoredSyscalls
			if len(diagAllowlist) == 0 {
				diagAllowlist = internalbpf.DefaultMonitoredSyscalls()
			}
			sc.WithMalformedDiagnostics(diagAllowlist, cfg.BPF.KernelFilter.Enabled)
			collectors = append(collectors, sc.WithBackpressureStrategy(bpStrategy))
			slog.Info("syscall: collector enabled")
		}

		if nc, ncErr := collector.NewNetworkCollector(slog.Default()); ncErr != nil {
			slog.Warn("network: collector creation failed", slog.Any("error", ncErr))
		} else {
			// The reporter is also needed when observer exclusion is on, not
			// only for sampling: without this condition the network collector
			// would silently keep emitting harness events while syscall and
			// fileaccess dropped theirs, and the "share of the observer tree"
			// criterion would be measured against a partially filtered stream.
			// 5.9.6a: also needed unconditionally to register the kernel-side
			// ringbuf_full counter, so the reporter is now always attached.
			{
				nc.WithStatusReporter(collector.StatusReporterFunc(func(name string, up bool) {
					if name != "network" || !up {
						return
					}
					ringbufFullTrackers.register("network", nc.RingbufFullMap())
					emittedTrackers.register("network", nc.EmittedMap())
					if cfg.BPF.Sampling.Enabled {
						enableSampling("network", nc.SamplingConfigMap(), cfg.BPF.Sampling, samplingMux, "network")
					}
					if cfg.Correlator.ObserverExclude.Enabled {
						observerRoot, observerCounters := nc.ObserverFilterMaps()
						observerFilters.register("network", observerRoot, observerCounters)
					}
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
			// 5.9.6a: unconditionally attached now to register the kernel-side
			// ringbuf_full counter, not only for the sampling/filter/observer
			// options below.
			{
				fc.WithStatusReporter(collector.StatusReporterFunc(func(name string, up bool) {
					if name != "fileaccess" || !up {
						return
					}
					ringbufFullTrackers.register("fileaccess", fc.RingbufFullMap())
					emittedTrackers.register("fileaccess", fc.EmittedMap())
					// P0-22 (wave 0.5): fileaccess.bpf.c consults its OWN copies
					// of comm_filter_map / kernel_filter_config / agent_pid_map.
					// Populating the syscall collector's maps leaves these zeroed,
					// which would silently disable both the comm denylist and the
					// agent self-exclusion for the collector producing 99.4% of
					// the event stream.
					if cfg.BPF.KernelFilter.Enabled {
						comm, sys, kfCfg, agentPID := fc.KernelFilterMaps()
						enableKernelFilter("fileaccess", kernelFilterMapSet{comm, sys, kfCfg, agentPID}, cfg.BPF.KernelFilter)
						// P1-18b: path-prefix denylist only exists in
						// fileaccess.bpf.c — no other collector's programs
						// consult path_filter_map.
						if len(cfg.BPF.KernelFilter.PathDenylist) > 0 {
							pathMap, dropCounters := fc.PathFilterMaps()
							if pf := enablePathFilter("fileaccess", pathMap, dropCounters, cfg.BPF.KernelFilter.PathDenylist); pf != nil {
								pathFilterCtrl.Store(pf)
							}
						}
					}
					if cfg.BPF.Sampling.Enabled {
						enableSampling("fileaccess", fc.SamplingConfigMap(), cfg.BPF.Sampling, samplingMux, "file")
					}
					if cfg.Correlator.ObserverExclude.Enabled {
						observerRoot, observerCounters := fc.ObserverFilterMaps()
						observerFilters.register("fileaccess", observerRoot, observerCounters)
					}
				}))
			}
			collectors = append(collectors, fc.WithBackpressureStrategy(bpStrategy))
			slog.Info("fileaccess: collector enabled",
				slog.Bool("track_open", fo.TrackOpen),
				slog.Bool("track_read", fo.TrackRead),
				slog.Bool("track_write", fo.TrackWrite),
			)
			// P2-12: *_write/*_modified rules require a real write event. If
			// the collector never emits one, those rules are inert — say so
			// loudly rather than letting the operator assume they are armed.
			if !fo.TrackWrite {
				if inert := correlator.RulesRequiringFileOp(engine.GetRules(), "write"); len(inert) > 0 {
					slog.Warn("fileaccess: write-dependent rules are inert — "+
						"collectors.file_ops.track_write is false, so no write events are produced "+
						"and these rules can never match",
						slog.Int("rules_disabled", len(inert)),
						slog.Any("rule_ids", inert),
					)
				}
			}
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

	// P0-25: track drops so /health can report degraded visibility. Run #4 lost
	// 52% of network events while reporting visibility_reduced:false; the whole
	// point of these counters is that any nonzero drop rate becomes visible.
	var highPriorityDrops atomic.Int64
	var lowPriorityDrops atomic.Int64
	var highPriorityAccepted atomic.Int64
	var lowPriorityAccepted atomic.Int64

	// 5.9.2a (finding #38): the drop-time watcher that degradation status reads
	// now lives in exporter.RecordEventDrop, shared with every collector's
	// ringbuf_to_router hop (internal/collector/*.go) — not tracked locally
	// here any more, so a hop this closure doesn't see can't go unnoticed by
	// /health the way ringbuf_to_router previously did.
	recordEventDrop := func(collectorName string, isHighPriority bool) {
		if isHighPriority {
			highPriorityDrops.Add(1)
		} else {
			lowPriorityDrops.Add(1)
		}
		// reason=router_to_queue: dropped between the priority router and the
		// hi/lo queue (plan.md 1.5c). Distinguished from ringbuf_to_router so a
		// zero on network/dns can be attributed to a specific hop instead of an
		// aggregate that hides which stage actually lost the event.
		exporter.RecordEventDrop(collectorName, "router_to_queue", isHighPriority)
	}

	// Accepted events are the denominator of the loss fraction; without them a
	// drop count cannot be turned into "we lost 52% of network events".
	recordEventAccepted := func(_ string, isHighPriority bool) {
		if isHighPriority {
			highPriorityAccepted.Add(1)
		} else {
			lowPriorityAccepted.Add(1)
		}
	}

	// P0-25: wrap every collector so its events are routed by type into the
	// protected (network/dns/syscall/…) or bulk (file) queue instead of all
	// sharing one channel that the file stream fills.
	priorityCollectors := make([]collector.Collector, 0, len(collectors))
	for _, c := range collectors {
		priorityCollectors = append(priorityCollectors,
			collector.NewPriorityEventCollector(c, highPriorityEventCh, lowPriorityEventCh, bpStrategy, recordEventDrop, recordEventAccepted, slog.Default()))
	}

	for _, c := range priorityCollectors {
		exporter.SetCollectorUp(c.Name(), true)
		srv.SetCollectorStatus(exporter.CollectorStatus{Name: c.Name(), Healthy: true})
		go func(c collector.Collector) {
			// The wrapper routes internally; this argument is unused by it.
			if err := c.Start(ctx, lowPriorityEventCh); err != nil && ctx.Err() == nil {
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
			newRules, err := loadRulesWithTuning(newCfg.Rules.Path, newCfg.Rules.LocalTuningPath)
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
			// Keep /debug/state's rule list in sync with the engine (P1-10).
			if dbg := srv.GetDebugHandler(); dbg != nil {
				dbg.SetRules(convertRulesToDebugState(newRules))
			}
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
				exporter.RecordQueueDepth(len(highPriorityEventCh)+len(lowPriorityEventCh), cap(highPriorityEventCh)+cap(lowPriorityEventCh))
				exporter.SetGoroutinePoolActive(activeWorkers.Load())
			}
		}
	}()

	// Background: publish BPF map size (static) and tracked-PIDs count every 15s.
	exporter.SetBPFMapSize("events", float64(cfg.BPF.MapSizes.Events))
	exporter.SetBPFMapSize("processes", float64(cfg.BPF.MapSizes.Processes))
	exporter.SetBPFMapSize("connections", float64(cfg.BPF.MapSizes.Connections))
	exporter.SetBPFMapEntries("events", 0)
	exporter.SetBPFMapEntries("processes", 0)
	exporter.SetBPFMapEntries("connections", 0)
	// Initialise events_dropped label sets so the series appear even at zero.
	// Both hops are pre-registered per collector (plan.md 1.5c): a run-gate
	// summing "network"/"dns" series for zero loss must see both reasons
	// present, or an all-zero read is indistinguishable from a missing series.
	for _, name := range []string{"syscall", "network", "fileaccess", "dns"} {
		exporter.EventsDropped.WithLabelValues(name, "ringbuf_to_router")
		exporter.EventsDropped.WithLabelValues(name, "router_to_queue")
	}
	// 5.9.6a (№71): pre-register the kernel ring-buffer-full series for the
	// three collectors sharing the `events` ring buffer's reserve_event()/
	// reserve_event_with_sampling() macros. privesc is excluded — its
	// collector is not currently instantiated in this startup sequence (see
	// plan.md 5.9.6a open questions), so pre-registering it here would print
	// a permanently-zero series for a collector that never runs.
	for _, name := range []string{"syscall", "network", "fileaccess"} {
		exporter.EventsDropped.WithLabelValues(name, "ringbuf_full")
		// 5.9.6b (№72): same three collectors, the balance identity's
		// left-hand side.
		exporter.EventsEmittedKernel.WithLabelValues(name)
	}
	// P1-18b: pre-register the path_denylist series too, and track the
	// cumulative BPF-side total so the 15s poll below can report deltas
	// (RecordDroppedN adds to a Prometheus counter — feeding it the
	// cumulative value every tick would double-count).
	exporter.EventsDropped.WithLabelValues("fileaccess", "path_denylist")
	var lastPathFilterDropTotal uint64
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		const logEvery = 4 // log learning progress roughly once a minute, not every 15s
		tick := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				progress := engine.LearningProgress()
				complete := engine.IsLearningComplete()
				remaining := engine.LearningTimeRemaining()
				exporter.SetLearningProgress(progress)
				exporter.SetLearningComplete(complete)
				exporter.SetLearningSecondsRemaining(remaining)
				exporter.SetTrackedPIDs(float64(engine.TrackedPIDCount()))

				// 5.9.6a (№71): drain the kernel ring-buffer-full counters onto
				// ebpf_guard_events_dropped_total{reason="ringbuf_full"} so a
				// full ring buffer shows up as a visible, growing number
				// per collector instead of being absorbed as an unexplained
				// gap between events_total and the actual syscall/connection/
				// file-op rate.
				ringbufFullTrackers.drain()
				emittedTrackers.drain()

				// P1-18b: publish the in-kernel path-filter drop count so a
				// wrong denylist prefix shows up as a visible, growing
				// number instead of quietly reducing file-event volume.
				// RecordDroppedN adds to the counter, so this must report the
				// delta since the last tick, not the cumulative total.
				// 5.9.2g: drain the in-kernel observer-exclusion counter onto
				// the same series 5.9a published from the correlator, so the
				// "share of the observer tree" criterion keeps being computed
				// from one metric across both implementations. Delta, not
				// total — see RecordObserverExcludedN.
				if delta := observerFilters.drainExcluded(); delta > 0 {
					engine.RecordObserverExcludedN(delta)
				}

				if pf := pathFilterCtrl.Load(); pf != nil {
					if total, err := pf.ReadPathFilterDropCount(); err != nil {
						slog.Warn("path_filter: failed to read drop counter", slog.Any("error", err))
					} else if total < lastPathFilterDropTotal {
						// The BPF counter went backwards — the map was
						// recreated (collector reload) and restarted from a
						// lower value. Re-baseline instead of subtracting:
						// unsigned wraparound here would add ~2^64 to the
						// Prometheus counter in one tick and destroy the
						// series for the rest of the process's life.
						slog.Debug("path_filter: drop counter reset, re-baselining",
							slog.Uint64("previous", lastPathFilterDropTotal),
							slog.Uint64("current", total))
						lastPathFilterDropTotal = total
					} else if delta := total - lastPathFilterDropTotal; delta > 0 {
						exporter.RecordDroppedN("fileaccess", "path_denylist", delta)
						lastPathFilterDropTotal = total
					}
				}

				tick++
				if cfg.Profiler.Enabled && !complete && tick%logEvery == 0 {
					slog.Info("profiler: learning in progress",
						slog.String("progress", fmt.Sprintf("%.0f%%", progress*100)),
						slog.Duration("time_remaining", remaining.Round(time.Second)),
						slog.Uint64("samples", engine.LearningSampleCount()))
				}
			}
		}
	}()

	// metricsNodeName labels the ebpf_guard_events_total / ebpf_guard_alerts_total
	// node dimension so the fleet-wide Grafana dashboard can attribute events and
	// alerts to a node even when Kubernetes enrichment is disabled (bare-metal/VM
	// fleets). Prefers per-event Enrichment.NodeName (set by the k8s enricher) and
	// falls back to this agent's own node identity.
	metricsNodeName := resolveMetricsNodeName()

	// alertAggregator folds repeated alerts sharing the same rule/comm/path-prefix/
	// pod key within a time window into a single alert with a running count,
	// so an operator sees one incident instead of a storm of identical rows.
	// Disabled by default; see correlator.alert_aggregation in config.yaml.
	alertAggWindow, err := time.ParseDuration(cfg.Correlator.AlertAggregation.Window)
	if err != nil || alertAggWindow <= 0 {
		alertAggWindow = 60 * time.Second
	}
	alertAggregator := correlator.NewAlertAggregator(correlator.AlertAggregationConfig{
		Enabled: cfg.Correlator.AlertAggregation.Enabled,
		Window:  alertAggWindow,
	})

	// storeMinSeverity gates admission to ebpf_guard_alerts_total and the alert
	// store (wave 5.1a). Default "info" admits everything, so an unset or empty
	// value cannot silently start dropping a severity tier; the value is
	// validated at load time, so anything else here is one of the three known
	// severities.
	storeMinSeverity := types.SeverityInfo
	if cfg.Store.MinSeverity != "" {
		storeMinSeverity = types.Severity(cfg.Store.MinSeverity)
	}
	if storeMinSeverity != types.SeverityInfo {
		slog.Info("alert intake filter active: alerts below the threshold are excluded from alerts_total and the store, but their rules still fire and their volume is counted in ebpf_guard_alerts_filtered_total",
			slog.String("store_min_severity", string(storeMinSeverity)))
	}

	// forwardAlerts fans a batch of alerts out to every configured sink: the
	// simple-mode auto-enforcer, attack-simulation collector, alert store,
	// Alertmanager webhook, notification fanout, and cross-node gossip.
	forwardAlerts := func(dispatched []types.Alert) {
		if len(dispatched) == 0 {
			return
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

	// dispatchAlerts records per-event Prometheus metrics for every raw alert —
	// RecordAlert always sees the un-aggregated stream, so ebpf_guard_alerts_total
	// stays per-event regardless of aggregation — then hands the batch to
	// alertAggregator.Ingest, which forwards new aggregation keys immediately
	// and folds repeats into their running count. Closed-window summaries for
	// keys that received repeats are forwarded separately by the Reap ticker
	// below.
	dispatchAlerts := func(dispatched []types.Alert) {
		// Wave 5.1a: hold alerts below store.min_severity out of both intake
		// sinks — the counter and the store — rather than only out of the
		// notifiers. Wave 5.1 downgraded the seven-rule daemon cluster to info
		// and measured no change in volume (4986/hour against a <1000 target):
		// alerts_total counts every alert regardless of severity, so lowering
		// severity alone moves nothing. The rules stay loaded and keep firing;
		// what they produce is counted in alerts_filtered_total instead, so the
		// suppressed volume stays visible (порядок работы, п. 8).
		//
		// The filter runs before aggregation so a filtered alert cannot re-enter
		// through a window summary, and admitted alerts keep flowing to
		// forwardAlerts unchanged.
		admitted := exporter.FilterAlertsForIntake(dispatched, storeMinSeverity)
		for _, a := range admitted {
			podName, namespace, node := a.Enrichment.PodName, a.Enrichment.Namespace, a.Enrichment.NodeName
			if node == "" {
				node = metricsNodeName
			}
			exporter.RecordAlert(a.RuleID, string(a.Severity), namespace, podName, node)
			if a.RuleID == "anomaly_detection" {
				exporter.RecordAnomaly()
			}
		}
		forwardAlerts(alertAggregator.Ingest(admitted, time.Now()))
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

	// Background: close out expired alert-aggregation windows and forward the
	// final count/first_seen/last_seen for any key that received repeats
	// within its window. The first occurrence of a key already went out
	// immediately via dispatchAlerts; this ticker is what turns "216 more
	// alerts suppressed" into one visible summary instead of silence.
	if cfg.Correlator.AlertAggregation.Enabled {
		reapInterval := alertAggWindow / 2
		if reapInterval < time.Second {
			reapInterval = time.Second
		}
		go func() {
			ticker := time.NewTicker(reapInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					forwardAlerts(alertAggregator.Reap(time.Now()))
				}
			}
		}()
	}

	// P0-25 / plan.md 1.5b: publish visibility degradation whenever ANY queue
	// (protected or bulk) is dropping events — the plan's literal criterion.
	// Previously only protected-queue drops raised degradation, so a run that
	// lost fim_*/canary_*/cred_* signal to bulk-queue drops would still read
	// /health: healthy — exactly the "mechanism silently fails, indicator shows
	// success" defect the whole wave exists to close. DegradedQueues tells the
	// two cases apart (signal loss vs. expected volume shedding) so raising
	// bulk drops to degraded doesn't itself get ignored as noise.
	// The state is sticky for degradationThreshold after the last drop so a
	// bursty loss does not flap between scrapes, and it is driven by the drop
	// counters themselves — not by whether sampling was reduced, which is what
	// let run #4 report visibility_reduced:false while losing 52% of network
	// events.
	const degradationThreshold = 5 * time.Second
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var degraded bool
		var prevHiDrop, prevLoDrop, prevHiOK, prevLoOK int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hiDrop, loDrop := highPriorityDrops.Load(), lowPriorityDrops.Load()
				hiOK, loOK := highPriorityAccepted.Load(), lowPriorityAccepted.Load()

				// Publish the loss ratio per window, not just the counter: 52%
				// of network events is invisible as an absolute number next to
				// a million file events (P0-25, item 3).
				exporter.EventsDroppedFraction.WithLabelValues("protected").
					Set(lossFraction(hiDrop-prevHiDrop, hiOK-prevHiOK))
				exporter.EventsDroppedFraction.WithLabelValues("bulk").
					Set(lossFraction(loDrop-prevLoDrop, loOK-prevLoOK))

				// 5.9.2a: both hops (ringbuf_to_router, in each collector's
				// readLoop, and router_to_queue, in recordEventDrop above) feed
				// exporter.RecordEventDrop, so a drop at either one marks these
				// timestamps — not just router_to_queue as before.
				lastHiDrop := exporter.LastHighPriorityDropTime()
				lastLoDrop := exporter.LastLowPriorityDropTime()
				hiDegraded := lastHiDrop > 0 && time.Since(time.Unix(0, lastHiDrop)) < degradationThreshold
				loDegraded := lastLoDrop > 0 && time.Since(time.Unix(0, lastLoDrop)) < degradationThreshold
				nowDegraded := hiDegraded || loDegraded

				var queues []string
				if hiDegraded {
					queues = append(queues, "protected")
				}
				if loDegraded {
					queues = append(queues, "bulk")
				}
				srv.SetDegradedQueues(queues)

				if nowDegraded != degraded {
					degraded = nowDegraded
					srv.SetVisibilityReduced(degraded)
					if degraded {
						// 5.9.2a: the aggregate protected/bulk counters above only
						// ever counted router_to_queue drops, so an operator
						// looking at this line could not tell "losing fim signal"
						// (fileaccess/ringbuf_to_router) from "shedding file
						// noise" (any other collector/hop) — exactly the
						// ambiguity DegradedQueues was introduced to resolve, but
						// one level too coarse. breakdown gives the same
						// distinction per collector and hop.
						slog.Warn("visibility reduced: a priority queue is dropping events",
							slog.String("status", "degraded"),
							slog.Any("degraded_queues", queues),
							slog.Int64("protected_dropped_since_start", hiDrop),
							slog.Int64("protected_dropped_in_window", hiDrop-prevHiDrop),
							slog.Int64("bulk_dropped_since_start", loDrop),
							slog.Int64("bulk_dropped_in_window", loDrop-prevLoDrop),
							slog.Any("dropped_by_collector_and_hop", exporter.DropBreakdownSnapshot()))
					} else {
						slog.Info("visibility restored: all priority queues flowing normally",
							slog.Int64("protected_dropped_since_start", hiDrop),
							slog.Int64("bulk_dropped_since_start", loDrop))
					}
				}
				prevHiDrop, prevLoDrop, prevHiOK, prevLoOK = hiDrop, loDrop, hiOK, loOK
			}
		}
	}()

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
				cfg.Server.ShutdownTimeout, cfg.Server.ShutdownDrainEnforcement, cfg.Server.ShutdownDrainRego,
				prof, cfg.Profiler.StatePersistence)
			return nil

		// P0-25: protected queue (network/dns/syscall/…) first.
		//
		// A plain two-case select would NOT prioritise: when both channels are
		// ready Go picks a uniformly random case, so at 5800 file ev/s against
		// 33 network ev/s the protected queue would still be serviced ~50% of
		// the time only by luck of arrival. The non-blocking drain below makes
		// the preference explicit — the bulk queue is only read once the
		// protected queue is empty.
		case event, ok := <-highPriorityEventCh:
			if !ok {
				return nil
			}
			processEvent(ctx, event, eventLog, k8sEnricher, runtimeEnricher, metricsNodeName, engine, driftDetector, &driftSeq, cfg, dispatchAsync)

		case event, ok := <-lowPriorityEventCh:
			if !ok {
				return nil
			}
			// Before spending time on a bulk event, yield to anything that
			// arrived on the protected queue in the meantime.
			drained := 0
		drain:
			for drained < maxProtectedDrainBurst {
				select {
				case hi, hiOK := <-highPriorityEventCh:
					if !hiOK {
						return nil
					}
					processEvent(ctx, hi, eventLog, k8sEnricher, runtimeEnricher, metricsNodeName, engine, driftDetector, &driftSeq, cfg, dispatchAsync)
					drained++
				default:
					break drain
				}
			}
			processEvent(ctx, event, eventLog, k8sEnricher, runtimeEnricher, metricsNodeName, engine, driftDetector, &driftSeq, cfg, dispatchAsync)
		}
	}
}

// maxProtectedDrainBurst caps how many protected-queue events are handled
// before the already-dequeued bulk event is processed. Without a cap, a
// sustained protected-queue burst could starve file events entirely; with it,
// bulk throughput degrades gracefully instead of stopping.
const maxProtectedDrainBurst = 64

// processEvent handles a single event through the enrichment and correlation pipeline.
func processEvent(
	ctx context.Context,
	event types.Event,
	eventLog *store.EventLog,
	k8sEnricher *k8s.Enricher,
	runtimeEnricher *runtime.Enricher,
	metricsNodeName string,
	engine *correlator.CorrelationEngine,
	driftDetector *drift.Detector,
	driftSeq *atomic.Uint64,
	cfg *config.Config,
	dispatchAsync func([]types.Alert),
) {
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
// enableKernelFilter populates a collector's BPF-side content filter (comm
// denylist + syscall allowlist + agent self-exclusion PID) and turns it on.
// Without this, raw_syscalls/sys_enter and sys_exit forward every syscall on
// the host to the ring buffer — on a busy node that overwhelms the event
// channel within seconds. Called once the collector reports its BPF maps are
// loaded.
//
// The filter maps are declared in bpf/common.h, which means each compiled BPF
// object owns a SEPARATE instance of them. Populating the syscall collector's
// maps does nothing for the fileaccess programs, so this must be called once
// per collector whose programs consult the filter — hence the `name` label and
// the map arguments rather than a concrete collector type.
func enableKernelFilter(name string, maps kernelFilterMapSet, fc config.KernelFilterConfig) {
	kf, err := internalbpf.NewKernelFilterController(maps.comm, maps.syscall, maps.cfg, maps.agentPid)
	if err != nil {
		slog.Warn("kernel_filter: maps unavailable, events forwarded unfiltered",
			slog.String("collector", name), slog.Any("error", err))
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
		slog.String("collector", name),
		slog.Int("monitored_syscalls", len(nrs)),
		slog.Int("comm_denylist", len(denylist)),
		slog.Bool("daemon_denylist_disabled", fc.DisableDefaultDaemonDenylist))

	// P0-22 (wave 0.5): self-exclusion by the agent's own PID, so the agent's
	// SQLite writes, audit.jsonl appends and API responses stop generating the
	// events that feed them. Keyed on PID, never on path — another process
	// touching the agent's files stays fully visible.
	if maps.agentPid != nil {
		agentPID := uint32(os.Getpid())
		if err := kf.SetAgentPID(agentPID); err != nil {
			slog.Warn("kernel_filter: set agent pid failed",
				slog.String("collector", name),
				slog.Uint64("pid", uint64(agentPID)), slog.Any("error", err))
		} else {
			slog.Info("kernel_filter: agent self-exclusion enabled",
				slog.String("collector", name),
				slog.Uint64("agent_pid", uint64(agentPID)))
		}
	} else {
		slog.Warn("kernel_filter: agent_pid_map unavailable, self-exclusion inactive",
			slog.String("collector", name))
	}
}

// enablePathFilter populates path_filter_map with the configured path-prefix
// denylist (P1-18b) and returns the controller so the caller can poll
// ReadPathFilterDropCount for the ebpf_guard_events_dropped_total{reason=
// "path_denylist"} metric. Returns nil if the maps are unavailable (stub
// mode) or the update fails — the caller logs and continues unfiltered
// rather than blocking startup on a diagnostic feature.
//
// Unlike enableKernelFilter's comm/syscall filters, an empty prefix list is
// a no-op here by construction (main.go only calls this when
// len(PathDenylist) > 0), and PathFilterController.SetDenylist itself
// refuses an empty-string prefix — the two-layer guard against
// "accidentally deny everything" is intentional given P1-18b's risk note.
func enablePathFilter(name string, pathMap, dropCounters *ebpf.Map, prefixes []string) *internalbpf.PathFilterController {
	pf, err := internalbpf.NewPathFilterController(pathMap, dropCounters)
	if err != nil {
		slog.Warn("path_filter: map unavailable, path denylist inactive",
			slog.String("collector", name), slog.Any("error", err))
		return nil
	}
	if err := pf.SetDenylist(prefixes); err != nil {
		slog.Error("path_filter: failed to load path denylist",
			slog.String("collector", name), slog.Any("error", err))
		return nil
	}
	slog.Info("path_filter: enabled BPF-side path-prefix denylist",
		slog.String("collector", name),
		slog.Int("prefixes", len(prefixes)))
	return pf
}

// lossFraction returns dropped/(dropped+accepted) for one window, or 0 when
// the window carried no events at all — an idle queue is not a lossy one.
func lossFraction(dropped, accepted int64) float64 {
	if dropped < 0 {
		dropped = 0
	}
	if accepted < 0 {
		accepted = 0
	}
	total := dropped + accepted
	if total == 0 {
		return 0
	}
	return float64(dropped) / float64(total)
}

// kernelFilterMapSet groups the four BPF maps that back one compiled object's
// content filter. Each BPF object has its own copies (the maps live in
// bpf/common.h), so they are always passed and populated as a set.
type kernelFilterMapSet struct {
	comm     *ebpf.Map
	syscall  *ebpf.Map
	cfg      *ebpf.Map
	agentPid *ebpf.Map
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
	// reduce this collector's sampling rate under load, and publish the
	// operator-configured base rate to the arbiter so recovery restores this
	// value rather than a hardcoded 1.0 (#304).
	if mux != nil {
		mux.Register(eventType, ctrl)
		var configured uint32
		switch eventType {
		case "syscall":
			configured = sc.SyscallRate
		case "network":
			configured = sc.NetworkRate
		case "file":
			configured = sc.FileRate
		}
		mux.SetBaseRate(eventType, sampleRateToFloat(configured))
	}
	slog.Info("sampling: enabled BPF-side static sample rate",
		slog.String("collector", name),
		slog.Uint64("syscall_rate", uint64(sc.SyscallRate)),
		slog.Uint64("network_rate", uint64(sc.NetworkRate)),
		slog.Uint64("file_rate", uint64(sc.FileRate)))
}

// sampleRateToFloat converts a BPF 1-in-N sampling rate (0 = disabled, 1 = all
// events) into the float rate in [0,1] used by the sampling arbiter.
func sampleRateToFloat(oneInN uint32) float64 {
	if oneInN == 0 {
		return 0 // disabled
	}
	return 1.0 / float64(oneInN)
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
	prof *profiler.Profiler,
	statePersistence config.StatePersistenceConfig,
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

	// Persist learned EWMA/allowlist state so the next restart doesn't reset
	// the learning timer to zero. See ISSUES-attack-run-2026-08-03.md P0-3.
	// EWMA state is saved from engine (the detector pool IngestAsync actually
	// routes events through); allowlist state from prof (unaffected — see
	// Profiler.SaveAllowlistState).
	//
	// prof != nil tracks cfg.Profiler.Enabled, which is also what gates the
	// engine's detector pool. Keeping the check here means a run with the
	// profiler off never even attempts a save — SaveDetectorsState refuses to
	// truncate an existing file in that case, but the intent belongs at the
	// call site as well as in the callee.
	if prof != nil && statePersistence.Enabled {
		slog.Info("graceful shutdown: saving profiler state",
			slog.String("path", statePersistence.Path))
		if err := engine.SaveState(statePersistence.Path); err != nil {
			slog.Warn("graceful shutdown: profiler state save error", slog.Any("error", err))
		}
		if err := prof.SaveAllowlistState(statePersistence.Path); err != nil {
			slog.Warn("graceful shutdown: allowlist state save error", slog.Any("error", err))
		}
	}

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
// directory instead of the real /var/lib/ebpf-guard.
//
// /var/lib (not /run) is intentional: /run is ephemeral and cleared on reboot,
// so a token persisted there would not survive a host restart and the agent
// would rotate credentials on every boot, breaking Prometheus scraping.
// /var/lib/ebpf-guard persists across reboots, so a generated token is stable
// for the lifetime of the installation unless the operator deletes the file.
var tokenFileDir = "/var/lib/ebpf-guard" // #nosec G101 -- filesystem directory path for the token file, not a credential value

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

// readTokenFile loads admin/viewer tokens previously persisted by writeTokenFile
// from <tokenFileDir>/token. It is called at startup so the agent reuses the
// same credentials across restarts instead of generating new ones each time.
// Returns empty strings with no error when the file does not exist (first run);
// a malformed line is skipped rather than fatal.
func readTokenFile() (adminToken, viewerToken string, err error) {
	tokenPath := tokenFileDir + "/token"
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", fmt.Errorf("read %s: %w", tokenPath, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "admin":
			adminToken = strings.TrimSpace(v)
		case "viewer":
			viewerToken = strings.TrimSpace(v)
		}
	}
	return adminToken, viewerToken, nil
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

func newStatusCmd(cfgPath *string) *cobra.Command {
	var (
		url   string
		token string
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show live agent status, including profiler learning progress",
		RunE: func(_ *cobra.Command, _ []string) error {
			if url == "" {
				url = defaultStatusURL(*cfgPath)
			}
			if token == "" {
				token = defaultStatusToken(*cfgPath)
			}

			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return fmt.Errorf("build request: %w", err)
			}
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				return fmt.Errorf("request %s: %w (is the agent running? use --url to point at a different agent)", url, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("%s returned %s: %s", url, resp.Status, strings.TrimSpace(string(body)))
			}

			var status exporter.StatusAPIResponse
			if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
				return fmt.Errorf("decode status response: %w", err)
			}

			fmt.Printf("healthy: %v   ready: %v   uptime: %s\n", status.Healthy, status.Ready, status.Uptime)
			fmt.Printf("store: %s\n", status.Store)
			for _, c := range status.Collectors {
				state := "up"
				if !c.Healthy {
					state = "down: " + c.Error
				}
				fmt.Printf("  collector %-12s %s\n", c.Name, state)
			}

			if status.Health == nil {
				fmt.Println("\nlearning: unknown (agent-health provider not configured)")
				return nil
			}
			h := status.Health
			fmt.Println()
			if h.LearningComplete {
				fmt.Println("learning: complete")
			} else {
				fmt.Printf("learning: %.0f%% complete, ~%s remaining, %d samples\n",
					h.LearningProgress*100,
					time.Duration(h.LearningSecondsRemaining*float64(time.Second)).Round(time.Second),
					h.LearningSamples)
			}
			if h.VisibilityReduced {
				fmt.Printf("visibility: REDUCED (cpu pressure level %d, %.0f%% cpu)\n", h.CPUPressureLevel, h.CPUPressurePercent)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&url, "url", "", "agent status endpoint (default: derived from --config's server.bind_address)")
	cmd.Flags().StringVar(&token, "token", "", "bearer token for authenticated agents (default: read from config or the persisted token file)")
	return cmd
}

// defaultStatusURL derives the GET /api/v1/status URL from the agent's own
// config file so `ebpf-guard status` works out of the box on the same host
// without requiring --url for the common case.
func defaultStatusURL(cfgPath string) string {
	bind := ":9090"
	if cfgManager, err := config.NewManagerSkipPermCheck(cfgPath); err == nil {
		if b := cfgManager.Get().Server.BindAddress; b != "" {
			bind = b
		}
	}
	host := "127.0.0.1"
	port := bind
	if idx := strings.LastIndex(bind, ":"); idx >= 0 {
		if h := bind[:idx]; h != "" && h != "0.0.0.0" && h != "::" {
			host = h
		}
		port = bind[idx:]
	}
	return "http://" + host + port + "/api/v1/status"
}

// defaultStatusToken resolves a bearer token for `ebpf-guard status` from the
// config file, falling back to the persisted token file written on first run
// (see writeTokenFile) when auth tokens were auto-generated.
func defaultStatusToken(cfgPath string) string {
	if cfgManager, err := config.NewManagerSkipPermCheck(cfgPath); err == nil {
		cfg := cfgManager.Get()
		if cfg.Auth.AdminToken != "" {
			return cfg.Auth.AdminToken
		}
		if cfg.Auth.BearerToken != "" {
			return cfg.Auth.BearerToken
		}
	}
	if admin, _, err := readTokenFile(); err == nil && admin != "" {
		return admin
	}
	return ""
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

			rules, err := loadRulesWithTuning(cfg.Rules.Path, cfg.Rules.LocalTuningPath)
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

	rules, _ := loadRulesWithTuning(cfg.Rules.Path, cfg.Rules.LocalTuningPath)

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

// applyRuntimeTuning applies the resolved hardware profile's GOMEMLIMIT/GOGC
// preset (lite only, currently) so the process stays within a small VPS's
// memory budget without operator intervention. No-op for profiles that don't
// set a ratio/percent (balanced, production keep the Go runtime defaults).
func applyRuntimeTuning(hw config.HardwareProfileInfo) {
	if hw.Applied.GOMEMLIMITRatio > 0 && hw.Hardware.MemTotalMB > 0 {
		limitBytes := int64(float64(hw.Hardware.MemTotalMB) * hw.Applied.GOMEMLIMITRatio * 1024 * 1024)
		debug.SetMemoryLimit(limitBytes)
		slog.Info("runtime tuning: GOMEMLIMIT set",
			slog.Int64("limit_bytes", limitBytes),
			slog.Float64("ratio", hw.Applied.GOMEMLIMITRatio))
	}
	if hw.Applied.GOGCPercent > 0 {
		debug.SetGCPercent(hw.Applied.GOGCPercent)
		slog.Info("runtime tuning: GOGC set", slog.Int("percent", hw.Applied.GOGCPercent))
	}
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
	return loadRulesWithTuning(path, "")
}

// loadRulesWithTuning loads the base rule set from path and, if tuningPath is
// non-empty, merges in a local-tuning overlay (see correlator.TuningOverlay)
// that adds exceptions to existing rules by rule_id. A missing tuning file is
// not an error — the overlay is opt-in.
func loadRulesWithTuning(path, tuningPath string) ([]correlator.Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat rules path: %w", err)
	}

	var rules []correlator.Rule
	if info.IsDir() {
		rules, err = correlator.LoadRulesFromDir(path)
	} else {
		rules, err = correlator.LoadRulesFromFile(path)
	}
	if err != nil {
		return nil, err
	}

	overlay, err := correlator.LoadTuningOverlay(tuningPath)
	if err != nil {
		return nil, fmt.Errorf("load tuning overlay: %w", err)
	}
	unknown, err := correlator.ApplyTuningOverlay(rules, overlay)
	if err != nil {
		return nil, fmt.Errorf("apply tuning overlay: %w", err)
	}
	for _, id := range unknown {
		slog.Warn("tuning overlay: rule_id not found in active rule set, exceptions not applied",
			slog.String("rule_id", id), slog.String("tuning_path", tuningPath))
	}

	return rules, nil
}

// observerFilterRegistry holds one in-kernel observer-exclusion controller per
// collector (5.9.2g). Each BPF object compiled from bpf/common.h carries its
// own observer_root_pid, observer_tree_cache and observer_excluded_counters —
// maps are per-object unless pinned, which is also why P0-22 has to populate
// comm_filter_map separately for the syscall and fileaccess collectors. A
// single controller would therefore filter exactly one collector's stream and
// leave the others emitting harness events, which is worse than not filtering
// at all: the "share of the observer tree" criterion would be computed over a
// partially filtered denominator and would look better than reality.
//
// Collectors register from their own status-reporter goroutines as they come
// up, which races the root-PID poller — hence the mutex, and hence lastRoot:
// a collector registering after the root is known is configured immediately
// rather than waiting up to one poll interval (2s) during which it would emit
// harness events the others were already dropping.
type observerFilterRegistry struct {
	mu       sync.Mutex
	ctrls    map[string]*internalbpf.ObserverFilterController
	lastRoot uint32

	// lastExcluded is the per-collector cumulative BPF counter value at the
	// previous drain, so drainExcluded can return a delta.
	lastExcluded map[string]uint64
}

// register adds a collector's maps to the registry. Nil maps (stub build, or
// a collector that failed to load its objects) are ignored — with a log line,
// because silently registering nothing is how a filter ends up believed-on and
// measurably off.
func (r *observerFilterRegistry) register(name string, rootMap, counters *ebpf.Map) {
	if rootMap == nil {
		slog.Warn("observer_filter: root map unavailable, in-kernel exclusion inactive for this collector",
			slog.String("collector", name))
		return
	}
	ctrl, err := internalbpf.NewObserverFilterController(rootMap, counters)
	if err != nil {
		slog.Warn("observer_filter: controller creation failed",
			slog.String("collector", name), slog.Any("error", err))
		return
	}

	r.mu.Lock()
	if r.ctrls == nil {
		r.ctrls = make(map[string]*internalbpf.ObserverFilterController)
		r.lastExcluded = make(map[string]uint64)
	}
	r.ctrls[name] = ctrl
	root := r.lastRoot
	r.mu.Unlock()

	slog.Info("observer_filter: in-kernel harness exclusion registered (5.9.2g)",
		slog.String("collector", name))
	if root != 0 {
		if err := ctrl.SetRootPID(root); err != nil {
			slog.Warn("observer_filter: replaying root pid to late collector failed",
				slog.String("collector", name), slog.Any("error", err))
		}
	}
}

// publish writes the harness root TGID to every registered collector and
// returns how many accepted it. A return of 0 means no BPF object is filtering,
// and the caller must keep the userspace filter engaged.
func (r *observerFilterRegistry) publish(root uint32) int {
	if root == 0 {
		return 0
	}
	r.mu.Lock()
	r.lastRoot = root
	ctrls := make(map[string]*internalbpf.ObserverFilterController, len(r.ctrls))
	for k, v := range r.ctrls {
		ctrls[k] = v
	}
	r.mu.Unlock()

	var ok int
	for name, c := range ctrls {
		if c.RootPID() == root {
			ok++
			continue
		}
		if err := c.SetRootPID(root); err != nil {
			slog.Warn("observer_filter: set root pid failed",
				slog.String("collector", name),
				slog.Uint64("root_pid", uint64(root)), slog.Any("error", err))
			continue
		}
		slog.Info("observer_filter: harness root published to kernel",
			slog.String("collector", name), slog.Uint64("root_pid", uint64(root)))
		ok++
	}
	return ok
}

// drainExcluded returns the number of events dropped in the kernel as belonging
// to the harness tree since the previous call, summed over all collectors.
//
// A collector whose counter went backwards had its maps recreated (collector
// reload) and is re-baselined rather than subtracted: on unsigned counters the
// subtraction would add ~2^64 to the Prometheus series in a single tick and
// destroy it for the life of the process — the same trap the path-filter drain
// guards against.
func (r *observerFilterRegistry) drainExcluded() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	var delta uint64
	for name, c := range r.ctrls {
		total, err := c.ReadExcludedCount()
		if err != nil {
			slog.Warn("observer_filter: failed to read excluded counter",
				slog.String("collector", name), slog.Any("error", err))
			continue
		}
		prev := r.lastExcluded[name]
		if total < prev {
			slog.Debug("observer_filter: excluded counter reset, re-baselining",
				slog.String("collector", name),
				slog.Uint64("previous", prev), slog.Uint64("current", total))
		} else {
			delta += total - prev
		}
		r.lastExcluded[name] = total
	}
	return delta
}

// kernelCounterRegistry holds each core collector's copy of a single-slot
// PERCPU_ARRAY BPF counter (ringbuf_full_counters for 5.9.6a/№71,
// events_emitted_counters for 5.9.6b/№72 — see bpf/common.h) and drains it,
// per collector, into whatever Prometheus series sink reports.
//
// Deliberately separate from observerFilterRegistry despite the similar
// shape: that registry sums across collectors into one correlator-side
// number (the "share of the observer tree" is a single question), while this
// one must keep collectors apart — 5.9.6b's per-collector event balance
// needs to attribute a kernel-side count to the collector it happened in,
// not to a project-wide total.
type kernelCounterRegistry struct {
	mu   sync.Mutex
	maps map[string]*ebpf.Map
	last map[string]uint64

	// sink receives the delta for one collector on a positive read. Two
	// instances of this registry exist, each with its own sink: one that
	// reports through ebpf_guard_events_dropped_total{reason="ringbuf_full"}
	// and one through ebpf_guard_events_emitted_kernel_total.
	sink func(collector string, delta uint64)
}

// register adds a collector's counter map. A nil map (stub build, or a
// collector that failed to load) is ignored — there is nothing to drain, and
// pre-registering a series that can never move would be worse than not
// having it: the run-gate treats an unmoving series as evidence of health,
// not absence.
func (r *kernelCounterRegistry) register(name string, m *ebpf.Map) {
	if m == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maps == nil {
		r.maps = make(map[string]*ebpf.Map)
		r.last = make(map[string]uint64)
	}
	r.maps[name] = m
}

// drain reads every registered collector's cumulative counter total and
// reports the delta since the previous call to r.sink. A counter that went
// backwards had its map recreated (collector reload) and is re-baselined
// rather than subtracted — the same trap the path-filter and
// observer-exclusion drains guard against.
func (r *kernelCounterRegistry) drain() {
	r.mu.Lock()
	maps := make(map[string]*ebpf.Map, len(r.maps))
	for k, v := range r.maps {
		maps[k] = v
	}
	r.mu.Unlock()

	for name, m := range maps {
		total, err := internalbpf.SumPerCPUUint64(m)
		if err != nil {
			slog.Warn("kernel_counter: failed to read counter",
				slog.String("collector", name), slog.Any("error", err))
			continue
		}
		r.mu.Lock()
		prev := r.last[name]
		if total < prev {
			slog.Debug("kernel_counter: counter reset, re-baselining",
				slog.String("collector", name),
				slog.Uint64("previous", prev), slog.Uint64("current", total))
			r.last[name] = total
			r.mu.Unlock()
			continue
		}
		delta := total - prev
		r.last[name] = total
		r.mu.Unlock()
		if delta > 0 {
			r.sink(name, delta)
		}
	}
}
