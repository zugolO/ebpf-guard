// Package main is the entry point for the ebpf-guard security agent.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/autolearn"
	"github.com/zugolO/ebpf-guard/internal/canary"
	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/drift"
	"github.com/zugolO/ebpf-guard/internal/enforcer"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/gossip"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/internal/simulate"
	"github.com/zugolO/ebpf-guard/internal/store"
	"github.com/zugolO/ebpf-guard/internal/tui"
	"github.com/zugolO/ebpf-guard/internal/watchdog"
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
		cfgPath          string
		logLevel         string
		dryRun           bool
		simulateMode     bool
		simulateDuration string
	)

	root := &cobra.Command{
		Use:   "ebpf-guard",
		Short: "eBPF-based runtime security agent for Linux/Kubernetes",
		Long: `ebpf-guard attaches eBPF probes to collect kernel events, correlates them
against YAML detection rules, and exports alerts to Prometheus and Alertmanager.`,
		Version:      fmt.Sprintf("%s (commit %s)", Version, Commit),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cfgPath, logLevel, dryRun, simulateMode, simulateDuration)
		},
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	root.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "run without real eBPF probes (uses synthetic events)")
	root.PersistentFlags().BoolVar(&simulateMode, "simulate", false,
		"simulate enforcement: count what would be killed/blocked/throttled without acting")
	root.PersistentFlags().StringVar(&simulateDuration, "simulate-duration", "",
		"stop simulation after this duration (e.g. 24h, 30m); empty = run until Ctrl+C")

	rulesCmd := newRulesCmd(&cfgPath)
	rulesCmd.AddCommand(newRulesTestCmd(&cfgPath))

	root.AddCommand(
		newAlertsCmd(&cfgPath),
		newStatusCmd(),
		rulesCmd,
		newVersionCmd(),
		newLearnCmd(),
		newDashboardCmd(),
	)

	return root
}

func runAgent(cfgPath, logLevel string, dryRun bool, simulateMode bool, simulateDuration string) error {
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

	if err := config.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("config validation:\n%w", err)
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

	// Feature D: canary trap / honeypot detection.
	if cfg.Canary.Enabled {
		cm := canary.New(canary.Config{
			Enabled:       true,
			AutoCreate:    cfg.Canary.AutoCreate,
			Files:         cfg.Canary.Files,
			AlertSeverity: cfg.Canary.AlertSeverity,
		})
		cm.Setup()
		canaryRules := cm.Rules()
		rules = append(rules, canaryRules...)
		slog.Info("canary: traps armed",
			slog.Int("files", len(cm.Paths())),
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
			Enabled:      true,
			NodeName:     nodeName,
			Secret:       cfg.Gossip.Secret,
			Peers:        cfg.Gossip.Peers,
			IOCTTL:       time.Duration(cfg.Gossip.IOCTTLSeconds) * time.Second,
			MaxIOCs:      cfg.Gossip.MaxIOCs,
			PushInterval: time.Duration(cfg.Gossip.PushIntervalSeconds) * time.Second,
			TLSEnabled:   cfg.Gossip.TLSEnabled,
			TLSCertFile:  cfg.Gossip.TLSCertFile,
			TLSKeyFile:   cfg.Gossip.TLSKeyFile,
			TLSCAFile:    cfg.Gossip.TLSCAFile,
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

	alertStore, err := store.New(store.Config{
		Backend: cfg.Store.Backend,
		SQLite: store.SQLiteConfig{
			Path:         cfg.Store.SQLite.Path,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
		},
		OpenSearch: store.OpenSearchConfig{
			Addresses:          []string{cfg.Store.OpenSearch.URL},
			Username:           cfg.Store.OpenSearch.Username,
			Password:           cfg.Store.OpenSearch.Password,
			InsecureSkipVerify: cfg.Store.OpenSearch.InsecureSkipVerify,
		},
		RetentionPeriod: 7 * 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("init alert store: %w", err)
	}
	defer alertStore.Close()

	authToken := cfg.Auth.BearerToken
	if cfg.Auth.Enabled && authToken == "" {
		authToken = generateToken()
		slog.Info("auth: generated bearer token (not shown for security)")
	}

	srv := exporter.NewServerWithAuth(
		cfg.Server.BindAddress,
		cfg.Server.MetricsPath,
		cfg.Server.HealthPath,
		cfg.Server.EnablePprof,
		cfg.Server.EnableDebug,
		authToken,
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

	eventCh := make(chan types.Event, engineCfg.BufferSize)
	engine.SetQueueDepthFn(func() int { return len(eventCh) }, func() int { return cap(eventCh) })

	var collectors []collector.Collector
	if dryRun {
		slog.Info("dry-run mode: using synthetic event generator")
		collectors = []collector.Collector{
			collector.NewSyntheticCollector(slog.Default(), 100*time.Millisecond),
		}
	}

	for _, c := range collectors {
		srv.SetCollectorStatus(exporter.CollectorStatus{Name: c.Name(), Healthy: true})
		go func(c collector.Collector) {
			if err := c.Start(ctx, eventCh); err != nil && ctx.Err() == nil {
				slog.Error("collector error", slog.String("name", c.Name()), slog.Any("error", err))
				srv.SetCollectorStatus(exporter.CollectorStatus{Name: c.Name(), Healthy: false, Error: err.Error()})
			}
		}(c)
	}

	if cfg.Rules.HotReload {
		cfgManager.OnChange(func(newCfg *config.Config) {
			newRules, err := correlator.LoadRulesFromFile(newCfg.Rules.Path)
			if err != nil {
				slog.Warn("hot-reload: failed to load rules", slog.Any("error", err))
				return
			}
			engine.ReloadRules(newRules)
			slog.Info("hot-reload: rules updated", slog.Int("count", len(newRules)))
		})
		if err := cfgManager.Watch(); err != nil {
			slog.Warn("hot-reload watch failed", slog.Any("error", err))
		}
	}

	srv.SetReady(true)
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

	// Container drift detector — enabled when containers use K8s enrichment.
	driftDetector := drift.NewDetector(drift.DetectorConfig{
		BaselineWindow: 5 * time.Minute,
		Logger:         slog.Default(),
	})
	var driftSeq atomic.Uint64

	for {
		select {
		case <-ctx.Done():
			gracefulShutdown(engine, collectors, alertStore, srv, enf, simCollector)
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
			alerts := engine.Ingest(ctx, event)

			// Run container drift detection alongside the rule engine.
			driftAlerts := driftDetector.Ingest(event)
			for _, da := range driftAlerts {
				seq := driftSeq.Add(1)
				alerts = append(alerts, drift.DriftAlertToTypes(da, seq))
			}

			if len(alerts) > 0 {
				if simCollector != nil {
					for _, a := range alerts {
						simCollector.Record(a)
					}
				}
				if err := alertStore.StoreBatch(ctx, alerts); err != nil {
					slog.Warn("store alerts error", slog.Any("error", err))
				}
				// Feature F: broadcast critical alerts to peer nodes (cross-node
				// alert amplification) and extract IOCs for gossip sharing.
				if gossipMgr != nil {
					for _, a := range alerts {
						gossipMgr.BroadcastAlert(a)
						gossipMgr.ExtractFromAlert(a)
					}
				}
			}
		}
	}
}

// gracefulShutdown orchestrates an ordered, time-bounded shutdown sequence:
//  1. Drain enforcement queue (up to 5 s) — let in-flight kill/block tasks finish.
//  2. Flush pending alerts from the correlation engine into the store.
//  3. Cleanup nftables/iptables chains left by the enforcer (if active).
//  4. Close BPF programs and collectors.
//  5. Shutdown the HTTP server.
//
// The entire procedure is bounded by a 30-second context.
func gracefulShutdown(
	engine *correlator.CorrelationEngine,
	collectors []collector.Collector,
	alertStore store.AlertStore,
	srv *exporter.Server,
	enf *enforcer.Enforcer,
	simCollector *simulate.Collector,
) {
	slog.Info("graceful shutdown: starting", slog.String("budget", "30s"))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Print simulation report before anything else so it's always visible.
	if simCollector != nil {
		simCollector.PrintReport(os.Stdout)
	}

	// Step 1: drain the enforcement worker queue so in-flight kill/block/throttle
	// tasks are not abandoned mid-execution. Capped at 5 s to avoid hanging.
	drainCtx, drainCancel := context.WithTimeout(shutdownCtx, 5*time.Second)
	slog.Info("graceful shutdown: draining enforcement queue")
	engine.DrainEnforceQueue(drainCtx)
	drainCancel()

	// Step 2: flush any pending alerts buffered in the correlation engine.
	slog.Info("graceful shutdown: flushing pending alerts")
	if pending := engine.Flush(); len(pending) > 0 {
		if err := alertStore.StoreBatch(shutdownCtx, pending); err != nil {
			slog.Warn("graceful shutdown: failed to flush pending alerts",
				slog.Int("count", len(pending)), slog.Any("error", err))
		} else {
			slog.Info("graceful shutdown: pending alerts flushed", slog.Int("count", len(pending)))
		}
	}

	// Step 3: remove nftables/iptables rules the enforcer installed.
	if enf != nil {
		slog.Info("graceful shutdown: cleaning up enforcement chains")
		if err := enf.Cleanup(); err != nil {
			slog.Warn("graceful shutdown: enforcement cleanup error", slog.Any("error", err))
		}
		if err := enf.Close(); err != nil {
			slog.Warn("graceful shutdown: enforcer close error", slog.Any("error", err))
		}
	}

	// Step 4: close BPF ring-buffer readers and detach probes.
	slog.Info("graceful shutdown: closing BPF collectors")
	for _, c := range collectors {
		if err := c.Close(); err != nil {
			slog.Warn("graceful shutdown: collector close error",
				slog.String("name", c.Name()), slog.Any("error", err))
		}
	}
	engine.Close()

	// Step 5: drain the HTTP server.
	slog.Info("graceful shutdown: shutting down HTTP server")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown: HTTP server shutdown error", slog.Any("error", err))
	}

	slog.Info("graceful shutdown: complete")
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
