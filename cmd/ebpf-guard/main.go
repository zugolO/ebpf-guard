// Package main is the entry point for the ebpf-guard security agent.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/zugolO/ebpf-guard/internal/collector"
	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/internal/profiler"
	"github.com/zugolO/ebpf-guard/internal/store"
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
		cfgPath  string
		logLevel string
		dryRun   bool
	)

	root := &cobra.Command{
		Use:   "ebpf-guard",
		Short: "eBPF-based runtime security agent for Linux/Kubernetes",
		Long: `ebpf-guard attaches eBPF probes to collect kernel events, correlates them
against YAML detection rules, and exports alerts to Prometheus and Alertmanager.`,
		Version:      fmt.Sprintf("%s (commit %s)", Version, Commit),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cfgPath, logLevel, dryRun)
		},
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "config/config.yaml", "path to config file")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	root.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "run without real eBPF probes (uses synthetic events)")

	root.AddCommand(
		newAlertsCmd(&cfgPath),
		newStatusCmd(),
		newRulesCmd(&cfgPath),
		newVersionCmd(),
	)

	return root
}

func runAgent(cfgPath, logLevel string, dryRun bool) error {
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

	rules, err := correlator.LoadRulesFromFile(cfg.Rules.Path)
	if err != nil {
		slog.Warn("failed to load rules file, starting with empty rule set",
			slog.String("path", cfg.Rules.Path),
			slog.Any("error", err))
		rules = nil
	} else {
		slog.Info("rules loaded", slog.Int("count", len(rules)))
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

	engine := correlator.NewCorrelationEngineWithConfig(engineCfg)

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

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			for _, c := range collectors {
				if err := c.Close(); err != nil {
					slog.Warn("collector close error", slog.String("name", c.Name()), slog.Any("error", err))
				}
			}
			srv.Shutdown(shutdownCtx) //nolint:errcheck
			return nil

		case event, ok := <-eventCh:
			if !ok {
				return nil
			}
			alerts := engine.Ingest(ctx, event)
			if len(alerts) > 0 {
				if err := alertStore.StoreBatch(ctx, alerts); err != nil {
					slog.Warn("store alerts error", slog.Any("error", err))
				}
			}
		}
	}
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
	return &cobra.Command{
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
}
