package attacker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ScenarioResult holds the outcome of running a single scenario.
type ScenarioResult struct {
	Scenario Scenario
	// Passed is true when all expected rule IDs fired.
	Passed bool
	// Fired contains the rule IDs that actually produced alerts.
	Fired []string
	// Missing contains expected rule IDs that did not produce alerts.
	Missing []string
	// Duration is how long the scenario took.
	Duration time.Duration
}

// Runner executes attack scenarios either synthetically (no kernel/agent needed)
// or against a live agent via the --verify mode.
type Runner struct {
	scenarios []Scenario
	logger    *slog.Logger
}

// NewRunner creates a Runner. When scenarios is nil or empty, all built-in
// scenarios are used.
func NewRunner(scenarios []Scenario, logger *slog.Logger) *Runner {
	if len(scenarios) == 0 {
		scenarios = BuiltinScenarios()
	}
	return &Runner{scenarios: scenarios, logger: logger}
}

// RunSynthetic feeds each scenario's synthetic event into a local correlation
// engine loaded from rulesPath and reports which expected rules fired.
// No OS-level operations are performed — safe to run in any environment.
func (r *Runner) RunSynthetic(ctx context.Context, rulesPath string) ([]ScenarioResult, error) {
	rules, err := correlator.LoadRulesFromFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("load rules %q: %w", rulesPath, err)
	}

	cfg := correlator.DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	engine := correlator.NewCorrelationEngineWithConfig(cfg)

	results := make([]ScenarioResult, 0, len(r.scenarios))
	for _, sc := range r.scenarios {
		result := r.runOne(ctx, sc, engine)
		results = append(results, result)
	}
	return results, nil
}

// RunScenarioSynthetic runs a single scenario by ID through a local engine.
func (r *Runner) RunScenarioSynthetic(ctx context.Context, id, rulesPath string) (ScenarioResult, error) {
	sc, ok := r.findByID(id)
	if !ok {
		return ScenarioResult{}, fmt.Errorf("unknown scenario %q", id)
	}

	rules, err := correlator.LoadRulesFromFile(rulesPath)
	if err != nil {
		return ScenarioResult{}, fmt.Errorf("load rules %q: %w", rulesPath, err)
	}

	cfg := correlator.DefaultCorrelationEngineConfig()
	cfg.Rules = rules
	engine := correlator.NewCorrelationEngineWithConfig(cfg)

	return r.runOne(ctx, sc, engine), nil
}

func (r *Runner) runOne(ctx context.Context, sc Scenario, engine *correlator.CorrelationEngine) ScenarioResult {
	start := time.Now()
	event := sc.Event()
	alerts := engine.Ingest(ctx, event)

	firedSet := make(map[string]bool, len(alerts))
	for _, a := range alerts {
		firedSet[a.RuleID] = true
	}

	var fired, missing []string
	for id := range firedSet {
		fired = append(fired, id)
	}
	for _, expected := range sc.RuleIDs {
		if !firedSet[expected] {
			missing = append(missing, expected)
		}
	}

	result := ScenarioResult{
		Scenario: sc,
		Passed:   len(missing) == 0,
		Fired:    fired,
		Missing:  missing,
		Duration: time.Since(start),
	}

	level := slog.LevelInfo
	if !result.Passed {
		level = slog.LevelWarn
	}
	r.logger.Log(ctx, level, "scenario result",
		slog.String("id", sc.ID),
		slog.Bool("passed", result.Passed),
		slog.Any("fired", fired),
		slog.Any("missing", missing),
	)
	return result
}

// Verify runs a scenario by ID and polls a live agent's alerts HTTP API to
// confirm all expected rules fired. baseURL is the agent address (e.g.
// "http://localhost:8080"). token is the bearer token (may be empty).
// The call blocks until all expected rules are observed or timeout elapses.
func (r *Runner) Verify(ctx context.Context, id, baseURL, token string, timeout time.Duration) (ScenarioResult, error) {
	sc, ok := r.findByID(id)
	if !ok {
		return ScenarioResult{}, fmt.Errorf("unknown scenario %q", id)
	}

	start := time.Now()
	deadline := start.Add(timeout)

	r.logger.Info("verify: waiting for alerts",
		slog.String("scenario", id),
		slog.String("agent", baseURL),
		slog.Duration("timeout", timeout),
	)

	var allFired []string
	firedSet := make(map[string]bool)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ScenarioResult{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}

		alerts, err := r.pollAlerts(ctx, baseURL, token, start)
		if err != nil {
			r.logger.Warn("verify: poll error", slog.Any("error", err))
			continue
		}

		for _, a := range alerts {
			if !firedSet[a.RuleID] {
				firedSet[a.RuleID] = true
				allFired = append(allFired, a.RuleID)
			}
		}

		allFound := true
		for _, expected := range sc.RuleIDs {
			if !firedSet[expected] {
				allFound = false
				break
			}
		}
		if allFound {
			break
		}
	}

	var missing []string
	for _, expected := range sc.RuleIDs {
		if !firedSet[expected] {
			missing = append(missing, expected)
		}
	}

	return ScenarioResult{
		Scenario: sc,
		Passed:   len(missing) == 0,
		Fired:    allFired,
		Missing:  missing,
		Duration: time.Since(start),
	}, nil
}

func (r *Runner) pollAlerts(ctx context.Context, baseURL, token string, since time.Time) ([]types.Alert, error) {
	url := strings.TrimRight(baseURL, "/") + "/alerts?since=" + since.UTC().Format(time.RFC3339)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alerts API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB
	if err != nil {
		return nil, err
	}

	var alerts []types.Alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("decode alerts: %w", err)
	}
	return alerts, nil
}

func (r *Runner) findByID(id string) (Scenario, bool) {
	for _, s := range r.scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// Scenarios returns the runner's scenario list (copy).
func (r *Runner) Scenarios() []Scenario {
	out := make([]Scenario, len(r.scenarios))
	copy(out, r.scenarios)
	return out
}

// PrintResults writes a formatted summary of scenario results to w.
func PrintResults(results []ScenarioResult, w io.Writer) {
	passed, failed := 0, 0
	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	fmt.Fprintf(w, "\n=== Attack Simulation Results ===\n")
	fmt.Fprintf(w, "Scenarios: %d  Passed: %d  Failed: %d\n\n", len(results), passed, failed)

	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %-40s  mitre=%-12s  %v\n",
			status, r.Scenario.ID, r.Scenario.MITRETech, r.Duration.Round(time.Millisecond))
		if !r.Passed {
			fmt.Fprintf(w, "       missing rules: %v\n", r.Missing)
			fmt.Fprintf(w, "       fired rules:   %v\n", r.Fired)
		}
	}
	fmt.Fprintln(w)
}
