// Package simulate provides the simulation report for --simulate mode.
// It intercepts alerts that would trigger enforcement and summarises what
// would have happened without executing any destructive actions.
package simulate

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Collector accumulates alerts in simulate mode.
type Collector struct {
	mu        sync.Mutex
	alerts    []types.Alert
	startTime time.Time
}

// NewCollector creates a new simulate Collector.
func NewCollector() *Collector {
	return &Collector{startTime: time.Now()}
}

// Record adds an alert to the simulation log.
func (c *Collector) Record(a types.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a)
}

// actionCounts returns action → count map.
func (c *Collector) actionCounts() map[string]int {
	counts := map[string]int{}
	for _, a := range c.alerts {
		action := a.Action
		if action == "" {
			action = "alert"
		}
		counts[action]++
	}
	return counts
}

// ruleCounts returns ruleID → count map (top triggered rules).
func (c *Collector) ruleCounts() map[string]int {
	counts := map[string]int{}
	for _, a := range c.alerts {
		counts[a.RuleID]++
	}
	return counts
}

// processCounts returns comm → count map (top involved processes).
func (c *Collector) processCounts() map[string]int {
	counts := map[string]int{}
	for _, a := range c.alerts {
		counts[a.Comm]++
	}
	return counts
}

// sevCounts returns severity → count map.
func (c *Collector) sevCounts() map[types.Severity]int {
	counts := map[types.Severity]int{}
	for _, a := range c.alerts {
		counts[a.Severity]++
	}
	return counts
}

// PrintReport writes the simulation summary to w.
func (c *Collector) PrintReport(w io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := time.Since(c.startTime).Round(time.Second)
	total := len(c.alerts)

	fmt.Fprintf(w, "\n%s\n", strings.Repeat("═", 60))
	fmt.Fprintf(w, "  ebpf-guard SIMULATE report  (observation: %s)\n", elapsed)
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("═", 60))

	if total == 0 {
		fmt.Fprintln(w, "  No alerts would have been generated during this window.")
		fmt.Fprintln(w, "  Your current rule set had no matches against observed events.")
		return
	}

	fmt.Fprintf(w, "  Total alerts:  %d\n\n", total)

	// Severity breakdown
	fmt.Fprintln(w, "  By severity:")
	sevs := c.sevCounts()
	for _, sev := range []types.Severity{types.SeverityCritical, types.SeverityWarning} {
		if n := sevs[sev]; n > 0 {
			fmt.Fprintf(w, "    %-10s %d\n", string(sev), n)
		}
	}
	fmt.Fprintln(w)

	// Enforcement action breakdown
	actions := c.actionCounts()
	if len(actions) > 0 {
		fmt.Fprintln(w, "  Enforcement actions that WOULD have been taken:")
		orderedActions := []string{"kill", "block", "throttle", "lsm_block", "drop", "alert"}
		printed := map[string]bool{}
		for _, act := range orderedActions {
			if n, ok := actions[act]; ok {
				icon := actionIcon(act)
				fmt.Fprintf(w, "    %s  %-12s %d\n", icon, act, n)
				printed[act] = true
			}
		}
		for act, n := range actions {
			if !printed[act] {
				fmt.Fprintf(w, "    •  %-12s %d\n", act, n)
			}
		}
		fmt.Fprintln(w)
	}

	// Top rules
	ruleCounts := c.ruleCounts()
	topRules := topN(ruleCounts, 10)
	if len(topRules) > 0 {
		fmt.Fprintln(w, "  Top triggered rules:")
		for _, kv := range topRules {
			fmt.Fprintf(w, "    %-30s %d\n", kv.key, kv.val)
		}
		fmt.Fprintln(w)
	}

	// Top processes
	procCounts := c.processCounts()
	topProcs := topN(procCounts, 10)
	if len(topProcs) > 0 {
		fmt.Fprintln(w, "  Most involved processes:")
		for _, kv := range topProcs {
			fmt.Fprintf(w, "    %-20s %d alerts\n", kv.key, kv.val)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "  No processes were killed, blocked, or throttled.")
	fmt.Fprintln(w, "  Review the rules above and enable enforcement when ready.")
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 60))
}

func actionIcon(action string) string {
	switch action {
	case "kill":
		return "☠"
	case "block":
		return "⛔"
	case "throttle":
		return "⏱"
	case "alert":
		return "🔔"
	default:
		return "•"
	}
}

type kv struct {
	key string
	val int
}

func topN(m map[string]int, n int) []kv {
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].val != all[j].val {
			return all[i].val > all[j].val
		}
		return all[i].key < all[j].key
	})
	if n < len(all) {
		return all[:n]
	}
	return all
}
