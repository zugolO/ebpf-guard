package store

import (
	"context"
	"sort"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// summaryTopRules bounds how many rules the summary reports.
const summaryTopRules = 10

// summaryMaxBuckets caps the hourly timeline so a wide "since" window (e.g.
// months) cannot produce an unbounded response.
const summaryMaxBuckets = 500

// AlertSummary is the aggregate view of a set of alerts used by the dashboard:
// total count, per-severity counts, the top rules by volume, and an hourly
// timeline. It is computed store-side (see Summarizer) so a summary does not
// require materializing every matching Alert.
type AlertSummary struct {
	Total      int              `json:"total"`
	BySeverity map[string]int   `json:"by_severity"`
	TopRules   []RuleCount      `json:"top_rules"`
	Timeline   []TimelineBucket `json:"timeline"`
	// Truncated is set when the summary was computed over a capped subset of
	// matching alerts (only the Query-based fallback path can set it); the UI
	// uses it to show "≥N" instead of a silently low number.
	Truncated bool `json:"truncated,omitempty"`
}

// RuleCount pairs a rule ID with the number of alerts it produced.
type RuleCount struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// TimelineBucket counts alerts within a single hour-wide bucket.
type TimelineBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// Summarizer is an optional interface a store may implement to compute an
// AlertSummary without returning the underlying alerts. Backends that can
// aggregate in the data layer (SQLite GROUP BY, the memory index) implement it
// so the dashboard's summary is exact over the whole window and cheap; callers
// that only have a plain AlertStore fall back to Query + SummarizeAlerts.
type Summarizer interface {
	Summarize(ctx context.Context, filters QueryFilters) (AlertSummary, error)
}

// SummarizeAlerts aggregates a slice of alerts into an AlertSummary. Used both
// by stores that lack a native aggregation and as the fallback for callers that
// already hold a slice of alerts.
func SummarizeAlerts(alerts []types.Alert) AlertSummary {
	summary := AlertSummary{
		Total:      len(alerts),
		BySeverity: map[string]int{},
	}
	if len(alerts) == 0 {
		return summary
	}

	ruleCounts := make(map[string]int)
	hourCounts := make(map[time.Time]int)
	var minHour, maxHour time.Time

	for _, a := range alerts {
		summary.BySeverity[string(a.Severity)]++
		ruleCounts[a.RuleID]++

		hour := a.Timestamp.UTC().Truncate(time.Hour)
		hourCounts[hour]++
		if minHour.IsZero() || hour.Before(minHour) {
			minHour = hour
		}
		if maxHour.IsZero() || hour.After(maxHour) {
			maxHour = hour
		}
	}

	summary.TopRules = topRulesFromCounts(ruleCounts)
	summary.Timeline = timelineFromCounts(hourCounts, minHour, maxHour)
	return summary
}

// topRulesFromCounts returns the top rules by count, ties broken by rule ID,
// capped at summaryTopRules.
func topRulesFromCounts(ruleCounts map[string]int) []RuleCount {
	rules := make([]RuleCount, 0, len(ruleCounts))
	for ruleID, count := range ruleCounts {
		rules = append(rules, RuleCount{RuleID: ruleID, Count: count})
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Count != rules[j].Count {
			return rules[i].Count > rules[j].Count
		}
		return rules[i].RuleID < rules[j].RuleID
	})
	if len(rules) > summaryTopRules {
		rules = rules[:summaryTopRules]
	}
	return rules
}

// timelineFromCounts materializes a contiguous hourly timeline from minHour to
// maxHour (inclusive), capped at summaryMaxBuckets.
func timelineFromCounts(hourCounts map[time.Time]int, minHour, maxHour time.Time) []TimelineBucket {
	timeline := make([]TimelineBucket, 0)
	if minHour.IsZero() {
		return timeline
	}
	for h := minHour; !h.After(maxHour) && len(timeline) < summaryMaxBuckets; h = h.Add(time.Hour) {
		timeline = append(timeline, TimelineBucket{
			Hour:  h.Format(time.RFC3339),
			Count: hourCounts[h],
		})
	}
	return timeline
}
