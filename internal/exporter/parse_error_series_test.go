package exporter

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// TestParseErrorSeriesMaterializedAtInit: a parse_error series is EXPORTED (at
// zero) for every collector before anything is dropped. Read through the
// gatherer, not WithLabelValues — the latter would create the series and pass.
func TestParseErrorSeriesMaterializedAtInit(t *testing.T) {
	require.NotEmpty(t, ParseErrorCollectors)
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	got := map[string]bool{}
	for _, mf := range mfs {
		if mf.GetName() != "ebpf_guard_events_dropped_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			lbl := map[string]string{}
			for _, l := range m.GetLabel() {
				lbl[l.GetName()] = l.GetValue()
			}
			if lbl["reason"] == "parse_error" {
				got[lbl["collector"]] = true
			}
		}
	}
	for _, c := range ParseErrorCollectors {
		require.True(t, got[c], "series {collector=%q,reason=\"parse_error\"} must be exported without a prior drop", c)
	}
}

// TestParseErrorCollectorsMatchCallSites pins ParseErrorCollectors to the
// RecordDropped(<name>, "parse_error") call sites in internal/collector: a
// collector added there without an entry here would be the №476 hole again.
func TestParseErrorCollectorsMatchCallSites(t *testing.T) {
	re := regexp.MustCompile(`RecordDropped\("([a-z_0-9]+)",\s*"parse_error"\)`)
	files, err := filepath.Glob("../collector/*.go")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	found := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = true
		}
	}
	var want, have []string
	for c := range found {
		want = append(want, c)
	}
	have = append(have, ParseErrorCollectors...)
	sort.Strings(want)
	sort.Strings(have)
	require.Equal(t, want, have)
}
