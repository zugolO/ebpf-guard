package correlator

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Finding №329 (wave 6.3, item 7, live run on ebaka2 15.09.2026): the DNS
// entropy rules scored qname_entropy, which is Shannon entropy over every
// label except the TLD *concatenated together*. That value tracks how many
// levels a name has, not how random it is, so it sat the wrong way round
// against its own threshold: an ordinary k8s service name cleared it while a
// genuinely random 8-character label did not. The rules now score
// qname_max_label_entropy — the highest entropy of any single label.
//
// These tests are the offline replica of stand controls 6.3.1 (positive) and
// 6.3.2 (negative): they run the REAL rules/ tree, so a future edit that
// points a DNS rule back at the concatenated field fails here rather than on
// the stand an hour into a run.

// realRulesDir returns the repository's rules/ directory.
func realRulesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "rules")
	return dir
}

// dnsRulesFiring loads the real rule set and returns the sorted ids of every
// DNS rule that fires on qname, queried by comm.
func dnsRulesFiring(t *testing.T, qname, comm string, qtype uint16) []string {
	t.Helper()
	rules, err := LoadRulesFromDir(realRulesDir(t))
	require.NoError(t, err)
	require.NotEmpty(t, rules)

	re := NewRuleEngine(rules)
	require.NoError(t, re.CompileErrors())

	var commBytes [16]byte
	copy(commBytes[:], comm)
	ev := types.Event{
		Type: types.EventDNS,
		PID:  4242,
		Comm: commBytes,
		DNS:  &types.DNSEvent{QName: qname, QType: qtype},
	}
	var ids []string
	for _, a := range re.Evaluate(ev) {
		ids = append(ids, a.RuleID)
	}
	sort.Strings(ids)
	return ids
}

// TestNegativeControl_LegitimateK8sFQDNsRaiseNothing is control 6.3.2 offline.
// kubernetes.default.svc.cluster.local exists in every pod of every cluster;
// before the fix it raised dns_dga_high_entropy on all four runs of item 7.
func TestNegativeControl_LegitimateK8sFQDNsRaiseNothing(t *testing.T) {
	for _, qname := range []string{
		"kubernetes.default.svc.cluster.local",
		"my-svc.my-namespace.svc.cluster.local",
		"metrics-server.kube-system.svc.cluster.local",
		"prometheus.monitoring.svc.cluster.local",
		"ebpf-guard-alertmanager.monitoring.svc.cluster.local",
		// 66 characters — an ordinary k8s FQDN passes the whole-name
		// thresholds of the long-label family on service and namespace names
		// alone. Found by this test, not on the stand.
		"ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local",
		// Short labels are where the bigram model scores legitimate names
		// highest ("my-svc" 0.654); the length floor in the scorer is what
		// keeps them out.
		// The thinnest measured margin against the standalone n-gram rule:
		// "kafka-broker-0" scores 0.515 against a threshold of 0.55.
		"kafka-broker-0.kafka.svc.cluster.local",
		"google.com",
		"registry-1.docker.io",
		"storage.googleapis.com",
	} {
		t.Run(qname, func(t *testing.T) {
			got := dnsRulesFiring(t, qname, "nslookup", 1)
			assert.Empty(t, got,
				"legitimate FQDN %q must raise no DNS rule, got: %s",
				qname, strings.Join(got, ", "))
		})
	}
}

// TestNegativeControl_LegitimateTXTQueryRaisesNothing covers the TXT half of
// the family: exfil_dns_txt_long_label is a critical rule gated on qtype 16
// plus a length, and the length was read off the whole name.
func TestNegativeControl_LegitimateTXTQueryRaisesNothing(t *testing.T) {
	got := dnsRulesFiring(t, "ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local", "nslookup", 16)
	for _, id := range got {
		assert.NotEqual(t, "exfil_dns_txt_long_label", id,
			"a long but ordinary k8s name must not raise the TXT exfiltration rule")
	}
}

// TestPositiveControl_LongLabelAttackStillDetected is the 5.9.5c positive
// control offline: run_dns_long_label_attack sends two 60-character labels, and
// all four long-label rules must still fire on that shape after the move from
// qname_length to qname_max_label_len.
func TestPositiveControl_LongLabelAttackStillDetected(t *testing.T) {
	q := strings.Repeat("x", 60) + "." + strings.Repeat("y", 60) +
		".ebpfguard-5951c-20260915120000.dns-tunnel-canary.invalid"
	got := dnsRulesFiring(t, q, "isc-net-0000", 16)
	for _, want := range []string{
		"dns_tunneling_long_domain",
		"exfil_dns_txt_long_label",
		"netintr_dns_long_label",
		"webshell_dns_exfil_long_subdomain",
	} {
		assert.Containsf(t, got, want,
			"5.9.5c positive control: %s must fire on a 60-character label", want)
	}
}

// TestPositiveControl_DGALabelStillDetected is control 6.3.1 offline: the
// narrowing must not be a silent mute. The 55-character random label is the
// shape the stand harness generates.
func TestPositiveControl_DGALabelStillDetected(t *testing.T) {
	for _, qname := range []string{
		"kq3v9zw7mrl2.net",
		"x7k2qv9zwmrl4bnt8pd3.w63-dga-probe.invalid",
		"a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz2345.w63-dga-probe.invalid",
	} {
		t.Run(qname, func(t *testing.T) {
			got := dnsRulesFiring(t, qname, "nslookup", 1)
			assert.NotEmpty(t, got,
				"DGA-shaped qname %q must raise at least one DNS rule", qname)
		})
	}
}

// TestMaxLabelEntropy_SeparatesPopulations pins the numbers the fix rests on:
// per label the legitimate names sit below the 3.5 threshold and the DGA-like
// name above it, whereas the concatenated value has them the other way round.
func TestMaxLabelEntropy_SeparatesPopulations(t *testing.T) {
	c := NewDNSEntropyCalculator()

	const threshold = 3.5
	legit := "kubernetes.default.svc.cluster.local"
	dga := "kq3v9zw7mrl2.net"

	// The defect, pinned so it cannot come back unnoticed: concatenated, the
	// legitimate name outscores the DGA one.
	assert.Greater(t, c.CalculateShannonEntropy(c.extractBaseDomain(legit)), threshold,
		"precondition of №329: concatenated entropy of a plain k8s FQDN is above the threshold")
	assert.Less(t, c.CalculateShannonEntropy(c.extractBaseDomain(dga)), 3.6,
		"precondition of №329: a 12-character DGA label barely clears the same threshold")

	// Per label the order is correct.
	assert.Less(t, c.AnalyzeDomain(legit).MaxLabelEntropy, threshold)
	assert.Greater(t, c.AnalyzeDomain(dga).MaxLabelEntropy, threshold)
}

// TestMaxLabelEntropy_Mechanics covers the helper directly.
func TestMaxLabelEntropy_Mechanics(t *testing.T) {
	c := NewDNSEntropyCalculator()

	// Value does not grow with the number of levels: appending more ordinary
	// labels to an ordinary name leaves it where it was.
	short := c.AnalyzeDomain("cluster.local").MaxLabelEntropy
	long := c.AnalyzeDomain("a.b.c.d.e.f.cluster.local").MaxLabelEntropy
	assert.InDelta(t, short, long, 1e-9,
		"max label entropy must be independent of level count")

	// The maximum is taken across labels wherever the random one sits.
	assert.InDelta(t,
		c.AnalyzeDomain("kq3v9zw7mrl2.example.com").MaxLabelEntropy,
		c.AnalyzeDomain("example.kq3v9zw7mrl2.com").MaxLabelEntropy, 1e-9)

	// Degenerate inputs do not panic and score zero.
	assert.Equal(t, 0.0, c.AnalyzeDomain("").MaxLabelEntropy)
	assert.Equal(t, 0.0, c.AnalyzeDomain("...").MaxLabelEntropy)

	// Single-character labels: entropy of an n-character string is bounded by
	// log2(n), so they cannot reach any threshold on their own.
	assert.Equal(t, 0.0, c.AnalyzeDomain("a.b.c").MaxLabelEntropy)
}

// TestIsDGADomain_PerLabel covers the same fix in the qname_is_dga path, which
// netintr_dga_domain_query reads and which raised the second alert of №329.
func TestIsDGADomain_PerLabel(t *testing.T) {
	c := NewDNSEntropyCalculator()
	assert.False(t, c.IsDGADomain("kubernetes.default.svc.cluster.local"))
	assert.False(t, c.IsDGADomain("prometheus.monitoring.svc.cluster.local"))
	assert.True(t, c.IsDGADomain("a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwxyz2345.example.com"))
}

// TestRuleSet_NoDNSRuleScoresConcatenatedEntropy is the drift sentinel: no
// built-in rule may go back to qname_entropy for a randomness test. The field
// itself stays valid (operator-written rules may use it deliberately) — this
// only pins the shipped rule set.
func TestRuleSet_NoDNSRuleScoresConcatenatedEntropy(t *testing.T) {
	rules, err := LoadRulesFromDir(realRulesDir(t))
	require.NoError(t, err)

	var offenders []string
	for _, r := range rules {
		re := NewRuleEngine([]Rule{r})
		for _, c := range re.getAllConditions(r) {
			if c.Field == "qname_entropy" {
				offenders = append(offenders, r.ID)
			}
		}
	}
	assert.Empty(t, offenders,
		"these rules score qname_entropy (labels concatenated — finding №329); "+
			"use qname_max_label_entropy: %s", strings.Join(offenders, ", "))
}
