package profiler

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestWave639F_Item4_SeededPair_SuppressesLoaderPrologueNoise verifies the
// #364/#371 fix: a fresh profile that has never seen "/etc/" before must not
// score an unknown-directory contribution for "/etc/ld.so.cache", because the
// (dir, ext) pair is seeded — but the extension score still applies normally
// (seeding only covers the directory half of the contribution).
func TestWave639F_Item4_SeededPair_SuppressesLoaderPrologueNoise(t *testing.T) {
	ad := NewAnomalyDetector(0.5, time.Hour, 0.3)
	profile := NewProcessProfile(4242, "sleep")

	event := &types.FileEvent{}
	copy(event.Filename[:], "/etc/ld.so.cache")

	var out []AnomalyContribution
	ad.analyzeFileBehavior(profile, event, &out)

	for _, c := range out {
		if c.Field == "directory" {
			t.Fatalf("seeded pair (/etc/, .cache) must not emit a directory contribution, got %+v", c)
		}
	}
}

// TestWave639F_Item4_SeededDirectory_DoesNotBlindOtherExtensions is the
// negative control from finding #371: seeding "/etc/" for ".cache" must NOT
// make the directory known for a DIFFERENT extension in the same directory
// (e.g. "/etc/shadow", extension ""). A directory-only seed would blind file
// access checks in exactly the way the finding warned against.
func TestWave639F_Item4_SeededDirectory_DoesNotBlindOtherExtensions(t *testing.T) {
	ad := NewAnomalyDetector(0.5, time.Hour, 0.3)
	profile := NewProcessProfile(4242, "sleep")

	event := &types.FileEvent{}
	copy(event.Filename[:], "/etc/shadow")

	var out []AnomalyContribution
	ad.analyzeFileBehavior(profile, event, &out)

	found := false
	for _, c := range out {
		if c.Field == "directory" && c.Value == "/etc/" {
			found = true
			if c.Contribution != 0.6 {
				t.Fatalf("expected unsuppressed unknown-directory contribution 0.6 for /etc/shadow, got %v", c.Contribution)
			}
		}
	}
	if !found {
		t.Fatal("expected /etc/shadow to still emit an unknown-directory contribution — seeding must be pair-scoped, not directory-scoped")
	}
}

// TestWave639F_Item4_SeededPairs_NotPersistedAsObservations guards criterion
// 6.3.9.3's "double-zero is a FAIL" rule at the structural level: seeded pairs
// must never round-trip through persistence as learned Directories/Extensions
// observations, or a restored profile would silently treat seeded noise as
// something the workload actually did.
func TestWave639F_Item4_SeededPairs_NotPersistedAsObservations(t *testing.T) {
	profile := NewProcessProfile(4242, "sleep")
	if len(profile.FileProfile.Directories) != 0 || len(profile.FileProfile.Extensions) != 0 {
		t.Fatal("seeding must not pre-populate Directories/Extensions — persistence.go walks only those two maps")
	}
	if len(profile.FileProfile.SeededPairs) == 0 {
		t.Fatal("expected a non-empty default seeded pair set")
	}
}

// TestWave639F_Item5_SeededSuppressionsCounted guards the double-zero rule of
// criterion 6.3.9.3 (item 5, finding #371): a suppressed seeded pair must be
// visible as a standalone counter, separate from AnomaliesTotal, so "seeding
// ran" and "anomaly layer is dead" can never be confused with each other.
func TestWave639F_Item5_SeededSuppressionsCounted(t *testing.T) {
	ad := NewAnomalyDetector(0.5, time.Hour, 0.3)
	profile := NewProcessProfile(4243, "sleep")

	before := SeededSuppressionsTotal()

	event := &types.FileEvent{}
	copy(event.Filename[:], "/etc/ld.so.cache")
	var out []AnomalyContribution
	ad.analyzeFileBehavior(profile, event, &out)

	after := SeededSuppressionsTotal()
	if after != before+1 {
		t.Fatalf("expected SeededSuppressionsTotal to increment by 1 for a suppressed seeded pair, before=%d after=%d", before, after)
	}

	// A non-seeded pair must not move the counter.
	event2 := &types.FileEvent{}
	copy(event2.Filename[:], "/etc/shadow")
	var out2 []AnomalyContribution
	ad.analyzeFileBehavior(profile, event2, &out2)

	if got := SeededSuppressionsTotal(); got != after {
		t.Fatalf("expected SeededSuppressionsTotal to stay at %d for a non-seeded pair, got %d", after, got)
	}
}

// TestWave639F_Item5_SeedingSurvivesRestore is the restart half of item 5:
// persistence.go never writes SeededPairs, so the ONLY thing that puts them
// back after a restart is restoreProfile going through the constructor. If a
// later refactor rebuilds the profile by struct literal instead, seeding would
// silently stop applying to every restored workload — the layer would look
// alive in a fresh process and be dead on the stand, where profiles are
// restored from disk at startup.
func TestWave639F_Item5_SeedingSurvivesRestore(t *testing.T) {
	restored := restoreProfile(persistedProfile{Comm: "sleep"}, WorkloadKey{Comm: "sleep"}, 0.3)
	if len(restored.FileProfile.SeededPairs) == 0 {
		t.Fatal("restored profile lost its seeded pairs — seeding must survive a restart")
	}
	if len(restored.FileProfile.Directories) != 0 {
		t.Fatal("restore of an empty snapshot must not materialize seeded pairs as learned directories")
	}

	ad := NewAnomalyDetector(0.5, time.Hour, 0.3)
	event := &types.FileEvent{}
	copy(event.Filename[:], "/etc/ld.so.cache")
	var out []AnomalyContribution
	ad.analyzeFileBehavior(restored, event, &out)
	for _, c := range out {
		if c.Field == "directory" {
			t.Fatalf("seeded pair must stay suppressed on a restored profile, got %+v", c)
		}
	}
}
