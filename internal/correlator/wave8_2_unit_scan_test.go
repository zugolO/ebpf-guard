package correlator

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unitScanFixture(t *testing.T) (root string, mk func(string) uint64) {
	root = t.TempDir()
	mk = func(p string) uint64 {
		full := filepath.Join(root, p)
		require.NoError(t, os.MkdirAll(full, 0o755))
		st, err := os.Stat(full)
		require.NoError(t, err)
		return uint64(st.Sys().(*syscall.Stat_t).Ino)
	}
	return root, mk
}

// Волна 8.2, доводка T2: поток промахов одного id (kubepods, сессии) запускает
// ОДИН скан, а не 10 в секунду.
func TestW82UnitScan_MissStreamScansOnce(t *testing.T) {
	root, mk := unitScanFixture(t)
	mk("system.slice/a.service")
	kube := mk("kubepods.slice/pod1/ctr")

	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }

	before := testutil.ToFloat64(systemdUnitScans)
	for i := 0; i < 200; i++ {
		assert.Empty(t, r.ResolveCgroupUnit(kube))
		now = now.Add(cgroupUnitRescanInterval) // каждый раз можно было бы сканировать
	}
	assert.Equal(t, 1.0, testutil.ToFloat64(systemdUnitScans)-before,
		"200 промахов одного id за 20 с (< TTL) — один скан")

	now = now.Add(cgroupUnitMissTTL)
	r.ResolveCgroupUnit(kube)
	assert.Equal(t, 2.0, testutil.ToFloat64(systemdUnitScans)-before, "по TTL — повторный скан")
}

// Обязательное условие: юнит, стартовавший после прошлого скана, разрешается
// на первом своём событии, даже при забитом отрицательном кэше.
func TestW82UnitScan_NewUnitResolvesAfterScan(t *testing.T) {
	root, mk := unitScanFixture(t)
	mk("system.slice/a.service")
	kube := mk("kubepods.slice/pod1/ctr")

	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }
	r.ResolveCgroupUnit(kube) // скан + отрицательная запись

	late := mk("system.slice/esm-cache.service")
	now = now.Add(cgroupUnitRescanInterval)
	assert.Equal(t, "esm-cache.service", r.ResolveCgroupUnit(late))
	assert.Empty(t, r.ResolveCgroupUnit(kube), "старый промах остаётся в кэше")
}

func TestW82UnitScan_MissCacheBounded(t *testing.T) {
	root, _ := unitScanFixture(t)
	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }
	for i := 0; i < cgroupUnitMissCap+500; i++ {
		now = now.Add(cgroupUnitRescanInterval)
		r.ResolveCgroupUnit(uint64(1000 + i))
	}
	assert.LessOrEqual(t, len(r.miss), cgroupUnitMissCap)
	_, newest := r.miss[uint64(1000+cgroupUnitMissCap+499)]
	_, oldest := r.miss[1000]
	assert.True(t, newest)
	assert.False(t, oldest, "вытеснены самые старые")
}

func TestW82UnitScan_ParallelMisses(t *testing.T) {
	root, mk := unitScanFixture(t)
	unit := mk("system.slice/a.service")
	r := NewSystemSliceUnitResolver(root)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r.ResolveCgroupUnit(uint64(5_000_000 + i%7))
				r.ResolveCgroupUnit(unit)
			}
		}(g)
	}
	wg.Wait()
	assert.Equal(t, "a.service", r.ResolveCgroupUnit(unit))
}
