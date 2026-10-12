package correlator

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, U1: id каталога-предка уровня 2 приходит из ядра, userspace мапит
// верхний уровень system.slice одним ReadDir. Юнит разрешается БЕЗ обхода
// поддеревьев (systemd_unit_scans_total не растёт).
func TestW85_U1_UnitResolvedFromKernelAncestorIDWithoutFullScan(t *testing.T) {
	root, mk := unitScanFixture(t)
	esm := mk("system.slice/esm-cache.service")
	mk("system.slice/esm-cache.service/payload/deep") // вложенный cgroup того же юнита
	user := mk("user.slice/user-1000.slice")
	kube := mk("kubepods.slice/kubepods-burstable.slice")
	notUnit := mk("system.slice/system-getty.slice")

	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }

	full0 := testutil.ToFloat64(systemdUnitScans)
	top0 := testutil.ToFloat64(systemdUnitTopScans)

	// Событие вложенной cgroup несёт id юнита верхнего уровня — он и есть ключ.
	assert.Equal(t, "esm-cache.service", r.ResolveUnitID(esm))
	assert.Empty(t, r.ResolveUnitID(user), "user.slice/user-N.slice — не юнит system.slice")
	assert.Empty(t, r.ResolveUnitID(kube))
	now = now.Add(cgroupUnitRescanInterval)
	assert.Empty(t, r.ResolveUnitID(notUnit), "*.slice под system.slice — не юнит")
	assert.Empty(t, r.ResolveUnitID(0))
	assert.Empty(t, r.ResolveUnitID(1))

	assert.Equal(t, 0.0, testutil.ToFloat64(systemdUnitScans)-full0, "полный обход поддеревьев не запускался")
	assert.Greater(t, testutil.ToFloat64(systemdUnitTopScans)-top0, 0.0)
}

// Поток промахов одного id (под kubepods) — ограниченное число дешёвых сканов, как у полного обхода.
func TestW85_U1_MissStreamIsBounded(t *testing.T) {
	root, mk := unitScanFixture(t)
	mk("system.slice/a.service")
	kube := mk("kubepods.slice/kubepods-burstable.slice")
	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }

	top0 := testutil.ToFloat64(systemdUnitTopScans)
	for i := 0; i < 200; i++ {
		assert.Empty(t, r.ResolveUnitID(kube))
		now = now.Add(cgroupUnitRescanInterval)
	}
	assert.Equal(t, 2.0, testutil.ToFloat64(systemdUnitTopScans)-top0)
}

// Юнит, стартовавший после прошлого скана, разрешается на первом событии после паузы.
func TestW85_U1_NewUnitResolvesAfterRescan(t *testing.T) {
	root, mk := unitScanFixture(t)
	mk("system.slice/a.service")
	kube := mk("kubepods.slice/kubepods-burstable.slice")
	now := time.Unix(1_000_000, 0)
	r := NewSystemSliceUnitResolver(root)
	r.now = func() time.Time { return now }
	r.ResolveUnitID(kube)
	late := mk("system.slice/apt-news.service")
	assert.Empty(t, r.ResolveUnitID(late), "внутри паузы — отказ в шум")
	now = now.Add(cgroupUnitRescanInterval)
	assert.Equal(t, "apt-news.service", r.ResolveUnitID(late))
}

// Поле правил: событие с unit_cgroup_id идёт новым путём, без него — прежним по cgroup_id;
// подставной резолвер без ResolveUnitID продолжает работать по cgroup_id.
func TestW85_U1_FieldUsesUnitIDAndFallsBack(t *testing.T) {
	root, mk := unitScanFixture(t)
	esm := mk("system.slice/esm-cache.service")
	nested := mk("system.slice/esm-cache.service/payload")
	r := NewSystemSliceUnitResolver(root)
	prev, _ := cgroupUnitResolver.Load().(cgroupUnitResolverHolder)
	SetCgroupUnitResolver(r)
	t.Cleanup(func() { SetCgroupUnitResolver(prev.r) })

	re := &RuleEngine{}
	ev := &types.Event{Type: types.EventSyscall, CgroupID: nested, UnitCgroupID: esm, Syscall: &types.SyscallEvent{}}
	full0 := testutil.ToFloat64(systemdUnitScans)
	assert.Equal(t, "esm-cache.service", re.getFieldValue(ev, "proc.systemd_unit", nil))
	assert.Equal(t, 0.0, testutil.ToFloat64(systemdUnitScans)-full0, "с id из ядра полный обход не нужен")

	// Запись без unit_cgroup_id (старый объект): прежний путь по cgroup_id.
	old := &types.Event{Type: types.EventSyscall, CgroupID: nested, Syscall: &types.SyscallEvent{}}
	assert.Equal(t, "esm-cache.service", re.getFieldValue(old, "proc.systemd_unit", nil))
	assert.Equal(t, 1.0, testutil.ToFloat64(systemdUnitScans)-full0, "запасной путь — один полный скан")

	// Резолвер без ResolveUnitID (подставной): по cgroup_id, unit_cgroup_id игнорируется.
	SetCgroupUnitResolver(w81UnitResolver{nested: "fake.service"})
	assert.Equal(t, "fake.service", re.getFieldValue(ev, "proc.systemd_unit", nil))
	require.NotNil(t, re)
}
