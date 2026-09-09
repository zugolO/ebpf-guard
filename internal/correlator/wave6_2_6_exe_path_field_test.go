package correlator

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// Волна 6.2.6, item 3 (№277). До этой правки exe_path (событие только что
// прошло execve) и parent_exe_path (форкнутый потомок демона без своего
// execve) инкрементировали ОДИН и тот же ebpf_guard_exe_path_lookups_total
// {result}, и «unresolved=375» на архиве 6.2.5 было смесью двух разных гонок
// с разными причинами. Тест доказывает, что лейбл field разводит их: запрос
// по PID и запрос по PPID через один и тот же резолвер обязаны прибавлять к
// РАЗНЫМ сериям.
type w626FieldResolver struct{ path string }

func (r w626FieldResolver) ResolveExePath(uint32) string { return r.path }

func TestWave6_2_6ExePathLookupsLabelSeparatesFields(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })

	SetExePathResolver(w626FieldResolver{path: "/usr/sbin/cron"})
	selfBefore := testutil.ToFloat64(exePathLookups.WithLabelValues("resolved", exePathFieldSelf))
	parentBefore := testutil.ToFloat64(exePathLookups.WithLabelValues("resolved", exePathFieldParent))

	got := resolveExePath(1234, exePathFieldSelf)
	require.Equal(t, "/usr/sbin/cron", got)
	require.Equal(t, selfBefore+1, testutil.ToFloat64(exePathLookups.WithLabelValues("resolved", exePathFieldSelf)),
		"запрос по PID обязан прибавить к серии field=exe_path")
	require.Equal(t, parentBefore, testutil.ToFloat64(exePathLookups.WithLabelValues("resolved", exePathFieldParent)),
		"запрос по PID не должен трогать серию field=parent_exe_path")

	got = resolveExePath(5678, exePathFieldParent)
	require.Equal(t, "/usr/sbin/cron", got)
	require.Equal(t, selfBefore+1, testutil.ToFloat64(exePathLookups.WithLabelValues("resolved", exePathFieldSelf)),
		"запрос по PPID не должен трогать серию field=exe_path")
	require.Equal(t, parentBefore+1, testutil.ToFloat64(exePathLookups.WithLabelValues("resolved", exePathFieldParent)),
		"запрос по PPID обязан прибавить к серии field=parent_exe_path")
}

// Отказ резолвера (нет procfs, процесс уже умер) обязан остаться
// различимым по field так же, как разрешённый случай — иначе
// unresolved-доля 6.2.6.15 по-прежнему считалась бы смесью.
func TestWave6_2_6ExePathLookupsUnresolvedLabelSeparatesFields(t *testing.T) {
	prev, _ := exeResolver.Load().(exeResolverHolder)
	t.Cleanup(func() { SetExePathResolver(prev.r) })

	SetExePathResolver(w626FieldResolver{path: ""})
	selfBefore := testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldSelf))
	parentBefore := testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldParent))

	require.Equal(t, "", resolveExePath(1234, exePathFieldSelf))
	require.Equal(t, selfBefore+1, testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldSelf)))
	require.Equal(t, parentBefore, testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldParent)))

	require.Equal(t, "", resolveExePath(5678, exePathFieldParent))
	require.Equal(t, selfBefore+1, testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldSelf)))
	require.Equal(t, parentBefore+1, testutil.ToFloat64(exePathLookups.WithLabelValues("unresolved", exePathFieldParent)))
}
