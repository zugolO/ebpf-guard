package profiler

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.2.9.F.1, находка №301 (архив collect-6.2.9.F.1).
//
// systemd ставит форкнутому потомку скобочный comm между fork() и execve();
// буфер 11 байт, при переполнении держится ХВОСТ имени — «(50-motd-news)»
// приходит как «(otd-news)». Продукт читает ядро верно, но ключ дерева (comm
// КОРНЯ) из-за этого дробит одно событие ноды на два: «(otd-news)» и
// «50-motd-news».
func TestWave6_2_9_F1_ProvisionalComm_Recognized(t *testing.T) {
	assert.True(t, isProvisionalComm("(otd-news)"))
	assert.True(t, isProvisionalComm("(ystemctl)"))
	assert.True(t, isProvisionalComm("(fwupdmgr)"))
	assert.False(t, isProvisionalComm("50-motd-news"))
	assert.False(t, isProvisionalComm("runc:[2:INIT]"),
		"квадратные скобки — постоянное имя стадии container-init, а не переходная форма systemd")
	assert.False(t, isProvisionalComm("()"))
	assert.False(t, isProvisionalComm(""))
}

// Снимок дерева переразрешает скобочный узел по кэшу /proc и не трогает
// остальные.
func TestWave6_2_9_F1_ProvisionalComm_NormalizedOnRead(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)

	const rootPID, childPID = 16764, 16780
	// Ancestry записана с тем именем, которое было известно в момент события —
	// скобочным, как в архиве.
	s := lt.shardFor(rootPID)
	s.mu.Lock()
	s.ancestry[rootPID] = []types.ProcessNode{{PID: rootPID, PPID: 1, Comm: "(otd-news)"}}
	s.mu.Unlock()

	cs := lt.shardFor(childPID)
	cs.mu.Lock()
	cs.ancestry[childPID] = []types.ProcessNode{
		{PID: rootPID, PPID: 1, Comm: "(otd-news)"},
		{PID: childPID, PPID: rootPID, Comm: "dpkg"},
	}
	cs.mu.Unlock()

	// К моменту снятия снимка execve уже случился, и настоящее имя известно
	// кэшу /proc.
	s.mu.Lock()
	s.procCache[rootPID] = &procEntry{comm: "50-motd-news", ppid: 1}
	s.mu.Unlock()

	seenBefore := testutil.ToFloat64(lineageProvisionalComms.WithLabelValues("seen"))
	tree := lt.GetProcessTree(childPID)
	require.Len(t, tree, 2)
	assert.Equal(t, "50-motd-news", tree[0].Comm,
		"корень снимка обязан прийти под своим именем, иначе одно событие ноды даёт два ключа дерева")
	assert.Equal(t, "dpkg", tree[1].Comm, "остальные узлы не трогаются")
	assert.Greater(t, testutil.ToFloat64(lineageProvisionalComms.WithLabelValues("seen")), seenBefore,
		"сторож обязан считать попытки: «ноль скобочных корней» должно отличаться от «нормализация не вызывалась»")

	// Запись ancestry НЕ переписана — правится копия снимка (нормализация на
	// чтении, а не на записи).
	s.mu.RLock()
	stored := s.ancestry[rootPID][0].Comm
	s.mu.RUnlock()
	assert.Equal(t, "(otd-news)", stored)
}

// Отказ открытый: имя не разрешилось — узел остаётся как есть, счётчик
// unresolved растёт. Ноль вместо лжи.
func TestWave6_2_9_F1_ProvisionalComm_UnresolvedKeptAsIs(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	const pid = 999901 // нет ни в кэше, ни в /proc (и /proc нет на mac вовсе)

	s := lt.shardFor(pid)
	s.mu.Lock()
	s.ancestry[pid] = []types.ProcessNode{{PID: pid, PPID: 1, Comm: "(ystemctl)"}}
	s.mu.Unlock()

	unresolvedBefore := testutil.ToFloat64(lineageProvisionalComms.WithLabelValues("unresolved"))
	tree := lt.GetProcessTree(pid)
	require.Len(t, tree, 1)
	assert.Equal(t, "(ystemctl)", tree[0].Comm)
	assert.Greater(t, testutil.ToFloat64(lineageProvisionalComms.WithLabelValues("unresolved")), unresolvedBefore)
}

// Кэш, который сам держит скобочное имя, ответом не считается — иначе
// «нормализация» разрешала бы имя в него же.
func TestWave6_2_9_F1_ProvisionalComm_CacheWithBracketsIsNotAnAnswer(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	const pid = 999902

	s := lt.shardFor(pid)
	s.mu.Lock()
	s.ancestry[pid] = []types.ProcessNode{{PID: pid, PPID: 1, Comm: "(fwupdmgr)"}}
	s.procCache[pid] = &procEntry{comm: "(fwupdmgr)", ppid: 1}
	s.mu.Unlock()

	assert.Equal(t, "", lt.resolveCurrentComm(pid),
		"скобочное значение кэша — та же переходная форма, а не разрешённое имя")
	tree := lt.GetProcessTree(pid)
	require.Len(t, tree, 1)
	assert.Equal(t, "(fwupdmgr)", tree[0].Comm)
}
