package profiler

import (
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 8.5, F2: вход профайлеров без поштучных событий.
//
// Предикат ядра (F1) отбрасывает события горячих номеров (mmap, mprotect,
// arch_prctl), которые не нужны ни одному правилу. Но номер вызова читает ещё
// EWMA-профиль нагрузки (слой anomaly) — а он знает только «этот номер у этой
// нагрузки бывал» и сколько наблюдений набрано. Ядро поэтому СЧИТАЕТ
// отброшенное, а здесь счётчики складываются в профиль так, будто каждое
// событие пришло: профиль из счётчиков = профиль из событий (тест
// TestW85_F2_*). Остальные читатели номера разобраны в plan.md (8.5, F2): база
// дрейфа видит только события, совпавшие с drift-правилом (предикат их не
// теряет); Марков/SequenceProfiler в живом пути агента событий не получает
// вовсе; deny-unknown allowlist и детектор дрейфа контейнера учатся на
// поштучных событиях, и пока они включены, F1 не программирует предикаты.

// SyscallCount — приращение счётчика ядра: n отброшенных предикатом событий
// номера Nr у процесса PID. Comm — comm на момент последнего счёта; CgroupID
// нужен энричеру (под, метки) — те же поля, по которым определялся бы ключ
// нагрузки у самого события.
type SyscallCount struct {
	PID      uint32
	Nr       int64
	CgroupID uint64
	Comm     [16]byte
	N        uint64
}

// IngestSyscallCounts складывает счётчики ядра в профили нагрузок. enrich —
// тот же энричер, что у поштучных событий (nil — без меток k8s). Возвращает,
// сколько событий учтено и сколько пропущено (нагрузка не определена: comm —
// предэкзековый хвост, который не удалось разрешить, как и в ProcessEvent).
//
// Потокобезопасна: берёт только блокировки менеджера профилей и общего
// learner'а, а не внутренности скоринга, которые требуют одной горутины.
func (ad *AnomalyDetector) IngestSyscallCounts(batch []SyscallCount, enrich func(*types.Event)) (applied, skipped uint64) {
	if ad == nil || !ad.IsEnabled() {
		return 0, 0
	}
	for i := range batch {
		c := &batch[i]
		if c.N == 0 {
			continue
		}
		e := types.Event{Type: types.EventSyscall, PID: c.PID, CgroupID: c.CgroupID, Comm: c.Comm}
		if enrich != nil {
			enrich(&e)
		}
		key, identified := workloadKeyFromEventResolved(e)
		if !identified {
			skipped += c.N
			continue
		}
		ad.profileManager.recordSyscallCountWithKey(key, c.PID, c.Nr, c.N)
		// В фазе обучения каждое событие — образец для порога обучения
		// (ProcessEvent: RecordSample × поправка выборки). Счётчик ядра —
		// это истинное число событий, выборка ядра его не режет.
		if !ad.IsLearningComplete() {
			ad.learner.RecordSamples(c.N)
		}
		applied += c.N
	}
	return applied, skipped
}

// recordSyscallCountWithKey — recordEventWithKey для n событий одного номера.
func (wpm *WorkloadProfileManager) recordSyscallCountWithKey(key WorkloadKey, pid uint32, nr int64, n uint64) {
	sh := wpm.shardFor(key)

	wpm.evictIfOverCapacity()

	sh.mu.Lock()
	p, ok := sh.profiles[key]
	if !ok {
		p = NewProcessProfileForWorkload(key)
		sh.profiles[key] = p
		sh.lruIndex.push(&sh.lruHeap, key)
		wpm.entryCount.Add(1)
	} else {
		sh.lruIndex.touch(&sh.lruHeap, key)
	}
	sh.mu.Unlock()

	p.mu.Lock()
	p.PID = pid
	p.recordSyscallCountLocked(nr, n, wpm.weight)
	p.mu.Unlock()
}

// recordSyscallCountLocked — recordSyscallEventLocked для n событий разом.
func (p *ProcessProfile) recordSyscallCountLocked(nr int64, n uint64, weight float64) {
	p.LastSeenAt = time.Now()
	p.SyscallProfile.TotalSyscalls += n
	e := p.SyscallProfile.Syscalls[nr]
	if e == nil {
		e = NewEWMA(weight)
		p.SyscallProfile.Syscalls[nr] = e
	}
	e.UpdateN(1.0, n)
}
