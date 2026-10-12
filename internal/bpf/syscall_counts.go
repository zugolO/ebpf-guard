package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Волна 8.5, F2: чтение счётчиков отброшенного предикатом (syscall_counts в
// bpf/syscall.bpf.c). Карта — LRU hash (tgid, nr) → {n, cgroup, comm}, НЕ per-CPU
// (решение 12.10: память не зависит от числа CPU); ядро растит n атомарным
// сложением. Приращения считаются здесь: помним прошлую сумму по
// ключу и отдаём разность. Запись, вытесненная LRU и заведённая заново, начнёт
// с единицы — сумма станет МЕНЬШЕ прежней, и тогда приращение — вся сумма.

// SyscallCountKey — struct syscall_count_key.
type SyscallCountKey struct {
	Tgid uint32
	Nr   uint32
}

// SyscallCountValue — struct syscall_count_val.
type SyscallCountValue struct {
	N        uint64
	CgroupID uint64
	Comm     [16]uint8
}

// SyscallCountDelta — приращение счёта пары (tgid, nr) с прошлого опроса.
type SyscallCountDelta struct {
	PID      uint32
	Nr       uint32
	CgroupID uint64
	Comm     [16]uint8
	N        uint64
}

// countSource обходит карту; подменяется в тестах.
type countSource interface {
	Each(fn func(k SyscallCountKey, v SyscallCountValue)) error
}

type mapCountSource struct{ m *ebpf.Map }

// syscallCountBatch — записей за один вызов пакетного чтения.
const syscallCountBatch = 512

// Each обходит карту. Основной путь — BPF_MAP_LOOKUP_BATCH: поэлементный обход
// стоил бы два bpf() на запись, а КАЖДЫЙ bpf() агента ядро снова показывает ему
// же как syscall-событие номера 321 (петля «агент видит себя», F3). Смок этапа 1
// это измерил: поэлементное чтение раздуло by_nr{nr="321"} с 11 тыс. до 84 тыс.
// за окно. Пакет в 512 записей — единицы вызовов на опрос. Без пакетного API
// (ядро < 5.6) или при любой его ошибке — обход Iterate; повторно отданные
// записи отсекает Poll.
func (s mapCountSource) Each(fn func(k SyscallCountKey, v SyscallCountValue)) error {
	if err := s.eachBatch(fn); err == nil {
		return nil
	}
	return s.eachIterate(fn)
}

func (s mapCountSource) eachBatch(fn func(k SyscallCountKey, v SyscallCountValue)) error {
	keys := make([]SyscallCountKey, syscallCountBatch)
	vals := make([]SyscallCountValue, syscallCountBatch)
	var cursor ebpf.MapBatchCursor
	for {
		n, err := s.m.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			fn(keys[i], vals[i])
		}
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil // конец карты
			}
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

func (s mapCountSource) eachIterate(fn func(k SyscallCountKey, v SyscallCountValue)) error {
	it := s.m.Iterate()
	var k SyscallCountKey
	var v SyscallCountValue
	for it.Next(&k, &v) {
		fn(k, v)
	}
	return it.Err()
}

// SyscallCountReader — читатель с памятью прошлых сумм. Не потокобезопасен:
// один опросчик.
type SyscallCountReader struct {
	src  countSource
	last map[SyscallCountKey]uint64
	// live и max — прибор вытеснений: живых записей на последнем обходе и
	// max_entries карты. Близко к max — LRU вытесняет пары, приращения
	// пересоздаются с единицы и недосчёт растёт.
	live, max uint32

	// F3: счётчик служебных bpf() агента, не ушедших в кольцо (карта из одной
	// записи); selfLast — прошлое чтение, selfDelta — приращение последнего Poll.
	selfMap   *ebpf.Map
	selfLast  uint64
	selfDelta uint64
}

// SetSelfExcludedMap подключает счётчик самоисключения (syscall_self_excluded).
func (r *SyscallCountReader) SetSelfExcludedMap(m *ebpf.Map) { r.selfMap = m }

// SelfExcludedDelta — сколько событий самоисключение отбросило с предыдущего Poll
// (enter и exit по отдельности, та же единица, что у by_nr).
func (r *SyscallCountReader) SelfExcludedDelta() uint64 { return r.selfDelta }

// Occupancy — живых записей на последнем Poll и max_entries карты.
func (r *SyscallCountReader) Occupancy() (live, max uint32) { return r.live, r.max }

// NewSyscallCountReader создаёт читателя карты syscall_counts.
func NewSyscallCountReader(m *ebpf.Map) (*SyscallCountReader, error) {
	if m == nil {
		return nil, fmt.Errorf("bpf: syscall_counts map is nil")
	}
	return &SyscallCountReader{src: mapCountSource{m: m}, last: make(map[SyscallCountKey]uint64), max: m.MaxEntries()}, nil
}

// Poll возвращает приращения по парам, чей счёт вырос. Пары, исчезнувшие из
// карты, забываются (LRU их вытеснил или процесс умер и запись состарилась).
func (r *SyscallCountReader) Poll() ([]SyscallCountDelta, error) {
	var out []SyscallCountDelta
	seen := make(map[SyscallCountKey]uint64, len(r.last))
	err := r.src.Each(func(k SyscallCountKey, v SyscallCountValue) {
		d := SyscallCountDelta{PID: k.Tgid, Nr: k.Nr, CgroupID: v.CgroupID, Comm: v.Comm}
		total := v.N
		if _, dup := seen[k]; dup {
			// Пакетный обход при одновременной вставке мог отдать ключ дважды.
			return
		}
		seen[k] = total
		prev := r.last[k]
		switch {
		case total > prev:
			d.N = total - prev
		case total < prev:
			d.N = total // запись пересоздана: старая сумма потеряна вместе с вытеснением
		}
		if d.N > 0 {
			out = append(out, d)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("bpf: iterate syscall_counts: %w", err)
	}
	r.last = seen
	r.live = uint32(len(seen))
	r.pollSelfExcluded()
	return out, nil
}

// pollSelfExcluded читает счётчик самоисключения и считает приращение; ошибка
// чтения оставляет приращение нулём (не теряя прошлую сумму).
func (r *SyscallCountReader) pollSelfExcluded() {
	r.selfDelta = 0
	if r.selfMap == nil {
		return
	}
	var cur uint64
	if err := r.selfMap.Lookup(uint32(0), &cur); err != nil {
		return
	}
	r.selfDelta = selfExcludedDelta(r.selfLast, cur)
	r.selfLast = cur
}

// selfExcludedDelta — приращение монотонного счётчика; меньше прежнего (карту
// пересоздали) — вся новая сумма.
func selfExcludedDelta(prev, cur uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}
