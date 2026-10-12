package bpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// Волна 8.5, F2: чтение счётчиков отброшенного предикатом (syscall_counts в
// bpf/syscall.bpf.c). Карта — LRU per-CPU hash (tgid, nr) → {n, cgroup, comm};
// ядро только растит счёт. Приращения считаются здесь: помним прошлую сумму по
// ключу и отдаём разность. Запись, вытесненная LRU и заведённая заново, начнёт
// с единицы — сумма станет МЕНЬШЕ прежней, и тогда приращение — вся сумма.

// SyscallCountKey — struct syscall_count_key.
type SyscallCountKey struct {
	Tgid uint32
	Nr   uint32
}

// SyscallCountValue — struct syscall_count_val (по одному на CPU).
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
	Each(fn func(k SyscallCountKey, perCPU []SyscallCountValue)) error
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
func (s mapCountSource) Each(fn func(k SyscallCountKey, perCPU []SyscallCountValue)) error {
	if cpus, err := ebpf.PossibleCPU(); err == nil && cpus > 0 {
		if err := s.eachBatch(cpus, fn); err == nil {
			return nil
		}
	}
	return s.eachIterate(fn)
}

func (s mapCountSource) eachBatch(cpus int, fn func(k SyscallCountKey, perCPU []SyscallCountValue)) error {
	keys := make([]SyscallCountKey, syscallCountBatch)
	vals := make([]SyscallCountValue, syscallCountBatch*cpus)
	var cursor ebpf.MapBatchCursor
	for {
		n, err := s.m.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			fn(keys[i], vals[i*cpus:(i+1)*cpus])
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

func (s mapCountSource) eachIterate(fn func(k SyscallCountKey, perCPU []SyscallCountValue)) error {
	it := s.m.Iterate()
	var k SyscallCountKey
	var vs []SyscallCountValue
	for it.Next(&k, &vs) {
		fn(k, vs)
	}
	return it.Err()
}

// SyscallCountReader — читатель с памятью прошлых сумм. Не потокобезопасен:
// один опросчик.
type SyscallCountReader struct {
	src  countSource
	last map[SyscallCountKey]uint64
}

// NewSyscallCountReader создаёт читателя карты syscall_counts.
func NewSyscallCountReader(m *ebpf.Map) (*SyscallCountReader, error) {
	if m == nil {
		return nil, fmt.Errorf("bpf: syscall_counts map is nil")
	}
	return &SyscallCountReader{src: mapCountSource{m: m}, last: make(map[SyscallCountKey]uint64)}, nil
}

// Poll возвращает приращения по парам, чей счёт вырос. Пары, исчезнувшие из
// карты, забываются (LRU их вытеснил или процесс умер и запись состарилась).
func (r *SyscallCountReader) Poll() ([]SyscallCountDelta, error) {
	var out []SyscallCountDelta
	seen := make(map[SyscallCountKey]uint64, len(r.last))
	err := r.src.Each(func(k SyscallCountKey, perCPU []SyscallCountValue) {
		var total, best uint64
		d := SyscallCountDelta{PID: k.Tgid, Nr: k.Nr}
		for i := range perCPU {
			v := &perCPU[i]
			total += v.N
			// comm и cgroup — с того CPU, где счёт больше: он обновлялся чаще
			// и ближе к последнему состоянию нагрузки.
			if v.N > best || (v.N == best && d.CgroupID == 0) {
				best = v.N
				d.Comm = v.Comm
				if v.CgroupID != 0 {
					d.CgroupID = v.CgroupID
				}
			}
		}
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
	return out, nil
}
