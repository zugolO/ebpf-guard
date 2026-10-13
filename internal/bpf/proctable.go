package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/zugolO/ebpf-guard/internal/procinfo"
)

// Волна 8.5, P1: таблица процессов в ядре (bpf/proctable.bpf.c) и её читатель.
//
// Две карты: proc_live (HASH, живые) и proc_exited (LRU, вышедшие с exit_ts). Читатель
// спрашивает сперва живую, затем вышедшую, и отбрасывает вышедшую старше TTL.
// Отдельный объект: отказ верификатора на tp_btf-программах не должен утащить syscall-коллектор.

// Раскладка записи — bpf/proctable.h (_Static_assert там, сверка констант — TestW85_P1_RecordLayoutMatchesHeader).
const (
	procRecSize        = 184
	procRecCommLen     = 16
	procRecFilenameLen = 128
)

// procRecRaw — struct proc_rec без неявных отступов (сумма полей = 184).
type procRecRaw struct {
	StartBoottime uint64
	ExitTS        uint64
	ExeIno        uint64
	PPID          uint32
	ExeDev        uint32
	Flags         uint32
	Pad           uint32
	Comm          [procRecCommLen]byte
	Filename      [procRecFilenameLen]byte
}

// procTableCounterNames — порядок enum proc_counter в bpf/proctable.h.
var procTableCounterNames = []string{
	"fork_ok", "fork_live_full", "exec_updated", "exec_created", "exec_live_full",
	"exit_moved", "exit_no_record", "exited_inserts",
}

// ProcTableConfig — параметры таблицы.
type ProcTableConfig struct {
	// LiveEntries — ёмкость proc_live (живые процессы узла с запасом). 0 — значение объекта (16384).
	LiveEntries uint32
	// ExitedEntries — ёмкость proc_exited. 0 — значение объекта (16384).
	ExitedEntries uint32
	// TTL — сколько после exit_ts запись вышедшего процесса считается годной. 0 — без ограничения.
	TTL    time.Duration
	Logger *slog.Logger
}

// tableMap — то, что читателю нужно от карты (*ebpf.Map его выполняет; в тестах — подставная карта).
type tableMap interface {
	Lookup(key, valueOut interface{}) error
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	MaxEntries() uint32
}

// ProcTable — загруженный объект и читатель.
type ProcTable struct {
	objs     *ProcTableObjects
	links    []link.Link
	live     tableMap
	exited   tableMap
	counters tableMap
	ttlNs    uint64
	now      func() uint64
	lookEr   atomic.Uint64
	cfg      ProcTableConfig
}

// OpenProcTable загружает объект, подгоняет ёмкости карт и вешает три хука. Любой отказ
// (нет BTF/tp_btf, верификатор, привязка) — ошибка; объект при этом закрывается целиком.
func OpenProcTable(cfg ProcTableConfig) (*ProcTable, error) {
	spec, err := LoadProcTable()
	if err != nil {
		return nil, err
	}
	if cfg.LiveEntries > 0 {
		spec.Maps["proc_live"].MaxEntries = cfg.LiveEntries
	}
	if cfg.ExitedEntries > 0 {
		spec.Maps["proc_exited"].MaxEntries = cfg.ExitedEntries
	}
	objs := &ProcTableObjects{}
	if err := spec.LoadAndAssign(objs, WithSharedKernelTypes(nil)); err != nil {
		return nil, fmt.Errorf("load proctable objects: %w", err)
	}
	t := &ProcTable{objs: objs, live: objs.ProcLive, exited: objs.ProcExited, counters: objs.ProcTableCounters,
		ttlNs: uint64(cfg.TTL), now: monotonicNs, cfg: cfg}
	for _, p := range []struct {
		name string
		prog *ebpf.Program
	}{{"sched_process_fork", objs.ProcFork}, {"sched_process_exec", objs.ProcExec}, {"sched_process_exit", objs.ProcExit}} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p.prog})
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("attach tp_btf/%s: %w", p.name, err)
		}
		t.links = append(t.links, l)
	}
	return t, nil
}

// Close снимает хуки и закрывает карты.
func (t *ProcTable) Close() error {
	var errs []error
	for _, l := range t.links {
		errs = append(errs, l.Close())
	}
	t.links = nil
	t.live, t.exited, t.counters = nil, nil, nil
	if t.objs != nil {
		errs = append(errs, t.objs.Close())
		t.objs = nil
	}
	return errors.Join(errs...)
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func decodeProcRec(pid uint32, raw *procRecRaw) procinfo.Record {
	return procinfo.Record{
		PID: pid, PPID: raw.PPID, StartBoottimeNs: raw.StartBoottime, ExitTS: raw.ExitTS,
		ExeIno: raw.ExeIno, ExeDev: raw.ExeDev, Flags: raw.Flags,
		Comm: trimNul(raw.Comm[:]), Filename: trimNul(raw.Filename[:]),
	}
}

// expired — вышедшая запись старше TTL.
func (t *ProcTable) expired(r procinfo.Record) bool {
	if r.ExitTS == 0 || t.ttlNs == 0 {
		return false
	}
	now := t.now()
	return now != 0 && now > r.ExitTS && now-r.ExitTS > t.ttlNs
}

// Lookup — точечное чтение: сперва живые, затем вышедшие. Реализует procinfo.Source.
// Чтение — BPF_MAP_LOOKUP_ELEM (cmd 1): служебный вызов агента, F3 его в поток не пускает.
func (t *ProcTable) Lookup(pid uint32) (procinfo.Record, procinfo.Result) {
	if t.live == nil || pid == 0 {
		return procinfo.Record{}, procinfo.Absent
	}
	var raw procRecRaw
	// Порядок «живые → вышедшие» безопасен: на выходе ядро сперва ВСТАВЛЯЕТ запись в proc_exited,
	// затем удаляет из proc_live, так что промах по живой означает «уже в вышедших».
	err := t.live.Lookup(pid, &raw)
	if err == nil {
		return decodeProcRec(pid, &raw), procinfo.Found
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.lookEr.Add(1)
		return procinfo.Record{}, procinfo.Error
	}
	err = t.exited.Lookup(pid, &raw)
	if err == nil {
		rec := decodeProcRec(pid, &raw)
		if t.expired(rec) {
			return rec, procinfo.Expired
		}
		return rec, procinfo.Found
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.lookEr.Add(1)
		return procinfo.Record{}, procinfo.Error
	}
	return procinfo.Record{}, procinfo.Absent
}

// LookupErrors — сбои чтения карт (не «нет записи»).
func (t *ProcTable) LookupErrors() uint64 { return t.lookEr.Load() }

// Counters — суммы счётчиков исходов хуков по всем CPU; ключи — procTableCounterNames.
func (t *ProcTable) Counters() (map[string]uint64, error) {
	out := make(map[string]uint64, len(procTableCounterNames))
	if t.counters == nil {
		return out, errors.New("proctable closed")
	}
	for i, name := range procTableCounterNames {
		var perCPU []uint64
		if err := t.counters.Lookup(uint32(i), &perCPU); err != nil {
			return out, fmt.Errorf("counter %s: %w", name, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[name] = sum
	}
	return out, nil
}

// Capacity — ёмкости карт (живые, вышедшие).
func (t *ProcTable) Capacity() (live, exited uint32) {
	if t.live == nil {
		return 0, 0
	}
	return t.live.MaxEntries(), t.exited.MaxEntries()
}

// Seed вносит записи процессов, существовавших ДО привязки хуков (старше агента). Запись ядра
// не затирается (UpdateNoExist): fork/exec после привязки точнее. Возвращает: внесено, уже было
// (ядро успело), сбоев (включая полную карту).
func (t *ProcTable) Seed(recs []SeedRecord) (seeded, existing, failed int) {
	if t.live == nil {
		return 0, 0, len(recs)
	}
	for _, r := range recs {
		raw := procRecRaw{StartBoottime: r.StartBoottimeNs, ExeIno: r.ExeIno, PPID: r.PPID, ExeDev: r.ExeDev, Flags: uint32(procinfo.FlagSeeded)}
		copy(raw.Comm[:procRecCommLen-1], r.Comm)
		err := t.live.Update(r.PID, &raw, ebpf.UpdateNoExist)
		switch {
		case err == nil:
			seeded++
		case errors.Is(err, ebpf.ErrKeyExist):
			existing++
		default:
			failed++
		}
	}
	return seeded, existing, failed
}
