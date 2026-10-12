package bpf

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"
)

// Волна 8.5, F1: программирование ядерного предиката аргументов
// (syscall_pred_map в bpf/syscall.bpf.c). Сам предикат выводится из правил в
// internal/correlator (DeriveKernelPredicates); здесь — раскладка записи и
// запись в карту. Раскладка обязана совпадать с struct syscall_pred в C;
// _Static_assert в C и TestSyscallPredLayout здесь держат её с двух сторон.

const (
	// SyscallPredTerms — конъюнктов на номер (EG_PRED_TERMS в C).
	SyscallPredTerms = 2
	// SyscallPredValues — значений в конъюнкте (EG_PRED_VALUES в C).
	SyscallPredValues = 8
)

// SyscallPredTerm — конъюнкт: args[Arg] ∈ Values.
type SyscallPredTerm struct {
	Arg    uint8
	Values []uint64
}

// SyscallPredicate — предикат номера Nr; Terms — конъюнкция.
type SyscallPredicate struct {
	Nr    uint32
	Terms []SyscallPredTerm
}

// syscallPredTermRaw — struct syscall_pred_term (72 байта).
type syscallPredTermRaw struct {
	Arg   uint8
	NVals uint8
	Pad   [6]uint8
	Vals  [SyscallPredValues]uint64
}

// SyscallPredRaw — struct syscall_pred (152 байта); нулевая запись — «без
// предиката».
type SyscallPredRaw struct {
	NTerms uint8
	Pad    [7]uint8
	Terms  [SyscallPredTerms]syscallPredTermRaw
}

// EncodeSyscallPred собирает запись карты. Проверки ужесточены против C:
// предикат, который C счёл бы невалидным (и тихо пропустил), здесь ошибка.
func EncodeSyscallPred(p SyscallPredicate) (SyscallPredRaw, error) {
	var raw SyscallPredRaw
	if p.Nr >= 512 {
		return raw, fmt.Errorf("bpf: predicate nr %d out of range [0, 512)", p.Nr)
	}
	if len(p.Terms) == 0 || len(p.Terms) > SyscallPredTerms {
		return raw, fmt.Errorf("bpf: predicate nr %d: %d terms (want 1..%d)", p.Nr, len(p.Terms), SyscallPredTerms)
	}
	for i, t := range p.Terms {
		if t.Arg > 5 {
			return raw, fmt.Errorf("bpf: predicate nr %d term %d: arg%d out of range", p.Nr, i, t.Arg)
		}
		if len(t.Values) == 0 || len(t.Values) > SyscallPredValues {
			return raw, fmt.Errorf("bpf: predicate nr %d term %d: %d values (want 1..%d)", p.Nr, i, len(t.Values), SyscallPredValues)
		}
		raw.Terms[i].Arg = t.Arg
		raw.Terms[i].NVals = uint8(len(t.Values))
		copy(raw.Terms[i].Vals[:], t.Values)
	}
	raw.NTerms = uint8(len(p.Terms))
	return raw, nil
}

// predSlotWriter — запись одного слота карты; подменяется в тестах.
type predSlotWriter interface {
	Put(nr uint32, raw *SyscallPredRaw) error
}

type mapPredWriter struct{ m *ebpf.Map }

func (w mapPredWriter) Put(nr uint32, raw *SyscallPredRaw) error {
	return w.m.Update(nr, raw, ebpf.UpdateAny)
}

// SetPredicateMap подключает карту syscall_pred_map (есть только у
// syscall-объекта). Без неё SetSyscallPredicates возвращает ошибку.
func (kf *KernelFilterController) SetPredicateMap(m *ebpf.Map) {
	if m == nil {
		kf.predWriter = nil
		return
	}
	kf.predWriter = mapPredWriter{m: m}
}

// HasPredicateMap — подключена ли карта предикатов.
func (kf *KernelFilterController) HasPredicateMap() bool { return kf.predWriter != nil }

// SetSyscallPredicates заменяет набор предикатов: слоты номеров, которых нет в
// preds, обнуляются (номер снова идёт целиком), остальные записываются.
// Слот пишется целиком одним Update — ядро видит старую или новую запись, не
// смесь. Порядок: сначала снимаются старые, затем ставятся новые; между
// двумя номерами окна согласованности нет и не нужно — предикаты независимы.
//
// Переход «предикат есть → нет» оставляет вызовы, чей enter ядро отбросило, а
// exit придёт уже без предиката: он уйдёт в кольцо с нулевыми args (так же
// ведёт себя номер без предиката при вытеснении записи syscall_args) —
// единичное событие на переключение, правилам нечего совпадать с нулями.
func (kf *KernelFilterController) SetSyscallPredicates(preds []SyscallPredicate) error {
	if kf.predWriter == nil {
		return fmt.Errorf("bpf: syscall_pred_map is nil")
	}
	want := make(map[uint32]SyscallPredRaw, len(preds))
	for _, p := range preds {
		raw, err := EncodeSyscallPred(p)
		if err != nil {
			return err
		}
		want[p.Nr] = raw
	}
	var zero SyscallPredRaw
	for nr := range kf.predNrs {
		if _, keep := want[nr]; keep {
			continue
		}
		if err := kf.predWriter.Put(nr, &zero); err != nil {
			return fmt.Errorf("bpf: clear syscall predicate %d: %w", nr, err)
		}
		delete(kf.predNrs, nr)
	}
	if kf.predNrs == nil {
		kf.predNrs = make(map[uint32]SyscallPredRaw, len(want))
	}
	for nr, raw := range want {
		raw := raw
		if cur, ok := kf.predNrs[nr]; ok && cur == raw {
			continue
		}
		if err := kf.predWriter.Put(nr, &raw); err != nil {
			return fmt.Errorf("bpf: set syscall predicate %d: %w", nr, err)
		}
		kf.predNrs[nr] = raw
	}
	return nil
}

// PredicateNrs возвращает номера, у которых сейчас запрограммирован предикат.
func (kf *KernelFilterController) PredicateNrs() []uint32 {
	out := make([]uint32, 0, len(kf.predNrs))
	for nr := range kf.predNrs {
		out = append(out, nr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
