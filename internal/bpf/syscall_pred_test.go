package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Раскладка записи карты совпадает с struct syscall_pred в C (152 байта,
// терм 72 байта); C держит то же _Static_assert.
func TestSyscallPredLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &SyscallPredRaw{}); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.Len(), 8+SyscallPredTerms*(8+8*SyscallPredValues); got != want {
		t.Fatalf("SyscallPredRaw = %d байт, C ждёт %d", got, want)
	}
	buf.Reset()
	_ = binary.Write(&buf, binary.LittleEndian, &syscallPredTermRaw{})
	if buf.Len() != 72 {
		t.Fatalf("терм = %d байт, C ждёт 72", buf.Len())
	}
	buf.Reset()
	_ = binary.Write(&buf, binary.LittleEndian, &SyscallCountValue{})
	if buf.Len() != 32 {
		t.Fatalf("SyscallCountValue = %d байт, C (struct syscall_count_val) ждёт 32", buf.Len())
	}
}

func TestEncodeSyscallPred(t *testing.T) {
	raw, err := EncodeSyscallPred(SyscallPredicate{Nr: 9, Terms: []SyscallPredTerm{
		{Arg: 4, Values: []uint64{^uint64(0)}}, {Arg: 2, Values: []uint64{4, 5, 6, 7}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if raw.NTerms != 2 || raw.Terms[0].Arg != 4 || raw.Terms[0].NVals != 1 || raw.Terms[0].Vals[0] != ^uint64(0) ||
		raw.Terms[1].Arg != 2 || raw.Terms[1].NVals != 4 || raw.Terms[1].Vals[3] != 7 {
		t.Fatalf("неверная запись: %+v", raw)
	}
	for name, p := range map[string]SyscallPredicate{
		"nr вне диапазона":  {Nr: 512, Terms: []SyscallPredTerm{{Arg: 0, Values: []uint64{1}}}},
		"нет термов":        {Nr: 1},
		"много термов":      {Nr: 1, Terms: []SyscallPredTerm{{Values: []uint64{1}}, {Values: []uint64{1}}, {Values: []uint64{1}}}},
		"arg вне диапазона": {Nr: 1, Terms: []SyscallPredTerm{{Arg: 6, Values: []uint64{1}}}},
		"нет значений":      {Nr: 1, Terms: []SyscallPredTerm{{Arg: 0}}},
		"много значений":    {Nr: 1, Terms: []SyscallPredTerm{{Arg: 0, Values: make([]uint64, 9)}}},
	} {
		if _, err := EncodeSyscallPred(p); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

type fakePredWriter struct {
	slots map[uint32]SyscallPredRaw
	puts  int
	fail  uint32
}

func (f *fakePredWriter) Put(nr uint32, raw *SyscallPredRaw) error {
	if f.fail != 0 && nr == f.fail {
		return errors.New("boom")
	}
	f.puts++
	f.slots[nr] = *raw
	return nil
}

func TestSetSyscallPredicatesReplacesAndClears(t *testing.T) {
	fw := &fakePredWriter{slots: map[uint32]SyscallPredRaw{}}
	kf := &KernelFilterController{predWriter: fw}
	p9 := SyscallPredicate{Nr: 9, Terms: []SyscallPredTerm{{Arg: 2, Values: []uint64{4, 5, 6, 7}}}}
	p10 := SyscallPredicate{Nr: 10, Terms: []SyscallPredTerm{{Arg: 2, Values: []uint64{4, 5, 6, 7}}}}

	if err := kf.SetSyscallPredicates([]SyscallPredicate{p9, p10}); err != nil {
		t.Fatal(err)
	}
	if got := kf.PredicateNrs(); len(got) != 2 || got[0] != 9 || got[1] != 10 {
		t.Fatalf("PredicateNrs=%v", got)
	}
	// Повтор того же набора ничего не пишет.
	puts := fw.puts
	if err := kf.SetSyscallPredicates([]SyscallPredicate{p9, p10}); err != nil || fw.puts != puts {
		t.Fatalf("повтор записал слоты: err=%v puts %d→%d", err, puts, fw.puts)
	}
	// Снятие номера обнуляет слот.
	if err := kf.SetSyscallPredicates([]SyscallPredicate{p9}); err != nil {
		t.Fatal(err)
	}
	if fw.slots[10].NTerms != 0 || fw.slots[9].NTerms != 1 {
		t.Fatalf("слоты после снятия: 9=%+v 10=%+v", fw.slots[9].NTerms, fw.slots[10].NTerms)
	}
	// Пустой набор снимает всё.
	if err := kf.SetSyscallPredicates(nil); err != nil {
		t.Fatal(err)
	}
	if fw.slots[9].NTerms != 0 || len(kf.PredicateNrs()) != 0 {
		t.Fatalf("после пустого набора остались предикаты: %v", kf.PredicateNrs())
	}
	// Ошибка валидации не трогает карту.
	puts = fw.puts
	if err := kf.SetSyscallPredicates([]SyscallPredicate{{Nr: 9}}); err == nil || fw.puts != puts {
		t.Fatalf("невалидный предикат записан: err=%v", err)
	}
}

func TestSetSyscallPredicatesWithoutMap(t *testing.T) {
	kf := &KernelFilterController{}
	if kf.HasPredicateMap() {
		t.Fatal("карты нет, HasPredicateMap=true")
	}
	if err := kf.SetSyscallPredicates(nil); err == nil {
		t.Fatal("без карты ожидалась ошибка")
	}
}
