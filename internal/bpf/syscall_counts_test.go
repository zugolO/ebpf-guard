package bpf

import "testing"

type fakeCountSource struct {
	rows map[SyscallCountKey]SyscallCountValue
}

func (f *fakeCountSource) Each(fn func(k SyscallCountKey, v SyscallCountValue)) error {
	for k, v := range f.rows {
		fn(k, v)
	}
	return nil
}

func w85comm16(s string) (b [16]uint8) {
	copy(b[:], s)
	return
}

func TestSyscallCountReaderDeltas(t *testing.T) {
	src := &fakeCountSource{rows: map[SyscallCountKey]SyscallCountValue{
		{Tgid: 100, Nr: 9}: {N: 8, CgroupID: 7, Comm: w85comm16("nginx")},
	}}
	r := &SyscallCountReader{src: src, last: map[SyscallCountKey]uint64{}}

	d, err := r.Poll()
	if err != nil || len(d) != 1 || d[0].N != 8 || d[0].PID != 100 || d[0].Nr != 9 || d[0].CgroupID != 7 || d[0].Comm != w85comm16("nginx") {
		t.Fatalf("первый опрос: %+v err=%v", d, err)
	}
	// Без изменений — пусто.
	if d, _ = r.Poll(); len(d) != 0 {
		t.Fatalf("без роста вернулись приращения: %+v", d)
	}
	// Рост — разность; comm — последний записанный ядром.
	src.rows[SyscallCountKey{100, 9}] = SyscallCountValue{N: 15, CgroupID: 7, Comm: w85comm16("curl")}
	d, _ = r.Poll()
	if len(d) != 1 || d[0].N != 7 || d[0].Comm != w85comm16("curl") {
		t.Fatalf("приращение: %+v", d)
	}
	// Запись пересоздана (сумма меньше прежней) — приращение равно новой сумме.
	src.rows[SyscallCountKey{100, 9}] = SyscallCountValue{N: 2}
	if d, _ = r.Poll(); len(d) != 1 || d[0].N != 2 {
		t.Fatalf("после вытеснения: %+v", d)
	}
	// Исчезнувшая пара забывается; вернувшаяся считается с нуля.
	delete(src.rows, SyscallCountKey{100, 9})
	if d, _ = r.Poll(); len(d) != 0 {
		t.Fatalf("пустая карта дала приращения: %+v", d)
	}
	src.rows[SyscallCountKey{100, 9}] = SyscallCountValue{N: 4}
	if d, _ = r.Poll(); len(d) != 1 || d[0].N != 4 {
		t.Fatalf("вернувшаяся пара: %+v", d)
	}
}

// Пакетный обход может отдать ключ дважды — приращение не должно удвоиться.
type dupCountSource struct{}

func (dupCountSource) Each(fn func(k SyscallCountKey, v SyscallCountValue)) error {
	v := SyscallCountValue{N: 6, Comm: w85comm16("curl")}
	fn(SyscallCountKey{Tgid: 7, Nr: 10}, v)
	fn(SyscallCountKey{Tgid: 7, Nr: 10}, v)
	return nil
}

func TestSyscallCountReaderIgnoresDuplicateKeyInOnePass(t *testing.T) {
	r := &SyscallCountReader{src: dupCountSource{}, last: map[SyscallCountKey]uint64{}}
	d, err := r.Poll()
	if err != nil || len(d) != 1 || d[0].N != 6 {
		t.Fatalf("дубль ключа удвоил приращение: %+v err=%v", d, err)
	}
}

// Прибор вытеснений: живых записей на обходе и max_entries.
func TestSyscallCountReaderOccupancy(t *testing.T) {
	src := &fakeCountSource{rows: map[SyscallCountKey]SyscallCountValue{
		{Tgid: 1, Nr: 9}:  {N: 1},
		{Tgid: 2, Nr: 9}:  {N: 1},
		{Tgid: 2, Nr: 10}: {N: 1},
	}}
	r := &SyscallCountReader{src: src, last: map[SyscallCountKey]uint64{}, max: 8192}
	if _, err := r.Poll(); err != nil {
		t.Fatal(err)
	}
	if live, max := r.Occupancy(); live != 3 || max != 8192 {
		t.Fatalf("occupancy = %d/%d, want 3/8192", live, max)
	}
	delete(src.rows, SyscallCountKey{Tgid: 1, Nr: 9})
	_, _ = r.Poll()
	if live, _ := r.Occupancy(); live != 2 {
		t.Fatalf("после исчезновения записи live = %d, want 2", live)
	}
}
