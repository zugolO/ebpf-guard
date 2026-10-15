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

// Волна 8.6 B, G4 — офлайн-тождество: опрос в три раза реже даёт те же суммы
// по (pid, nr) и по nr (ε = 0), пока LRU не вытеснял записи внутри интервала.
func TestSyscallCountReaderPollIntervalKeepsTotals(t *testing.T) {
	const ticks = 60
	run := func(every int) (perPair map[SyscallCountKey]uint64, perNr map[uint32]uint64, polls int) {
		src := &fakeCountSource{rows: map[SyscallCountKey]SyscallCountValue{}}
		r := &SyscallCountReader{src: src, last: map[SyscallCountKey]uint64{}}
		perPair, perNr = map[SyscallCountKey]uint64{}, map[uint32]uint64{}
		for tick := 1; tick <= ticks; tick++ {
			for pid := uint32(1); pid <= 40; pid++ {
				for _, nr := range []uint32{9, 10, 158} {
					if (uint32(tick)+pid+nr)%3 == 0 { // детерминированная нагрузка
						k := SyscallCountKey{pid, nr}
						v := src.rows[k]
						v.N += uint64(1 + (tick*int(pid))%7)
						src.rows[k] = v
					}
				}
			}
			if tick%every != 0 {
				continue
			}
			polls++
			d, err := r.Poll()
			if err != nil {
				t.Fatal(err)
			}
			for _, x := range d {
				perPair[SyscallCountKey{x.PID, x.Nr}] += x.N
				perNr[x.Nr] += x.N
			}
		}
		return
	}
	pair1, nr1, polls1 := run(1)
	pair3, nr3, polls3 := run(3)
	if polls3*3 != polls1 {
		t.Fatalf("опросов %d и %d, ждали отношение 3", polls1, polls3)
	}
	if len(pair1) == 0 {
		t.Fatal("фикстура не создала нагрузки")
	}
	for k, v := range pair1 {
		if pair3[k] != v {
			t.Fatalf("пара %+v: каждый тик %d, каждый третий %d", k, v, pair3[k])
		}
	}
	for nr, v := range nr1 {
		if nr3[nr] != v {
			t.Fatalf("nr=%d: %d против %d", nr, v, nr3[nr])
		}
	}
}

// Граница тождества названа тестом: запись, вытесненная и заведённая заново
// ВНУТРИ интервала, теряет приращение до вытеснения — тем больше, чем реже опрос.
// Это прежнее свойство LRU (прибор — Occupancy), редкий опрос лишь растягивает окно.
func TestSyscallCountReaderEvictionInsideIntervalIsTheOnlyLoss(t *testing.T) {
	k := SyscallCountKey{Tgid: 5, Nr: 9}
	src := &fakeCountSource{rows: map[SyscallCountKey]SyscallCountValue{k: {N: 10}}}
	r := &SyscallCountReader{src: src, last: map[SyscallCountKey]uint64{}}
	if d, _ := r.Poll(); len(d) != 1 || d[0].N != 10 {
		t.Fatalf("%+v", d)
	}
	// Между опросами: ещё 4 (итого 14), запись вытеснена, пересоздана и набрала 3.
	src.rows[k] = SyscallCountValue{N: 3}
	d, _ := r.Poll()
	if len(d) != 1 || d[0].N != 3 {
		t.Fatalf("после вытеснения внутри интервала: %+v", d)
	}
	// Настоящий прирост за интервал был 4 + 3 = 7, прочитано 3: недосчёт 4 — до вытеснения.
}

// G4: опрос не аллоцирует карту на каждый обход.
func BenchmarkSyscallCountReaderPoll(b *testing.B) {
	src := &fakeCountSource{rows: map[SyscallCountKey]SyscallCountValue{}}
	for pid := uint32(1); pid <= 4000; pid++ {
		for _, nr := range []uint32{9, 10, 158} {
			src.rows[SyscallCountKey{pid, nr}] = SyscallCountValue{N: 1}
		}
	}
	r := &SyscallCountReader{src: src, last: map[SyscallCountKey]uint64{}}
	r.Poll()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Poll()
	}
}
