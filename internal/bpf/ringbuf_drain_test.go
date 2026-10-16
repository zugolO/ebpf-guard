package bpf

import (
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// availRing — fakeRing с AvailableBytes: сколько записей сейчас лежит в кольце.
type availRing struct {
	fakeRing
	avail int
}

func (a *availRing) AvailableBytes() int { return a.avail }

func (a *availRing) ReadInto(rec *ringbuf.Record) error {
	if a.avail > 0 {
		a.avail--
	}
	return a.fakeRing.ReadInto(rec)
}

// Волна 8.7, П2: на пустом кольце читатель спит окно; на непустом — читает сразу.
func TestDrainWindowSleepsOnEmptyRingOnly(t *testing.T) {
	windows := 0
	ring := &availRing{}
	r := newRingbufReader(ring, 0, RingbufReaderOptions{DrainWindow: 30 * time.Millisecond, OnDrain: func() { windows++ }}, nil)

	var rec ringbuf.Record
	start := time.Now()
	if err := r.ReadInto(&rec); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 25*time.Millisecond {
		t.Fatalf("пустое кольцо: окно не выспано (%v)", d)
	}
	if windows != 1 {
		t.Fatalf("окон %d, ожидалось 1", windows)
	}

	ring.avail = 3 // кольцо отстаёт: окно не добавляет задержки
	start = time.Now()
	for i := 0; i < 3; i++ {
		_ = r.ReadInto(&rec)
		if i < 2 {
			ring.avail = 3 - i - 1 + 1
		}
	}
	if d := time.Since(start); d > 20*time.Millisecond {
		t.Fatalf("непустое кольцо читается с задержкой %v", d)
	}
	if windows != 1 {
		t.Fatalf("окно спано на непустом кольце: %d", windows)
	}
}

func TestDrainWindowOffIsPreviousPath(t *testing.T) {
	ring := &availRing{}
	r := newRingbufReader(ring, 0, RingbufReaderOptions{}, nil)
	var rec ringbuf.Record
	start := time.Now()
	_ = r.ReadInto(&rec)
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("окно выключено, а читатель спит")
	}
}

// Close прерывает сон окна.
func TestDrainWindowInterruptedByClose(t *testing.T) {
	ring := &availRing{}
	r := newRingbufReader(ring, 0, RingbufReaderOptions{DrainWindow: 5 * time.Second}, nil)
	done := make(chan struct{})
	go func() {
		var rec ringbuf.Record
		_ = r.ReadInto(&rec)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	_ = r.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close не прервал окно слива")
	}
}

// Ядро читателя без AvailableBytes (фейк старых тестов): окно молча выключено, а не паника.
func TestDrainWindowWithoutAvailableBytes(t *testing.T) {
	r := newRingbufReader(&fakeRing{}, 0, RingbufReaderOptions{DrainWindow: time.Second}, nil)
	var rec ringbuf.Record
	start := time.Now()
	_ = r.ReadInto(&rec)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("без AvailableBytes окно не должно спать")
	}
}
