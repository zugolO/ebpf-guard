package correlator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 9, заход B (В8): три равных горячих pid на одном воркере все считаются
// тяжёлыми (k=1 не называл ни одного), лёгкий pid среди них — нет.
func TestW9B_HeavyTracker_ThreeHotPidsLightStaysLight(t *testing.T) {
	var h heavyTracker
	for round := 0; round < 40; round++ {
		for i := 0; i < 100; i++ {
			h.note(1001)
			h.note(1002)
			h.note(1003)
		}
		h.note(7) // лёгкий: ~0,3% потока
	}
	for _, pid := range []uint32{1001, 1002, 1003} {
		if !h.isHeavy(pid) {
			t.Errorf("горячий pid %d не назван тяжёлым", pid)
		}
	}
	if h.isHeavy(7) {
		t.Error("лёгкий pid назван тяжёлым")
	}
	if h.isHeavy(424242) {
		t.Error("незнакомый pid назван тяжёлым")
	}
}

// Окно полуубывания: pid, замолчавший после потока, перестаёт быть тяжёлым.
func TestW9B_HeavyTracker_DecaysAfterBurst(t *testing.T) {
	var h heavyTracker
	for i := 0; i < 500; i++ {
		h.note(5)
	}
	if !h.isHeavy(5) {
		t.Fatal("поток не назван тяжёлым")
	}
	for i := 0; i < 8*heavyWindow; i++ {
		h.note(uint32(100 + i%20)) // двадцать мелких, каждый ~5%
	}
	if h.isHeavy(5) {
		t.Error("замолчавший pid остался тяжёлым")
	}
}

// Лёгкий pid с редкими событиями не набирает долю при свободных слотах:
// без окна счётчик рос бы вечно.
func TestW9B_HeavyTracker_SparsePidNeverAccumulates(t *testing.T) {
	var h heavyTracker
	for i := 0; i < 100000; i++ {
		h.note(1)
		h.note(2)
		if i%200 == 0 {
			h.note(9)
		}
	}
	if h.isHeavy(9) {
		t.Error("редкий pid накопил вес в свободном слоте")
	}
}

// Волна 9, заход B (8.8.4): при непрерывной подаче protected-событий воркер всё равно
// берёт bulk-событие — раньше строгий приоритет не пускал его, пока защищённый
// диспетчер держал канал полным.
func TestW9B_WorkerTakesBulkUnderProtectedFlood(t *testing.T) {
	cfg := DefaultCorrelationEngineConfig()
	cfg.Rules = []Rule{{ID: "w9b_file", Name: "file", EventType: types.EventFileAccess,
		Condition: RuleCondition{Field: "filename", Op: OpEquals, Values: []string{"/etc/w9b-fair"}},
		Severity:  types.SeverityWarning, Action: ActionAlert}}
	cfg.EnableDedup = false
	cfg.EnableRateLimit = false
	cfg.IngestWorkerCount = 1
	cfg.IngestWorkerBufferSize = 64
	eng := NewCorrelationEngineWithConfig(cfg)
	defer eng.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			eng.IngestAsyncPriority(ctx, types.Event{Type: types.EventTCPConnect, PID: 1, Network: &types.NetworkEvent{Dport: 1}}, true)
		}
	}()
	time.Sleep(100 * time.Millisecond) // канал protected полон, воркер занят им
	fe := &types.FileEvent{}
	fe.Filename = "/etc/w9b-fair"
	eng.IngestAsyncPriority(ctx, types.Event{Type: types.EventFileAccess, PID: 2, File: fe}, false)

	// Событие снято с bulk-канала воркера (алерт ждёт локального сброса — его здесь не судим).
	deadline := time.Now().Add(2 * time.Second)
	got := false
	for time.Now().Before(deadline) && !got {
		got = len(eng.ingestPool[0].ch) == 0
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	assert.True(t, got, "bulk-событие не обработано за 2 с под потоком protected")
}
