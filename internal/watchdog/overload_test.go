package watchdog

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type ovHarness struct {
	drop, acc int64
	fill      float64
	rate      float64
	rateSet   int
}

func (h *ovHarness) SetSamplingRate(eventType string, rate float64) {
	if eventType == "file" {
		h.rate = rate
		h.rateSet++
	}
}

func newOv(h *ovHarness) *OverloadShedder {
	cfg := DefaultOverloadConfig()
	cfg.CalmTicks = 3
	return NewOverloadShedder(cfg, nil, h, OverloadSignals{
		BulkDropped:  func() int64 { return h.drop },
		BulkAccepted: func() int64 { return h.acc },
		Fill:         func() float64 { return h.fill },
	})
}

func TestOverload_LossRaisesDivisorAndCalmLowersIt(t *testing.T) {
	h := &ovHarness{}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now) // baseline
	assert.False(t, s.Active())

	h.fill = 0.95
	for i := 1; i <= 12; i++ {
		now = now.Add(time.Second)
		h.acc += 900
		h.drop += 300 // 25%
		s.Step(now)
	}
	assert.True(t, s.Active())
	assert.Greater(t, s.Divisor(), 2.0)
	assert.InDelta(t, 1/s.Divisor(), h.rate, 1e-9, "arbiter gets 1/N")

	// Loss stops: calm lowers N step by step and finally switches off.
	h.fill = 0.02
	for i := 0; i < 80; i++ {
		now = now.Add(time.Second)
		h.acc += 100
		s.Step(now)
	}
	assert.False(t, s.Active())
	assert.Equal(t, 1.0, h.rate)
}

// A full queue WITHOUT loss (one hot pid keeps its worker busy) is not pressure.
func TestOverload_FullQueueWithoutLossIsNotPressure(t *testing.T) {
	h := &ovHarness{fill: 1}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now)
	for i := 0; i < 20; i++ {
		now = now.Add(time.Second)
		h.acc += 1000
		s.Step(now)
	}
	assert.False(t, s.Active())
}

// Loss between LossLow and LossHigh is tolerated: N neither rises nor falls.
func TestOverload_ToleratedLossHoldsDivisor(t *testing.T) {
	h := &ovHarness{}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now)
	now = now.Add(time.Second)
	h.acc += 800
	h.drop += 200
	s.Step(now)
	assert.True(t, s.Active())
	n := s.Divisor()
	for i := 0; i < 30; i++ {
		now = now.Add(time.Second)
		h.acc += 97000
		h.drop += 3000 // 3%: between LossLow (1%) and LossHigh (5%)
		s.Step(now)
	}
	assert.Equal(t, n, s.Divisor())
}

func TestOverload_DropRateRaisesDivisorEvenWithLowFill(t *testing.T) {
	h := &ovHarness{}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now)
	now = now.Add(time.Second)
	h.acc += 9000
	h.drop += 1000 // 10%
	s.Step(now)
	assert.True(t, s.Active())
}

func TestOverload_SmallDropsIgnored(t *testing.T) {
	h := &ovHarness{}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now)
	for i := 0; i < 5; i++ {
		now = now.Add(time.Second)
		h.acc += 1000000
		h.drop += 10 // 0.001%
		s.Step(now)
	}
	assert.False(t, s.Active())
}

func TestOverload_CapsAtMaxDivisor(t *testing.T) {
	h := &ovHarness{fill: 1}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now)
	for i := 0; i < 200; i++ {
		now = now.Add(5 * time.Second)
		h.acc += 500
		h.drop += 500
		s.Step(now)
	}
	assert.Equal(t, DefaultOverloadConfig().MaxDivisor, s.Divisor())
}

func TestOverload_HoldBetweenSteps(t *testing.T) {
	h := &ovHarness{fill: 1}
	s := newOv(h)
	now := time.Unix(1000, 0)
	s.Step(now)
	now = now.Add(time.Second)
	h.acc += 500
	h.drop += 500
	s.Step(now)
	first := s.Divisor()
	now = now.Add(time.Second) // inside the 2-tick hold
	h.acc += 500
	h.drop += 500
	s.Step(now)
	assert.Equal(t, first, s.Divisor(), "no second step inside the hold window")
}
