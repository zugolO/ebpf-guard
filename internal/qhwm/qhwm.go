// Package qhwm tracks the high-water mark of queue depths (wave 8.1 item 9).
//
// The existing occupancy gauges are Set() every 30 s from len(ch), so a burst
// that fills a queue and drains inside the tick is invisible, and queue sizing
// (items 9/10) has no honest input: a point reading says nothing about the peak.
// Tracker samples every registered queue once a second and publishes, per queue:
//
//	ebpf_guard_queue_depth_hwm{queue}          max depth over the trailing 5 min
//	ebpf_guard_queue_depth_hwm_lifetime{queue} max depth since process start
//	ebpf_guard_queue_capacity{queue}           channel capacity
//
// The trailing window is five 1-minute buckets, so a reader that scrapes every
// 5 minutes (idle-run snapshots) sees the peak of the whole interval and not
// the last few seconds. Sampling is at 1 Hz: a sub-second spike can still be
// missed, so a 0 HWM means "not seen at 1 Hz", not "never full" — losses on the
// queue's drop counter remain the verdict for fullness.
package qhwm

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	bucketCount      = 5
	samplesPerBucket = 60 // one sample per second
	sampleEvery      = time.Second
)

type queue struct {
	name     string
	lenFn    func() int
	buckets  [bucketCount]int
	cur      int
	n        int // samples taken in the current bucket
	lifetime int
}

// Tracker samples registered queues. The zero value is not usable; use New.
type Tracker struct {
	mu       sync.Mutex
	queues   []*queue
	window   *prometheus.GaugeVec
	lifetime *prometheus.GaugeVec
	capacity *prometheus.GaugeVec
}

// New creates a Tracker and registers its series with reg (nil reg skips
// registration, for tests).
func New(reg prometheus.Registerer) (*Tracker, error) {
	t := &Tracker{
		window: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_queue_depth_hwm",
			Help: "Peak queue depth (items) over the trailing 5 minutes, sampled at 1 Hz.",
		}, []string{"queue"}),
		lifetime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_queue_depth_hwm_lifetime",
			Help: "Peak queue depth (items) since process start, sampled at 1 Hz.",
		}, []string{"queue"}),
		capacity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_queue_capacity",
			Help: "Queue capacity (items).",
		}, []string{"queue"}),
	}
	if reg != nil {
		for _, c := range []prometheus.Collector{t.window, t.lifetime, t.capacity} {
			if err := reg.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return t, nil
}

// Track adds a queue. lenFn must be safe to call concurrently (len(ch) is).
func (t *Tracker) Track(name string, lenFn, capFn func() int) {
	if t == nil || lenFn == nil {
		return
	}
	t.mu.Lock()
	t.queues = append(t.queues, &queue{name: name, lenFn: lenFn})
	t.mu.Unlock()
	if capFn != nil {
		t.capacity.WithLabelValues(name).Set(float64(capFn()))
	}
	t.window.WithLabelValues(name).Set(0)
	t.lifetime.WithLabelValues(name).Set(0)
}

// sample takes one reading of every queue and refreshes the gauges.
func (t *Tracker) sample() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, q := range t.queues {
		v := q.lenFn()
		if v > q.buckets[q.cur] {
			q.buckets[q.cur] = v
		}
		if v > q.lifetime {
			q.lifetime = v
		}
		q.n++
		if q.n >= samplesPerBucket {
			q.n = 0
			q.cur = (q.cur + 1) % bucketCount
			q.buckets[q.cur] = 0
		}
		peak := 0
		for _, b := range q.buckets {
			if b > peak {
				peak = b
			}
		}
		t.window.WithLabelValues(q.name).Set(float64(peak))
		t.lifetime.WithLabelValues(q.name).Set(float64(q.lifetime))
	}
}

// Run samples until ctx is cancelled.
func (t *Tracker) Run(ctx context.Context) {
	if t == nil {
		return
	}
	tk := time.NewTicker(sampleEvery)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.sample()
		}
	}
}
