package profiler

import (
	"testing"
	"time"
)

// Доводка 8.2: тик уборки — TTL/5, а не TTL (удержание было до 2×TTL).
func TestLineageCleanupInterval(t *testing.T) {
	cases := []struct{ ttl, want time.Duration }{
		{5 * time.Minute, time.Minute},
		{10 * time.Minute, 2 * time.Minute},
		{30 * time.Second, 10 * time.Second}, // нижняя граница
		{time.Second, 10 * time.Second},
	}
	for _, c := range cases {
		if got := lineageCleanupInterval(c.ttl); got != c.want {
			t.Errorf("lineageCleanupInterval(%v) = %v, want %v", c.ttl, got, c.want)
		}
	}
}
