package collector

import "testing"

// Волна 6.3, item 4 (№328, открытый вопрос 4): "не по нулю" половина
// сторожа немоты — dnsRateStale is the pure decision dnsRateStale pulls out
// of watchForStaleness's ticker loop, so it is exercised here without
// waiting on real wall-clock time.
func TestDnsRateStale(t *testing.T) {
	cases := []struct {
		name         string
		minEvents    int
		windowFull   bool
		windowEvents uint64
		want         bool
	}{
		{"disabled (0) never fires, even with zero events in a full window", 0, true, 0, false},
		{"disabled (negative) never fires either", -1, true, 0, false},
		{"window not yet full: no verdict regardless of count", 8, false, 0, false},
		{"below floor in a full window: stale", 8, true, 3, true},
		{"at the floor: not stale (floor is inclusive of passing)", 8, true, 8, false},
		{"above floor: not stale", 8, true, 50, false},
		{"zero events in a full window, floor set: stale", 8, true, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsRateStale(tc.minEvents, tc.windowFull, tc.windowEvents)
			if got != tc.want {
				t.Errorf("dnsRateStale(%d, %v, %d) = %v, want %v",
					tc.minEvents, tc.windowFull, tc.windowEvents, got, tc.want)
			}
		})
	}
}

func TestDNSCollector_WithMinEventsPerStaleWindow_SetsField(t *testing.T) {
	c := &DNSCollector{}
	c.WithMinEventsPerStaleWindow(42)
	if c.minEventsPerStaleWindow != 42 {
		t.Fatalf("got %d, want 42", c.minEventsPerStaleWindow)
	}
}

func TestDNSCollector_Stale_DefaultsFalse(t *testing.T) {
	c := &DNSCollector{}
	if c.Stale() {
		t.Fatal("a freshly constructed collector must report Stale()==false before any watchForStaleness tick")
	}
	c.stale.Store(true)
	if !c.Stale() {
		t.Fatal("Stale() must reflect the underlying atomic state")
	}
}
