package collector

import "testing"

func TestPidHeavyTracker_HotPidsHeavyLightNot(t *testing.T) {
	var h pidHeavyTracker
	for r := 0; r < 40; r++ {
		for i := 0; i < 100; i++ {
			h.note(11)
			h.note(12)
			h.note(13)
		}
		h.note(7)
	}
	for _, p := range []uint32{11, 12, 13} {
		if !h.isHeavy(p) {
			t.Errorf("горячий pid %d не тяжёлый", p)
		}
	}
	if h.isHeavy(7) || h.isHeavy(999) {
		t.Error("лёгкий или незнакомый pid назван тяжёлым")
	}
}
