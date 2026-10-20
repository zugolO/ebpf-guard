package collector

// pidHeavyTracker is a space-saving counter with a halving window over the pids of one ring
// reader (волна 9, заход B, 8.8.4): a pid holding at least 1/8 of the recent window is heavy.
// Written and read by the single reader goroutine only, so it needs no lock.
type pidHeavyTracker struct {
	pid [pidHeavySlots]uint32
	cnt [pidHeavySlots]int32
	n   int32
}

const (
	pidHeavySlots  = 8
	pidHeavyWindow = 256
	pidHeavyShare  = pidHeavyWindow / 8
)

// note counts one event of pid.
func (h *pidHeavyTracker) note(pid uint32) {
	slot, minI := -1, 0
	for i := 0; i < pidHeavySlots; i++ {
		if h.cnt[i] > 0 && h.pid[i] == pid {
			slot = i
			break
		}
		if h.cnt[i] < h.cnt[minI] {
			minI = i
		}
	}
	if slot >= 0 {
		h.cnt[slot]++
	} else {
		h.pid[minI], h.cnt[minI] = pid, 1
	}
	if h.n++; h.n >= pidHeavyWindow {
		for i := range h.cnt {
			h.cnt[i] >>= 1
		}
		h.n = 0
	}
}

// isHeavy reports whether pid holds at least pidHeavyShare of the recent window.
func (h *pidHeavyTracker) isHeavy(pid uint32) bool {
	for i := 0; i < pidHeavySlots; i++ {
		if h.cnt[i] > 0 && h.pid[i] == pid {
			return h.cnt[i] >= pidHeavyShare
		}
	}
	return false
}
