//go:build linux

package bpf

import "golang.org/x/sys/unix"

// monotonicNs — CLOCK_MONOTONIC в наносекундах: ровно та шкала, что у bpf_ktime_get_ns()
// (exit_ts записи таблицы процессов).
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
