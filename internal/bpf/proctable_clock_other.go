//go:build !linux

package bpf

// monotonicNs вне Linux: таблицы процессов нет, часы не нужны (0 отключает проверку TTL).
func monotonicNs() uint64 { return 0 }
