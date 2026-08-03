// SPDX-License-Identifier: Apache-2.0
//
// boottime.go converts BPF CLOCK_MONOTONIC timestamps to Unix epoch time.
//
// Every ebpf-guard BPF program stamps events with bpf_ktime_get_ns(), which
// returns nanoseconds elapsed since boot (CLOCK_MONOTONIC). Downstream Go
// code treats Event.Timestamp as Unix-epoch nanoseconds (time.Unix(0, ts)),
// so without conversion every alert and event is mis-dated to 1970, offset
// from the epoch by the host's uptime. KtimeToEpoch derives boot's epoch
// instant once from /proc/uptime and adds it to each ktime value.

package types

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// bootOffset holds the realtime (epoch) nanosecond timestamp of system boot.
// It is computed exactly once per process on first use.
var bootOffset struct {
	sync.Once
	ns int64
}

// InitBootOffset eagerly computes the boot→epoch offset from /proc/uptime.
// Optional: KtimeToEpoch lazily performs the same initialisation on first call.
// Safe to call concurrently and repeatedly.
func InitBootOffset() {
	bootOffset.Do(computeBootOffset)
}

func computeBootOffset() {
	now := time.Now().UnixNano()
	bootOffset.ns = now - readProcUptimeNanos()
}

// KtimeToEpoch converts a BPF CLOCK_MONOTONIC timestamp (the value returned by
// bpf_ktime_get_ns, i.e. nanoseconds since boot) into a Unix epoch nanosecond
// timestamp suitable for time.Unix(0, ts).
//
// On read/parse error of /proc/uptime the offset falls back to 0, preserving
// the raw ktime value rather than crashing the event pipeline; this only
// happens on non-Linux hosts or in unit tests, never in production.
func KtimeToEpoch(ktime uint64) uint64 {
	bootOffset.Do(computeBootOffset)
	return uint64(int64(ktime) + bootOffset.ns)
}

// readProcUptimeNanos parses the first field of /proc/uptime (uptime in
// seconds as a decimal float) into nanoseconds. Returns 0 on any error or when
// /proc/uptime is unavailable (non-Linux hosts / unit tests).
func readProcUptimeNanos() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(strings.TrimRight(string(data), "\n"))
	if len(fields) < 1 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs < 0 || secs > 1e12 {
		return 0
	}
	return int64(secs * 1e9)
}
