//go:build !race

package e2e

// p99ContentionTargetMicros is the P99 lock-wait target for TestShardedLockContention.
// Without the race detector, 128-shard bitmask routing gives true zero contention
// (P99 = 0 µs); 5 µs is a conservative upper bound.
const p99ContentionTargetMicros = int64(5)
