//go:build race

package e2e

// p99ContentionTargetMicros is the P99 lock-wait target for TestShardedLockContention
// when the race detector is active.  The race detector adds significant overhead to
// time.Now() calls and goroutine scheduling, inflating measured wall-clock values
// well beyond actual lock-wait time.  50 µs accommodates that overhead while still
// confirming that no shard-level serialisation is occurring.
const p99ContentionTargetMicros = int64(50)
