package main

import "testing"

// TestW9B_BulkShardsKeepTheMemoryBound: the shards of the bulk queue share the depth of
// the former single queue, so capQueueDepthByMemLimit still bounds their sum (pod GC
// spiral, волна 8.8) — sharding must not multiply the queued heap by the worker count.
func TestW9B_BulkShardsKeepTheMemoryBound(t *testing.T) {
	for _, tc := range []struct{ workers, depth, per int }{
		{4, 65536, 16384}, {2, 7740, 3870}, {0, 4096, 4096}, {1, 4096, 4096}, {8, 4, 1},
	} {
		s := makeBulkShards(tc.workers, tc.depth)
		want := tc.workers
		if want < 1 {
			want = 1
		}
		if len(s) != want {
			t.Fatalf("workers=%d: shards %d, want %d", tc.workers, len(s), want)
		}
		if got := bulkShardsCap(s); got > tc.depth && tc.per > 1 {
			t.Fatalf("workers=%d depth=%d: shards hold %d > depth", tc.workers, tc.depth, got)
		}
		if cap(s[0]) != tc.per {
			t.Fatalf("workers=%d depth=%d: per-shard %d, want %d", tc.workers, tc.depth, cap(s[0]), tc.per)
		}
	}
}
