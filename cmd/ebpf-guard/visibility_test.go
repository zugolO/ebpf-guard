package main

import (
	"testing"
	"time"
)

func TestLossTracker_BulkNeedsMaterialRate(t *testing.T) {
	var tr lossTracker
	now := time.Unix(1000, 0)
	// 311 drops in 2.8 M events (Е6 "loss-free" host step) → healthy.
	wd, wa := tr.observe(31, 280000)
	if tr.degraded(now, false, wd, wa) {
		t.Fatalf("0.01%% loss must not read degraded")
	}
	// 5% loss → degraded at once.
	now = now.Add(time.Second)
	wd, wa = tr.observe(20000, 380000)
	if !tr.degraded(now, false, wd, wa) {
		t.Fatalf("5%% loss must read degraded")
	}
}

func TestLossTracker_HoldThenRecover(t *testing.T) {
	var tr lossTracker
	now := time.Unix(1000, 0)
	wd, wa := tr.observe(5000, 1000)
	if !tr.degraded(now, false, wd, wa) {
		t.Fatal("expected degraded")
	}
	// Drops stop; window still carries the loss for lossWindow ticks, then the
	// hold expires degradationHold after the last bad evaluation.
	var got bool
	for i := 1; i <= lossWindow+10; i++ {
		now = now.Add(time.Second)
		wd, wa = tr.observe(0, 1000)
		got = tr.degraded(now, false, wd, wa)
	}
	if got {
		t.Fatal("must recover once the window is clean and the hold has passed")
	}
}

func TestLossTracker_ProtectedAnyDrop(t *testing.T) {
	var tr lossTracker
	now := time.Unix(1000, 0)
	wd, wa := tr.observe(1, 1_000_000)
	if !tr.degraded(now, true, wd, wa) {
		t.Fatal("a single protected drop must read degraded")
	}
}

func TestLossTracker_SmallBulkBurstIgnored(t *testing.T) {
	var tr lossTracker
	now := time.Unix(1000, 0)
	// 3 of 5 events dropped: 60% but below bulkLossMinDrops → not material.
	wd, wa := tr.observe(3, 2)
	if tr.degraded(now, false, wd, wa) {
		t.Fatal("below min-drops must not degrade")
	}
}
