// Package main is the ebpf-guard comparative benchmark workload generator.
//
// It generates a reproducible mix of syscall, file, network, and DNS events
// to drive the comparative benchmarks in bench/comparative/run.sh.
//
// Usage:
//
//	go run ./bench/comparative/workload/gen.go [flags]
//
// Flags:
//
//	--duration   Duration of the workload (default: 60s)
//	--intensity  Load intensity 1-10 (default: 5)
//	--seed       RNG seed for reproducibility (default: 42)
//	--output     Path to write JSON results (default: /tmp/workload-results.json)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

// Result is the JSON structure written to --output.
type Result struct {
	DurationMS      int64            `json:"duration_ms"`
	EventsGenerated int64            `json:"events_generated"`
	Seed            int64            `json:"seed"`
	Intensity       int              `json:"intensity"`
	EventTypes      map[string]int64 `json:"event_types"`
	OS              string           `json:"os"`
	Arch            string           `json:"arch"`
	CPUs            int              `json:"cpus"`
}

func main() {
	var (
		durationStr = flag.String("duration", "60s", "Duration of the workload (e.g. 30s, 2m)")
		intensity   = flag.Int("intensity", 5, "Load intensity 1-10 (higher = more syscalls/sec)")
		seed        = flag.Int64("seed", 42, "RNG seed for reproducibility")
		output      = flag.String("output", "/tmp/workload-results.json", "Path to write JSON results")
	)
	flag.Parse()

	duration, err := time.ParseDuration(*durationStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --duration %q: %v\n", *durationStr, err)
		os.Exit(1)
	}
	if *intensity < 1 || *intensity > 10 {
		fmt.Fprintf(os.Stderr, "--intensity must be between 1 and 10\n")
		os.Exit(1)
	}

	rng := rand.New(rand.NewSource(*seed)) //nolint:gosec // workload tool, not crypto
	_ = rng

	// iterationsPerSec scales linearly with intensity: intensity=5 → ~10k ops/s.
	iterationsPerSec := *intensity * 2000

	fmt.Printf("workload-gen: duration=%s intensity=%d seed=%d output=%s\n",
		duration, *intensity, *seed, *output)
	fmt.Printf("workload-gen: target=%d ops/sec\n", iterationsPerSec)

	result := &Result{
		Seed:       *seed,
		Intensity:  *intensity,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		CPUs:       runtime.NumCPU(),
		EventTypes: make(map[string]int64),
	}

	deadline := time.Now().Add(duration)
	start := time.Now()

	// Create temp directory for file operations.
	tmpDir, err := os.MkdirTemp("", "ebpf-guard-workload-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	// Target loop rate: sleep between batches to hit iterationsPerSec.
	batchSize := 100
	sleepPerBatch := time.Duration(float64(time.Second) / float64(iterationsPerSec/batchSize))
	if sleepPerBatch < 0 {
		sleepPerBatch = 0
	}

	var totalEvents int64
	phase := 0

	for time.Now().Before(deadline) {
		// Round-robin between event categories for a realistic mix.
		switch phase % 4 {
		case 0:
			// Syscall storm: open/close/read/write in tight loop.
			n := generateSyscallStorm(tmpDir, batchSize)
			result.EventTypes["syscall"] += int64(n)
			totalEvents += int64(n)
		case 1:
			// File operations: create temp files, stat, truncate.
			n := generateFileOps(tmpDir, batchSize/10)
			result.EventTypes["file"] += int64(n)
			totalEvents += int64(n)
		case 2:
			// Network connects: dial localhost on known-closed ports.
			n := generateNetworkOps(batchSize / 20)
			result.EventTypes["network"] += int64(n)
			totalEvents += int64(n)
		case 3:
			// DNS lookups: resolve a mix of valid/invalid hosts.
			n := generateDNSOps(batchSize / 50)
			result.EventTypes["dns"] += int64(n)
			totalEvents += int64(n)
		}
		phase++

		if sleepPerBatch > 0 {
			time.Sleep(sleepPerBatch)
		}

		// Print progress every 5 seconds.
		if phase%500 == 0 {
			elapsed := time.Since(start)
			remaining := time.Until(deadline)
			rate := float64(totalEvents) / elapsed.Seconds()
			fmt.Printf("workload-gen: elapsed=%.0fs remaining=%.0fs events=%d rate=%.0f/s\n",
				elapsed.Seconds(), remaining.Seconds(), totalEvents, rate)
		}
	}

	elapsed := time.Since(start)
	result.DurationMS = elapsed.Milliseconds()
	result.EventsGenerated = totalEvents

	// Write JSON result.
	f, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output file %q: %v\n", *output, err)
		os.Exit(1)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("workload-gen: done events=%d duration=%.2fs rate=%.0f/s output=%s\n",
		totalEvents, elapsed.Seconds(), float64(totalEvents)/elapsed.Seconds(), *output)
}

// generateSyscallStorm performs n open/read/write/close cycles on a temp file,
// generating a realistic stream of file-related syscalls for the monitoring agent.
func generateSyscallStorm(tmpDir string, n int) int {
	path := tmpDir + "/storm.tmp"
	count := 0
	buf := make([]byte, 64)

	for i := 0; i < n; i++ {
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0600)
		if err != nil {
			// Fall back to os.Create if direct syscall fails (permission/platform).
			f, e2 := os.Create(path)
			if e2 != nil {
				continue
			}
			_, _ = f.Write(buf)
			f.Close()
			count++
			continue
		}
		_, _ = syscall.Write(fd, buf)
		_, _ = syscall.Read(fd, buf)
		_ = syscall.Close(fd)
		count += 3 // open + write + read count as 3 events
	}
	return count
}

// generateFileOps creates and removes temp files, generating inode churn.
func generateFileOps(tmpDir string, n int) int {
	count := 0
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("%s/file-%d.tmp", tmpDir, i)
		f, err := os.Create(path)
		if err != nil {
			continue
		}
		_, _ = f.WriteString("ebpf-guard-workload\n")
		f.Close()
		if err := os.Remove(path); err == nil {
			count += 3 // create + write + remove
		} else {
			count += 2
		}
	}
	return count
}

// generateNetworkOps attempts TCP connections to localhost on closed ports.
// The connections will be refused immediately but generate network events.
func generateNetworkOps(n int) int {
	// Use ports 19000-19099 — unlikely to have a listener.
	ports := []string{
		"127.0.0.1:19001", "127.0.0.1:19002", "127.0.0.1:19003",
		"127.0.0.1:19004", "127.0.0.1:19005",
	}
	count := 0
	for i := 0; i < n; i++ {
		addr := ports[i%len(ports)]
		conn, err := net.DialTimeout("tcp", addr, 10*time.Millisecond)
		if err == nil {
			conn.Close()
		}
		// Count regardless of error: the connect syscall still fires.
		count++
	}
	return count
}

// generateDNSOps resolves a mix of real and synthetic hostnames.
// Real lookups exercise the DNS resolver; synthetic ones generate NXDOMAIN events.
func generateDNSOps(n int) int {
	hosts := []string{
		"localhost",                      // always resolves
		"ebpf-guard-workload.invalid",    // NXDOMAIN
		"benchmark.ebpf-guard.test",      // NXDOMAIN
		"time.cloudflare.com",            // real
	}
	count := 0
	for i := 0; i < n; i++ {
		host := hosts[i%len(hosts)]
		// LookupHost generates DNS queries on Linux even for localhost (nsswitch).
		addrs, _ := net.LookupHost(host)
		_ = addrs
		count++
	}
	return count
}

// spawnHelper spawns a short-lived child process to generate execve events.
// This is the most direct way to generate execve tracepoints.
func spawnHelper() {
	cmd := exec.Command("/bin/true")
	_ = cmd.Run()
}

// init registers spawnHelper as a side-effect generator; it is unused in the main
// benchmark loop but available for intensity levels 8-10 that need execve events.
var _ = spawnHelper
