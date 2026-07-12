#!/bin/bash
# Load Testing Script for ebpf-guard Performance Testing
# Tests ebpf-guard performance under various load patterns

set -e

# Configuration
RESULTS_DIR="/opt/ebpf-load-test/results"
LOGS_DIR="/opt/ebpf-load-test/logs"
DURATION=${DURATION:-30}  # Default test duration in seconds
CONCURRENCY=${CONCURRENCY:-10}  # Default concurrent connections
TARGET_URL=${TARGET_URL:-"http://localhost:3000"}  # Default target (Juice Shop)
METRICS_URL=${METRICS_URL:-"http://localhost:9090/metrics"}  # ebpf-guard metrics
REPORT_DIR="$RESULTS_DIR/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "=== ebpf-guard Load Testing ==="
echo "Report directory: $REPORT_DIR"
echo "Target: $TARGET_URL"
echo "Duration: ${DURATION}s, Concurrency: $CONCURRENCY"
echo ""

# Function to capture ebpf-guard metrics before test
capture_baseline() {
    local output="$1"
    echo "Capturing baseline metrics..."
    curl -s "$METRICS_URL" > "$output/baseline.prom" 2>/dev/null || true
}

# Function to capture ebpf-guard metrics after test
capture_metrics() {
    local output="$1"
    local name="$2"
    echo "Capturing metrics after $name..."
    curl -s "$METRICS_URL" > "$output/${name}_metrics.prom" 2>/dev/null || true
}

# Function to analyze metrics difference
analyze_metrics() {
    local baseline="$1/baseline.prom"
    local after="$2/$3_metrics.prom"
    local output="$2/$3_analysis.txt"

    echo "Analyzing metrics for $3..." | tee "$output"

    # Extract key metrics
    echo "=== Alert Metrics ===" >> "$output"
    grep -E "ebpf_guard_alerts_total|ebpf_guard_events_total" "$after" 2>/dev/null || echo "No alert metrics found" >> "$output"

    echo "=== Event Processing Metrics ===" >> "$output"
    grep -E "ebpf_guard_correlator_processing|ebpf_guard_collector_events" "$after" 2>/dev/null || echo "No processing metrics found" >> "$output"

    echo "=== Memory Usage ===" >> "$output"
    grep -E "go_memstats|process_resident_memory_bytes" "$after" 2>/dev/null || echo "No memory metrics found" >> "$output"

    echo "✓ Metrics analysis saved to $output"
}

# Test 1: Baseline - Low Load
test_baseline() {
    echo ""
    echo "=========================================="
    echo "TEST 1: Baseline (1 connection, 30s)"
    echo "=========================================="
    capture_baseline "$REPORT_DIR"

    echo "Running wrk with 1 connection..."
    wrk -t1 -c1 -d30s "$TARGET_URL" > "$REPORT_DIR/test1_baseline.txt" 2>&1
    cat "$REPORT_DIR/test1_baseline.txt"

    capture_metrics "$REPORT_DIR" "test1_baseline"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test1_baseline"
}

# Test 2: Medium Load
test_medium() {
    echo ""
    echo "=========================================="
    echo "TEST 2: Medium Load (10 connections, 30s)"
    echo "=========================================="

    echo "Running wrk with 10 connections..."
    wrk -t2 -c10 -d30s "$TARGET_URL" > "$REPORT_DIR/test2_medium.txt" 2>&1
    cat "$REPORT_DIR/test2_medium.txt"

    capture_metrics "$REPORT_DIR" "test2_medium"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test2_medium"
}

# Test 3: High Load
test_high() {
    echo ""
    echo "=========================================="
    echo "TEST 3: High Load (50 connections, 30s)"
    echo "=========================================="

    echo "Running wrk with 50 connections..."
    wrk -t4 -c50 -d30s "$TARGET_URL" > "$REPORT_DIR/test3_high.txt" 2>&1
    cat "$REPORT_DIR/test3_high.txt"

    capture_metrics "$REPORT_DIR" "test3_high"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test3_high"
}

# Test 4: Peak Load
test_peak() {
    echo ""
    echo "=========================================="
    echo "TEST 4: Peak Load (100 connections, 30s)"
    echo "=========================================="

    echo "Running wrk with 100 connections..."
    wrk -t4 -c100 -d30s "$TARGET_URL" > "$REPORT_DIR/test4_peak.txt" 2>&1
    cat "$REPORT_DIR/test4_peak.txt"

    capture_metrics "$REPORT_DIR" "test4_peak"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test4_peak"
}

# Test 5: Sustained Load (5 minutes)
test_sustained() {
    echo ""
    echo "=========================================="
    echo "TEST 5: Sustained Load (20 connections, 300s)"
    echo "=========================================="

    echo "Running wrk with 20 connections for 5 minutes..."
    wrk -t4 -c20 -d300s --latency "$TARGET_URL" > "$REPORT_DIR/test5_sustained.txt" 2>&1
    cat "$REPORT_DIR/test5_sustained.txt"

    capture_metrics "$REPORT_DIR" "test5_sustained"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test5_sustained"
}

# Test 6: Mixed Request Patterns
test_mixed() {
    echo ""
    echo "=========================================="
    echo "TEST 6: Mixed Request Patterns (hey)"
    echo "=========================================="

    # Test multiple endpoints
    cat > /tmp/endpoints.txt << EOF
$TARGET_URL/
$TARGET_URL/#/
$TARGET_URL/api/Products
$TARGET_URL/api/Products?id=1
$TARGET_URL/rest/user/login
$TARGET_URL/rest/basket/products
EOF

    echo "Running hey with mixed endpoints..."
    hey -n 1000 -c 10 -m GET -D /tmp/endpoints.txt "$TARGET_URL" > "$REPORT_DIR/test6_mixed.txt" 2>&1
    cat "$REPORT_DIR/test6_mixed.txt"

    capture_metrics "$REPORT_DIR" "test6_mixed"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test6_mixed"
}

# Test 7: Attack Simulation Load
test_attack_load() {
    echo ""
    echo "=========================================="
    echo "TEST 7: Attack Pattern Load (SQLi + Brute Force)"
    echo "=========================================="

    echo "Simulating SQL injection attacks..."
    wrk -t2 -c5 -d30s -s scripts/attack.lua "$TARGET_URL/rest/user/login" \
        > "$REPORT_DIR/test7_attack_load.txt" 2>&1 || true
    cat "$REPORT_DIR/test7_attack_load.txt"

    capture_metrics "$REPORT_DIR" "test7_attack_load"
    analyze_metrics "$REPORT_DIR" "$REPORT_DIR" "test7_attack_load"
}

# Generate summary report
generate_summary() {
    echo ""
    echo "=========================================="
    echo "Generating Summary Report"
    echo "=========================================="

    cat > "$REPORT_DIR/summary.md" << EOF
# ebpf-guard Load Test Report
**Date**: $(date)
**Target**: $TARGET_URL
**Test Duration**: ${DURATION}s per test

## Test Results

### Test 1: Baseline (1 conn)
$(cat "$REPORT_DIR/test1_baseline.txt" | grep -E "Requests/sec|Transfer/sec|Latency")

### Test 2: Medium Load (10 conn)
$(cat "$REPORT_DIR/test2_medium.txt" | grep -E "Requests/sec|Transfer/sec|Latency")

### Test 3: High Load (50 conn)
$(cat "$REPORT_DIR/test3_high.txt" | grep -E "Requests/sec|Transfer/sec|Latency")

### Test 4: Peak Load (100 conn)
$(cat "$REPORT_DIR/test4_peak.txt" | grep -E "Requests/sec|Transfer/sec|Latency")

### Test 5: Sustained Load (20 conn, 5min)
$(cat "$REPORT_DIR/test5_sustained.txt" | grep -E "Requests/sec|Transfer/sec|Latency")

## ebpf-guard Metrics Analysis

### Alert Generation
$(grep -h "ebpf_guard_alerts_total" "$REPORT_DIR"/*_metrics.prom 2>/dev/null | sort | uniq)

### Event Processing
$(grep -h "ebpf_guard_events_total" "$REPORT_DIR"/*_metrics.prom 2>/dev/null | sort | uniq)

## Performance Observations
- Compare event processing rates vs load
- Check for any correlation engine bottlenecks
- Memory usage under sustained load

## Files Generated
- Baseline metrics: baseline.prom
- Test outputs: test*.txt
- Metric snapshots: *_metrics.prom
- Analysis files: *_analysis.txt
EOF

    echo "✓ Summary report generated: $REPORT_DIR/summary.md"
    cat "$REPORT_DIR/summary.md"
}

# Main execution
main() {
    echo "Starting load tests at $(date)"
    echo ""

    # Check if target is reachable
    if ! curl -sf "$TARGET_URL" > /dev/null 2>&1; then
        echo "⚠️  WARNING: Target $TARGET_URL is not reachable!"
        echo "Tests will continue but may fail."
    fi

    # Check if ebpf-guard metrics are reachable
    if ! curl -sf "$METRICS_URL" > /dev/null 2>&1; then
        echo "⚠️  WARNING: ebpf-guard metrics at $METRICS_URL are not reachable!"
        echo "Metrics collection will be skipped."
    fi

    # Run tests
    test_baseline
    sleep 2

    test_medium
    sleep 2

    test_high
    sleep 2

    test_peak
    sleep 2

    # Skip sustained test if QUICK_MODE is set
    if [ "${QUICK_MODE:-0}" != "1" ]; then
        test_sustained
        sleep 2
    else
        echo ""
        echo "⚡ QUICK_MODE: Skipping sustained 5-minute test"
    fi

    test_mixed
    sleep 2

    # Generate summary
    generate_summary

    echo ""
    echo "✓ All load tests completed!"
    echo "Results saved to: $REPORT_DIR"
    echo ""
    echo "Quick view of results:"
    ls -lh "$REPORT_DIR"
}

# Run main function
main "$@"
