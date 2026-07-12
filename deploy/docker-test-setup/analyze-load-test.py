#!/usr/bin/env python3
"""
Load Test Results Analyzer for ebpf-guard
Analyzes the results from load testing and generates reports
"""

import re
import sys
import json
from pathlib import Path
from datetime import datetime
import argparse

def parse_wrk_output(file_path):
    """Parse wrk output file and extract metrics"""
    with open(file_path, 'r') as f:
        content = f.read()

    metrics = {
        'requests_per_sec': None,
        'transfer_per_sec': None',
        'avg_latency_ms': None,
        'stdev_latency_ms': None,
        'p50_latency_ms': None,
        'p75_latency_ms': None,
        'p90_latency_ms': None,
        'p99_latency_ms': None
    }

    # Extract requests/sec
    match = re.search(r'Requests/sec:\s+([\d.]+)', content)
    if match:
        metrics['requests_per_sec'] = float(match.group(1))

    # Extract transfer/sec
    match = re.search(r'Transfer/sec:\s+([\d.]+[A-Z]+)', content)
    if match:
        metrics['transfer_per_sec'] = match.group(1)

    # Extract latency stats
    match = re.search(r'Latency\s+([\d.]+[a-z]+)\s+([\d.]+[a-z]+)', content)
    if match:
        # Convert to ms (assuming input is in us or ms)
        metrics['avg_latency_ms'] = parse_latency(match.group(1))
        metrics['stdev_latency_ms'] = parse_latency(match.group(2))

    # Extract percentiles
    for percentile in ['50', '75', '90', '99']:
        pattern = f'{percentile}%\s+([\d.]+[a-z]+)'
        match = re.search(pattern, content)
        if match:
            metrics[f'p{percentile}_latency_ms'] = parse_latency(match.group(1))

    return metrics

def parse_latency(lat_str):
    """Convert latency string to milliseconds"""
    val = float(re.findall(r'[\d.]+', lat_str)[0])
    unit = re.findall(r'[a-z]+', lat_str)[0] if re.findall(r'[a-z]+', lat_str) else 's'

    if unit == 'us':
        return val / 1000  # microseconds to ms
    elif unit == 'ms':
        return val
    elif unit == 's':
        return val * 1000  # seconds to ms
    return val

def parse_prometheus_metrics(file_path):
    """Parse Prometheus metrics file"""
    metrics = {}

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse metric lines
                    if '{' in line:
                        # Metric with labels
                        match = re.match(r'(\w+)\{(.+?)\}\s+(.+)', line)
                        if match:
                            name, labels, value = match.groups()
                            metrics[name] = float(value)
                    else:
                        # Simple metric
                        parts = line.split()
                        if len(parts) >= 2:
                            metrics[parts[0]] = float(parts[1])
    except FileNotFoundError:
        print(f"Warning: {file_path} not found")

    return metrics

def compare_metrics(baseline, current):
    """Compare two metric sets and return differences"""
    diff = {}
    for key, value in current.items():
        if key in baseline:
            diff[key] = {
                'before': baseline[key],
                'after': value,
                'delta': value - baseline[key],
                'delta_percent': ((value - baseline[key]) / baseline[key] * 100) if baseline[key] > 0 else 0
            }
    return diff

def generate_markdown_report(results_dir, output_file):
    """Generate comprehensive markdown report"""

    results_path = Path(results_dir)
    if not results_path.exists():
        print(f"Results directory not found: {results_dir}")
        return

    report = []
    report.append("# ebpf-guard Load Test Report")
    report.append(f"\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Results Directory**: `{results_dir}`")
    report.append("\n---\n")

    # Parse all test results
    tests = []
    for test_file in sorted(results_path.glob('test*.txt')):
        test_name = test_file.stem
        wrk_metrics = parse_wrk_output(test_file)
        tests.append((test_name, wrk_metrics))

    # Performance Summary Table
    report.append("## Performance Summary\n")
    report.append("| Test | RPS | Avg Latency | P99 Latency | Transfer/sec |")
    report.append("|------|-----|-------------|-------------|--------------|")

    for test_name, metrics in tests:
        rps = metrics.get('requests_per_sec', 0)
        avg_lat = metrics.get('avg_latency_ms', 0)
        p99_lat = metrics.get('p99_latency_ms', 0)
        transfer = metrics.get('transfer_per_sec', 'N/A')

        label = test_name.replace('test', '').replace('_', ' ').title()
        report.append(f"| {label} | {rps:.2f} | {avg_lat:.2f}ms | {p99_lat:.2f}ms | {transfer} |")

    report.append("\n### Key Observations\n")
    report.append("- **RPS** = Requests Per Second (higher is better)")
    report.append("- **Latency** = Response time (lower is better)")
    report.append("- **P99 Latency** = 99th percentile (worst 1% of requests)")

    # ebpf-guard Metrics Analysis
    report.append("\n---\n")
    report.append("## ebpf-guard Metrics Analysis\n")

    baseline_metrics = None
    for prom_file in sorted(results_path.glob('*_metrics.prom')):
        test_name = prom_file.stem.replace('_metrics', '')

        if 'baseline' in test_name:
            baseline_metrics = parse_prometheus_metrics(prom_file)
            continue

        current_metrics = parse_prometheus_metrics(prom_file)

        report.append(f"\n### {test_name.replace('_', ' ').title()}\n")

        # Alert metrics
        if 'ebpf_guard_alerts_total' in current_metrics:
            report.append(f"- **Total Alerts**: {current_metrics['ebpf_guard_alerts_total']}")

        # Event metrics
        if 'ebpf_guard_events_total' in current_metrics:
            report.append(f"- **Total Events Processed**: {current_metrics['ebpf_guard_events_total']}")

        # Processing metrics
        if 'ebpf_guard_correlator_processing_duration_seconds' in current_metrics:
            report.append(f"- **Avg Processing Time**: {current_metrics['ebpf_guard_correlator_processing_duration_seconds']:.4f}s")

    # Performance vs Load Analysis
    report.append("\n---\n")
    report.append("## Performance vs Load Analysis\n")

    if len(tests) >= 2:
        baseline_rps = tests[0][1].get('requests_per_sec', 0)
        peak_rps = tests[-1][1].get('requests_per_sec', 0) if len(tests) > 1 else baseline_rps

        report.append(f"\n- **Baseline Performance**: {baseline_rps:.2f} RPS")
        report.append(f"- **Peak Performance**: {peak_rps:.2f} RPS")
        report.append(f"- **Performance Ratio**: {peak_rps/baseline_rps:.2f}x" if baseline_rps > 0 else "-")

        # Detect performance degradation
        if tests[-1][1].get('avg_latency_ms', 0) > tests[0][1].get('avg_latency_ms', 0) * 2:
            report.append("\n⚠️ **WARNING**: Significant latency increase under load!")

    # Recommendations
    report.append("\n---\n")
    report.append("## Recommendations\n")

    recommendations = [
        "Check ebpf-guard CPU usage during peak load",
        "Monitor memory consumption over sustained tests",
        "Review correlation engine processing times",
        "Consider tuning BPF map sizes for higher load scenarios",
        "Evaluate alert rate limiting impact on detection accuracy"
    ]

    for i, rec in enumerate(recommendations, 1):
        report.append(f"{i}. {rec}")

    # Append raw test outputs
    report.append("\n---\n")
    report.append("## Raw Test Outputs\n")

    for test_file in sorted(results_path.glob('test*.txt')):
        report.append(f"\n### {test_file.name}\n")
        report.append("```")
        with open(test_file, 'r') as f:
            report.append(f.read())
        report.append("```")

    # Write report
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write('\n'.join(report))

    print(f"✓ Report generated: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Analyze ebpf-guard load test results')
    parser.add_argument('results_dir', help='Directory containing test results')
    parser.add_argument('-o', '--output', default='load-test-report.md',
                       help='Output report file (default: load-test-report.md)')
    parser.add_argument('--json', action='store_true',
                       help='Also generate JSON report')

    args = parser.parse_args()

    generate_markdown_report(args.results_dir, args.output)

    if args.json:
        # Generate JSON version
        json_output = args.output.replace('.md', '.json')
        # TODO: Implement JSON generation
        print(f"JSON report would be saved to: {json_output}")

if __name__ == '__main__':
    main()
