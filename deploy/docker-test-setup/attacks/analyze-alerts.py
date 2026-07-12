#!/usr/bin/env python3
"""
Анализатор алертов ebpf-guard для Security Testing
Анализирует результаты атак и генерирует детальные отчеты
"""

import json
import sys
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any
import argparse
import subprocess
import os

class AlertsAnalyzer:
    """Анализатор алертов ebpf-guard"""

    def __init__(self, api_url: str = None):
        self.api_url = api_url or os.environ.get("EBPF_GUARD_API", "http://localhost:19090")
        self.alerts = []
        self.baseline_alerts = []
        self.attack_alerts = []

    def fetch_alerts(self) -> List[Dict]:
        """Получение алертов из ebpf-guard API"""
        try:
            result = subprocess.run(
                ["curl", "-s", f"{self.api_url}/alerts"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self.alerts = json.loads(result.stdout)
                return self.alerts
            return []
        except Exception as e:
            print(f"Error fetching alerts: {e}")
            return []

    def load_baseline(self, file_path: str) -> List[Dict]:
        """Загрузка baseline алертов из файла"""
        try:
            with open(file_path, 'r') as f:
                self.baseline_alerts = json.load(f)
                return self.baseline_alerts
        except Exception as e:
            print(f"Error loading baseline: {e}")
            return []

    def calculate_delta(self) -> List[Dict]:
        """Вычисление разницы между текущими и baseline алертами"""
        if not self.baseline_alerts:
            return self.alerts

        # Упрощенный подход - возвращаем alerts как attack alerts
        # В реальности нужно более умное сравнение
        self.attack_alerts = self.alerts[len(self.baseline_alerts):]
        return self.attack_alerts

    def analyze_by_rule(self) -> Dict[str, int]:
        """Анализ по правилам"""
        counter = Counter()
        for alert in self.alerts:
            rule_id = alert.get('rule_id', 'unknown')
            counter[rule_id] += 1
        return dict(counter)

    def analyze_by_severity(self) -> Dict[str, int]:
        """Анализ по严重程度"""
        counter = Counter()
        for alert in self.alerts:
            severity = alert.get('severity', 'unknown')
            counter[severity] += 1
        return dict(counter)

    def analyze_by_event_type(self) -> Dict[str, int]:
        """Анализ по типам событий"""
        counter = Counter()
        for alert in self.alerts:
            event_type = alert.get('event_type', 'unknown')
            counter[event_type] += 1
        return dict(counter)

    def analyze_by_source_ip(self) -> Dict[str, int]:
        """Анализ по source IP"""
        counter = Counter()
        for alert in self.alerts:
            source = alert.get('source_ip', 'unknown')
            counter[source] += 1
        return dict(counter)

    def analyze_temporal_pattern(self) -> Dict[str, List[int]]:
        """Временной анализ (по минутам)"""
        time_series = defaultdict(list)
        for alert in self.alerts:
            timestamp = alert.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    minute_key = dt.strftime('%Y-%m-%d %H:%M')
                    time_series[minute_key].append(alert)
                except:
                    pass
        return dict(time_series)

    def detect_false_positives(self) -> Dict[str, Any]:
        """Обнаружение потенциальных false positives"""
        fp_candidates = {
            'repeating_same_rule': [],
            'low_severity_high_volume': [],
            'expected_system_events': []
        }

        # Правила с очень высокой частотой (возможно FP)
        rule_counts = self.analyze_by_rule()
        total_alerts = len(self.alerts)

        for rule, count in rule_counts.items():
            if count > total_alerts * 0.5:  # Если > 50% всех алертов
                fp_candidates['low_severity_high_volume'].append({
                    'rule': rule,
                    'count': count,
                    'percentage': (count / total_alerts) * 100
                })

        return fp_candidates

    def generate_summary(self) -> Dict[str, Any]:
        """Генерация сводки"""
        return {
            'total_alerts': len(self.alerts),
            'unique_rules': len(self.analyze_by_rule()),
            'by_severity': self.analyze_by_severity(),
            'by_event_type': self.analyze_by_event_type(),
            'top_rules': self._get_top_n(self.analyze_by_rule(), 10),
            'top_sources': self._get_top_n(self.analyze_by_source_ip(), 5)
        }

    def _get_top_n(self, data: Dict, n: int) -> List[tuple]:
        """Получение top N элементов"""
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:n]

    def print_report(self, detailed: bool = False):
        """Вывод отчета"""
        summary = self.generate_summary()

        print("=" * 60)
        print("ebpf-guard ALERTS ANALYSIS REPORT")
        print("=" * 60)
        print(f"Generated: {datetime.now().isoformat()}")
        print(f"Total Alerts: {summary['total_alerts']}")
        print(f"Unique Rules Triggered: {summary['unique_rules']}")
        print()

        # By Severity
        print("Alerts by Severity:")
        for severity, count in sorted(summary['by_severity'].items()):
            print(f"  {severity}: {count}")
        print()

        # Top Rules
        print("Top Triggered Rules:")
        for rule, count in summary['top_rules']:
            print(f"  {rule}: {count} times")
        print()

        # By Event Type
        if detailed:
            print("By Event Type:")
            for event_type, count in sorted(summary['by_event_type'].items()):
                print(f"  {event_type}: {count}")
            print()

        # False Positive Candidates
        if detailed:
            fp = self.detect_false_positives()
            print("Potential False Positives:")
            if fp['low_severity_high_volume']:
                print("  High-volume rules (>50% of alerts):")
                for item in fp['low_severity_high_volume']:
                    print(f"    {item['rule']}: {item['count']} ({item['percentage']:.1f}%)")
            print()

    def export_json(self, file_path: str):
        """Экспорт в JSON"""
        summary = self.generate_summary()
        summary['generated_at'] = datetime.now().isoformat()
        summary['api_url'] = self.api_url

        with open(file_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"Report exported to {file_path}")

    def compare_metrics(self, baseline_file: str, final_file: str) -> Dict[str, Any]:
        """Сравнение метрик до и после"""
        try:
            with open(baseline_file, 'r') as f:
                baseline = f.read()
            with open(final_file, 'r') as f:
                final = f.read()

            # Простое сравнение строк (в реальности нужен парсинг Prometheus метрик)
            baseline_alerts = self._extract_metric(baseline, 'alerts_total')
            final_alerts = self._extract_metric(final, 'alerts_total')

            baseline_events = self._extract_metric(baseline, 'events_total')
            final_events = self._extract_metric(final, 'events_total')

            return {
                'alerts': {
                    'before': baseline_alerts,
                    'after': final_alerts,
                    'delta': final_alerts - baseline_alerts
                },
                'events': {
                    'before': baseline_events,
                    'after': final_events,
                    'delta': final_events - baseline_events
                }
            }
        except Exception as e:
            print(f"Error comparing metrics: {e}")
            return {}

    def _extract_metric(self, content: str, metric_name: str) -> int:
        """Извлечение значения метрики из Prometheus формата"""
        for line in content.split('\n'):
            if line.startswith(metric_name + ' ') or line.startswith(metric_name + '{'):
                parts = line.split(' ')
                if len(parts) >= 2:
                    try:
                        return int(parts[-1])
                    except ValueError:
                        continue
        return 0


def main():
    parser = argparse.ArgumentParser(description='Analyze ebpf-guard alerts')
    parser.add_argument('--api', default=os.environ.get('EBPF_GUARD_API', 'http://localhost:19090'),
                       help='ebpf-guard API URL (or set EBPF_GUARD_API env var)')
    parser.add_argument('--baseline', help='Baseline alerts JSON file')
    parser.add_argument('--compare-baseline', help='Baseline metrics file')
    parser.add_argument('--compare-final', help='Final metrics file')
    parser.add_argument('--export', help='Export report to JSON file')
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed analysis')

    args = parser.parse_args()

    analyzer = AlertsAnalyzer(api_url=args.api)

    # Получение алертов
    alerts = analyzer.fetch_alerts()
    print(f"Fetched {len(alerts)} alerts from ebpf-guard")

    # Загрузка baseline если указан
    if args.baseline:
        analyzer.load_baseline(args.baseline)
        analyzer.calculate_delta()
        print(f"Loaded baseline with {len(analyzer.baseline_alerts)} alerts")
        print(f"Attack alerts: {len(analyzer.attack_alerts)}")

    # Вывод отчета
    analyzer.print_report(detailed=args.detailed)

    # Сравнение метрик если указаны файлы
    if args.compare_baseline and args.compare_final:
        print("\n" + "=" * 60)
        print("METRICS COMPARISON")
        print("=" * 60)
        comparison = analyzer.compare_metrics(args.compare_baseline, args.compare_final)
        if comparison:
            print("\nAlerts:")
            print(f"  Before: {comparison['alerts']['before']}")
            print(f"  After:  {comparison['alerts']['after']}")
            print(f"  Delta:  {comparison['alerts']['delta']}")

            print("\nEvents:")
            print(f"  Before: {comparison['events']['before']}")
            print(f"  After:  {comparison['events']['after']}")
            print(f"  Delta:  {comparison['events']['delta']}")

    # Экспорт
    if args.export:
        analyzer.export_json(args.export)


if __name__ == '__main__':
    main()
