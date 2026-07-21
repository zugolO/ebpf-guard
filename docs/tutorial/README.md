# Учебное пособие по ebpf-guard

Полное учебное пособие «с нуля» для тех, кто не знаком ни с eBPF, ни с
runtime-security. Главы добавляются последовательно — прогресс отслеживается
в [issue #319](https://github.com/zugolO/ebpf-guard/issues/319).

## Часть I. Основы (для полного новичка)

1. [Введение: что такое ebpf-guard и зачем он нужен](01-introduction.md) — новичок
2. [Ликбез по eBPF (нулевой уровень)](02-ebpf-basics.md) — новичок
3. [Быстрый старт (Getting Started)](03-getting-started.md) — новичок

## Часть II. Как устроен ebpf-guard внутри

4. [Архитектура и поток событий](04-architecture.md) — средний
5. [BPF-слой (`bpf/*.bpf.c`)](05-bpf-layer.md) — средний
6. [Коллекторы (`internal/collector/`)](06-collectors.md) — средний
7. [Движок корреляции и DSL правил (`internal/correlator/`)](07-correlation-engine.md) — средний

## Часть III. Обнаружение: правила и поведенческий анализ

8. [Руководство по написанию правил + встроенные наборы](08-writing-rules.md) — средний
9. [Профайлер и аномалии (`internal/profiler/`)](09-profiler-anomalies.md) — средний
10. [Policy engine (`internal/policy/`, Rego/OPA)](10-policy-engine.md) — средний
11. [Автообучение и дрейф (`internal/autolearn/`, `internal/drift/`, `internal/feedback/`)](11-autolearn-drift.md) — средний

Остальные главы появятся по мере закрытия соответствующих пунктов issue #319.
