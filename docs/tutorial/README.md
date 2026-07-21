# Учебное пособие по ebpf-guard

Полное учебное пособие «с нуля» для тех, кто не знаком ни с eBPF, ни с
runtime-security. Главы добавлены последовательно — прогресс отслеживается
в [issue #319](https://github.com/zugolO/ebpf-guard/issues/319). Каждая
глава сверена с реальным кодом (ссылки `file:line`), содержит минимум одну
Mermaid-схему, рабочий пример из репозитория, блок «Дальше почитать» и
глоссарий терминов главы.

## Часть I. Основы (для полного новичка)

1. [Введение: что такое ebpf-guard и зачем он нужен](01-introduction.md) — новичок
   Проблема обнаружения атак в рантайме без модуля ядра, аналогия «камера + охранник», честное сравнение с Falco/Tetragon/Tracee.
2. [Ликбез по eBPF (нулевой уровень)](02-ebpf-basics.md) — новичок
   Что такое eBPF, verifier, JIT; tracepoints/kprobes/uprobes/LSM/XDP; ring buffer, maps, BTF и CO-RE.
3. [Быстрый старт (Getting Started)](03-getting-started.md) — новичок
   Prerequisites, `make generate/build`, запуск через `sudo make run` и без ядра через `--dry-run`, первый алерт за 5 минут.

## Часть II. Как устроен ebpf-guard внутри

4. [Архитектура и поток событий](04-architecture.md) — средний
   Полная схема event flow (kernel → ring buffer → collectors → correlator → exporters), карта пакетов `internal/*`, шаги `main.go`.
5. [BPF-слой (`bpf/*.bpf.c`)](05-bpf-layer.md) — средний
   Разбор каждой BPF-программы (syscall/network/fileaccess/dns/tls/lsm/...), `common.h`, генерация `*_gen.go` через `bpf2go`.
6. [Коллекторы (`internal/collector/`)](06-collectors.md) — средний
   Чтение ring buffer, per-event sampling, `SyntheticCollector`, разбор одного события от C-структуры до `pkg/types.Event`.
7. [Движок корреляции и DSL правил (`internal/correlator/`)](07-correlation-engine.md) — средний
   16+-шардовый PID-буфер, SHA-256 fingerprinting, rate limiting, полный справочник операторов условий, `condition_group`.

## Часть III. Обнаружение: правила и поведенческий анализ

8. [Руководство по написанию правил + встроенные наборы](08-writing-rules.md) — средний
   Анатомия правила, hot-reload, обзор встроенных наборов `rules/`, MITRE ATT&CK покрытие, «напиши своё правило» end-to-end.
9. [Профайлер и аномалии (`internal/profiler/`)](09-profiler-anomalies.md) — средний
   EWMA baseline learning, `SequenceProfiler` (cosine distance), `LineageTracker` (цепочки атак).
10. [Policy engine (`internal/policy/`, Rego/OPA)](10-policy-engine.md) — средний
    Post-filter policy на Rego, обогащение MITRE, где живут `rules/rego/`.
11. [Автообучение и дрейф (`internal/autolearn/`, `internal/drift/`, `internal/feedback/`)](11-autolearn-drift.md) — средний
    Allowlist-mode, drift detection, обратная связь через feedback API.

## Часть IV. Реакция и вывод

12. [Enforcer — активная реакция (`internal/enforcer/`)](12-enforcer.md) — средний
    Действия `alert/block/kill/throttle/drop`, backends `log/nftables/lsm`, `dry_run`, схема принятия решения о блокировке.
13. [Экспортёры и интеграции (`internal/exporter/`)](13-exporters.md) — средний
    Prometheus `/metrics`, cardinality guard, Alertmanager по mTLS, нотификации Slack/Teams/webhook, Falco-совместимый вывод, HTTP API.
14. [Хранилище алертов (`internal/store/`)](14-alert-store.md) — средний
    Три backend'а — memory / SQLite / OpenSearch — и когда какой выбирать.

## Часть V. Продвинутые фичи

15. [Продвинутая защита и наблюдение](15-advanced-protection.md) — продвинутый
    Self-protection, integrity scan, watchdog + memory pressure auto-tuning, canary, gossip-кластеризация, OSINT, hidden process.
16. [WASM-плагины (`internal/wasm/`)](16-wasm-plugins.md) — продвинутый
    Модель расширения на wazero/WASI, как написать плагин, `ebpf-guard plugins`.
17. [TLS/HTTP inspection и DNS-мониторинг](17-tls-dns-monitoring.md) — продвинутый
    Uprobes на OpenSSL, ClientHello/JA3, DNS entropy и DGA-детект.

## Часть VI. Эксплуатация

18. [Полный справочник CLI](18-cli-reference.md) — средний
    Все подкоманды (`alerts`, `status`, `rules`, `explain`, `learn`, `migrate`, `wizard`, ...) с флагами и примерами вывода.
19. [Полный справочник конфигурации (`internal/config/`)](19-config-reference.md) — средний
    Разбор всех секций конфига и закомментированный образец полного `config.yaml`.
20. [Развёртывание в Kubernetes](20-kubernetes-deployment.md) — средний
    DaemonSet, Helm-чарт, RBAC, ConfigMap, ServiceMonitor, PrometheusRule, hardening (AppArmor/seccomp, `values-secure.yaml`).
21. [Миграция с Falco (`internal/migration/`)](21-falco-migration.md) — средний
    Импорт Falco-правил, `ebpf-guard migrate`, что поддерживается и что нет.
22. [Производительность, тюнинг и траблшутинг](22-performance-tuning.md) — продвинутый
    Hardware-profiles, PGO, бенчмарки, lock ordering, типовые проблемы (нет BTF, старое ядро, verifier reject, drop событий).
23. [Безопасность самого агента и модель угроз](23-agent-security.md) — продвинутый
    Модель угроз из `SECURITY.md`, привилегии/capabilities, mTLS, bearer-токен, self-protection.

## Часть VII. Финализация

24. [Глоссарий терминов](24-glossary.md) — справочный
    Сводный глоссарий по всему пособию: eBPF, BTF, CO-RE, tracepoint, uprobe, LSM, EWMA, JA3, MITRE ATT&CK и другие термины из всех глав.
25. [Индекс внешних ресурсов](25-external-resources.md) — справочный
    Единый список всех внешних статей/докладов/документации из блоков «Дальше почитать», сгруппированный по темам.
26. **Оглавление (этот файл)** — навигация по всем главам с кратким описанием и оценкой уровня.

Все 26 пунктов issue #319 закрыты.
