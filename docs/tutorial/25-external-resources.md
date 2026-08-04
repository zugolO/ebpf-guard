# Глава 25. Индекс внешних ресурсов

> Уровень: **справочный**. Единый список всех внешних ссылок из блоков
> «Дальше почитать» глав 1–23, сгруппированный по темам — так проще найти
> первоисточник, не пролистывая всё пособие заново.

## eBPF: основы, ядро, инструменты сборки

- [ebpf.io — What is eBPF?](https://ebpf.io/what-is-ebpf/) — официальный обзорный сайт проекта eBPF. (Глава 2)
- [Liz Rice, "Learning eBPF" (O'Reilly / Isovalent)](https://isovalent.com/books/learning-ebpf/) — лучшая книга-введение в eBPF для тех, кто раньше не касался ядра. (Глава 1)
- [Brendan Gregg, "BPF Performance Tools"](https://www.brendangregg.com/bpf-performance-tools-book.html) — классика по трейсингу через eBPF/BCC. (Глава 2)
- [Andrii Nakryiko, "BPF CO-RE (Compile Once – Run Everywhere)"](https://nakryiko.com/posts/bpf-portability-and-co-re/) — лучшее объяснение CO-RE от одного из мейнтейнеров libbpf. (Глава 2)
- [Kernel documentation: BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html) — официальная документация ядра по BTF. (Глава 2)
- [Kernel docs: tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html) — формат и стабильность tracepoint-интерфейса. (Главы 2, 5)
- [Kernel docs: LSM eBPF](https://docs.kernel.org/bpf/prog_lsm.html) — официальная документация по `lsm/*` hook-ам. (Глава 5)
- [Kernel docs: BPF iterators](https://docs.kernel.org/bpf/bpf_iterators.html) — механизм `bpf iter/task`, на котором строится hidden-process detection. (Глава 15)
- [libbpf documentation](https://libbpf.readthedocs.io/) — библиотека, на API которой построена загрузка BPF-объектов. (Глава 5)
- [cilium/ebpf: bpf2go documentation](https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go) — генератор Go-биндингов, используемый в `make generate`. (Главы 2, 5)

## Ландшафт runtime security (аналоги и сравнение)

- [CNCF blog — Cloud Native Runtime Security](https://www.cncf.io/blog/) — обзорные материалы CNCF о рантайм-безопасности контейнеров. (Глава 1)
- [Falco documentation](https://falco.org/docs/) — для сравнения архитектуры и языка правил. (Глава 1)
- [Falco rules syntax](https://falco.org/docs/rules/) — официальная документация условий Falco, целевая для конвертера миграции. (Глава 21)
- [Falco output fields](https://falco.org/docs/reference/rules/output/) — формат, с которым совместим `falco_output.go`. (Глава 13)
- [Tetragon documentation](https://tetragon.io/docs/) — пример eBPF-based синхронного enforcement. (Глава 1)
- [Tracee documentation](https://aquasecurity.github.io/tracee/latest/) — пример forensic-ориентированного eBPF-трейсинга. (Глава 1)
- [Sigma project](https://github.com/SigmaHQ/sigma) — формат, из которого импортированы правила `sigma-linux.yaml`. (Глава 8)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/) — матрица техник, на которую опирается `tags`/`mitre` в правилах. (Глава 8)
- [MITRE ATT&CK: Rootkit (T1014)](https://attack.mitre.org/techniques/T1014/) — техника, которую покрывает связка hidden-process + integrity scan. (Глава 15)

## Обнаружение и поведенческий анализ (математика)

- [Exponential smoothing (Wikipedia)](https://en.wikipedia.org/wiki/Exponential_smoothing) — математика EWMA, лежащей в основе профайлера. (Глава 9)
- [Cosine similarity (Wikipedia)](https://en.wikipedia.org/wiki/Cosine_similarity) — база для `cosineDistance` в `SequenceProfiler`. (Глава 9)
- [Shannon entropy (Wikipedia)](https://en.wikipedia.org/wiki/Entropy_(information_theory)) — математическая база энтропийного детекта DGA-доменов. (Глава 17)
- [DGA Detection Techniques (Splunk)](https://www.splunk.com/en_us/blog/security/deep-learning-domain-generation-algorithms-dga-detection.html) — обзор методов детекта DGA. (Глава 17)
- [DNS Tunneling Detection (Akamai)](https://www.akamai.com/blog/security/dns-tunneling-detection) — обзорная статья по DNS-туннелированию. (Глава 17)

## Policy engine (OPA/Rego)

- [Rego Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/) — официальная документация языка. (Глава 10)
- [Open Policy Agent — Go integration (`rego` package)](https://www.openpolicyagent.org/docs/latest/integration/#integrating-with-the-go-api) — API, который использует `internal/policy`. (Глава 10)

## Автообучение и allowlist-режим

- [OCI seccomp profile format](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp) — формат, в который экспортирует `autolearn`. (Глава 11)

## Enforcement (блокировка, kill, throttle)

- [google/nftables](https://github.com/google/nftables) — Go-библиотека для netlink-взаимодействия с nftables, используемая напрямую (не через `nft`-бинарник). (Глава 12)
- [pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html) — man-страница, объясняющая, почему `pidfd` устраняет гонку за PID. (Глава 12)
- [cgroup v2: CPU controller](https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu-interface-files) — семантика `cpu.max`, на которой построен throttle. (Глава 12)
- [Linux LD_PRELOAD hijacking techniques (ld.so man-page)](https://man7.org/linux/man-pages/man8/ld.so.8.html) — раздел про `LD_PRELOAD`. (Глава 15)

## Экспортёры и наблюдаемость

- [Prometheus: cardinality](https://prometheus.io/docs/practices/instrumentation/#do-not-overuse-labels) — почему кардинальность меток нужно ограничивать. (Глава 13)
- [Alertmanager webhook receiver](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config) — протокол, которому следует `alertmanager.go`. (Глава 13)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) — механика preflight-запросов, на которой построен `corsMiddleware`. (Глава 13)

## Хранилище алертов

- [SQLite WAL mode](https://www.sqlite.org/wal.html) — официальная документация по режиму Write-Ahead Logging. (Глава 14)
- [OpenSearch Bulk API](https://opensearch.org/docs/latest/api-reference/document-apis/bulk/) — протокол, которым пользуется `StoreBatch`. (Глава 14)
- [Index-per-time-period pattern](https://opensearch.org/docs/latest/im-plugin/index-rollups/index/) — почему time-series индексы часто бьют по дням/месяцам. (Глава 14)

## WASM-плагины

- [wazero](https://wazero.io/) — WebAssembly-рантайм на чистом Go (без cgo), используемый как хост. (Глава 16)
- [WASI (WebAssembly System Interface)](https://wasi.dev/) — таргет компиляции для плагинов. (Глава 16)
- [TinyGo](https://tinygo.org/) — компилятор Go в WASM/WASI с компактным рантаймом. (Глава 16)

## TLS/HTTP inspection и DNS

- [JA3 (Salesforce)](https://github.com/salesforce/ja3) — оригинальная спецификация TLS-фингерпринтинга. (Глава 17)
- [JA4 (FoxIO)](https://github.com/FoxIO-LLC/ja4) — обновлённая спецификация фингерпринтинга. (Глава 17)
- [OpenSSL SSL_write/SSL_read](https://www.openssl.org/docs/man3.0/man3/SSL_write.html) — функции, на которые вешается TLS-uprobe. (Глава 17)

## CLI и конфигурация

- [Cobra (spf13/cobra) docs](https://github.com/spf13/cobra) — библиотека, на которой построен весь CLI. (Глава 18)
- [spf13/viper](https://github.com/spf13/viper) — библиотека загрузки конфигурации. (Глава 19)
- [fsnotify/fsnotify](https://github.com/fsnotify/fsnotify) — библиотека отслеживания изменений файлов, на которой построен hot-reload. (Глава 19)

## Kubernetes и деплой

- [Kubernetes DaemonSet docs](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/) — справочная документация примитива, на котором развёрнут ebpf-guard. (Глава 20)
- [Prometheus Operator](https://prometheus-operator.dev/) — используемые CRD (`ServiceMonitor`, `PrometheusRule`). (Глава 20)

## Производительность

- [Go PGO (Profile-Guided Optimization)](https://go.dev/doc/pgo) — официальная документация механизма, на котором строится `-pgo=auto`. (Глава 22)

## Безопасность агента

- [OWASP: Timing Attacks](https://owasp.org/www-community/attacks/Timing_attack) — почему нужен `subtle.ConstantTimeCompare`. (Глава 23)
- [Linux capabilities(7) man page](https://man7.org/linux/man-pages/man7/capabilities.7.html) — справочник по `CAP_BPF`/`CAP_SYS_ADMIN`/и т.д. (Глава 23)

## Дальше почитать

- [Глава 24. Глоссарий терминов](24-glossary.md) — если непонятен термин, а не первоисточник.
- Разделы «Дальше почитать» внутри каждой главы также содержат ссылки на **внутренние** файлы репозитория (код, `docs/*.md`) — они намеренно не продублированы здесь, поскольку не являются внешними ресурсами.

---

**Назад:** [Глава 24. Глоссарий терминов](24-glossary.md) · **Далее:** [README — оглавление пособия](README.md)
