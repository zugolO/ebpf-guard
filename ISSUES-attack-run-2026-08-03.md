# ebpf-guard — задачи по итогам прогона атак (2026-08-03)

Основано на анализе `server-logs/` (SQLmap/brute-force/SSRF/LDAP-CSRF против Juice Shop,
~7 мин, 11:25–11:32 UTC) и чтении кода. Каждая задача содержит доказательство из логов
и/или ссылку на код.

Сводка первопричин:
1. **Нет корреляции в «атаку».** Инциденты группируются только по `(PID, namespace)` и
   существуют лишь как пассивный query-API — нет цепочки между процессами и нет вердикта
   «это атака» вместо «это N системных вызовов».
2. **Learning не завершается и не сохраняется.** `learning_period=3600s` при тесте 7 минут +
   код persistence (`SaveState`/`LoadState`) существует, но **нигде не вызывается** из `main.go`
   → база обучения теряется при каждом рестарте.
3. **UI отдаёт 503 под нагрузкой.** Health-gating завязан на здоровье коллекторов, а CPU-watchdog
   под атакой режет сэмплинг; HTTP-сервер делит CPU с event-loop без изоляции, `ReadTimeout=5s`.
4. **Отчётный скрипт и сами атаки врут** (фантомные 8063 из суммирования counter'ов; половина
   атак слала 0 запросов; sqlmap 1.6.4 падал).

---

## P0-1 — Инциденты не коррелируют цепочку атаки между процессами

**Тип:** bug / feature · **Приоритет:** P0 · **Метки:** `correlation`, `detection-quality`

**Проблема.** `IncidentTracker` группирует алерты по ключу `(pid, namespace)`
([incident.go:18-21](internal/correlator/incident.go#L18-L21)), поэтому атака вида
`bash → curl → xmrig` (разные PID, родитель-потомок) попадает в разные инциденты и никогда
не сшивается в одну цепочку. `LineageTracker` знает предков
([engine.go:151-154](internal/correlator/engine.go#L151-L154),
[engine.go:1329](internal/correlator/engine.go#L1329)), но используется только для
**обогащения одиночного алерта**, а не как ключ группировки инцидента.

**Доказательство из прогона.** Топ-алерты (`container_escape_proc_write`, `sigma_memory_proc_dump`,
`fim_library_replaced`, `webshell_network_connection_web_proc`, `exfil_db_nonstandard_port_connect`)
летели как независимые события; ни один per-attack блок в `attacks-run.log` не показал
«новых алертов» > 0, потому что нет агрегации в атаку.

**Что сделать.**
- Ввести опциональный ключ группировки по корню process-tree (root ancestor PID из
  `LineageTracker`), а не только по конкретному PID.
- Добавить в `types.Incident` поля цепочки: `ProcessChain []string`, `RootPID uint32`.
- Cross-process окно + слияние инцидентов, когда потомок появляется в пределах окна родителя.

**Критерий приёмки.** Сценарий `parent-shell → child-download → child-exec` из одного
process-tree даёт **один** инцидент со списком PID цепочки. Есть unit-тест на слияние.

---

## P0-2 — Нет вердикта «атака»: инцидент не повышает серьёзность и не скорится

**Тип:** feature · **Приоритет:** P0 · **Метки:** `correlation`, `detection-quality`

**Проблема.** `IncidentTracker.Add` только накапливает `AlertIDs`/`RuleIDs` и берёт
`max(severity)` ([incident.go:79-94](internal/correlator/incident.go#L79-L94)). Нет логики
«N связанных слабых сигналов = 1 подтверждённая атака»: инцидент из 10 `warning` остаётся
`warning`. Инциденты доступны только через `GET /api/v1/incidents`
([api.go:44-45](internal/exporter/api.go#L44-L45)) — не влияют на алертинг, метрики, нотификации.

**Что сделать.**
- Ввести scoring инцидента: взвешенная сумма по числу уникальных правил, разнообразию
  MITRE-тактик (killchain-прогресс), плотности во времени.
- При превышении порога — эмитить синтетический алерт `incident_confirmed_attack`
  (critical) и слать его в exporter/нотификации.
- Экспонировать метрику `ebpf_guard_incidents_total{verdict="attack|suspicious"}`.

**Критерий приёмки.** 5+ связанных правил из ≥2 разных MITRE-тактик в окне → один
critical-алерт `incident_confirmed_attack`, видимый в нотификациях и метриках.

---

## P0-3 — Persistence состояния profiler'а не вызывается → learning теряется при рестарте

**Тип:** bug · **Приоритет:** P0 · **Метки:** `profiler`, `learning`

**Проблема.** `Profiler.SaveState`/`LoadState`
([profiler.go:319-341](internal/profiler/profiler.go#L319-L341)) и
`AnomalyDetector.SaveState`/`LoadState`
([persistence.go:264-362](internal/profiler/persistence.go#L264-L362)) реализованы, конфиг
`StatePersistenceConfig{Enabled, Path}` существует
([config.go:1053-1063](internal/config/config.go#L1053-L1063)) — но `grep` по `cmd/`
показывает, что **ни `SaveState`, ни `LoadState` не вызываются нигде из `main.go`**.
Это мёртвая фича: `BaselineLearner.startTime` каждый старт выставляется в `time.Now()`
([baseline.go:88-94](internal/profiler/baseline.go#L88-L94)), поэтому learning-таймер
всегда стартует с нуля.

**Последствие.** Любой рестарт агента (в т.ч. под CPU-нагрузкой/OOM) сбрасывает обучение.
В Kubernetes DaemonSet рестарты обычны → база не накапливается никогда.

**Что сделать.**
- В `main.go`: если `Profiler.StatePersistence.Enabled` — `LoadState(path)` на старте и
  `SaveState(path)` в graceful-shutdown (defer + на SIGTERM).
- Периодический автосейв (тикер) чтобы пережить `kill -9`.
- Тест: сохранить → создать новый детектор → загрузить → `IsLearningComplete()` сохраняется.

---

## P1-4 — learning_period 3600s непрозрачен: нет видимости прогресса и «мало обучения»

**Тип:** enhancement · **Приоритет:** P1 · **Метки:** `profiler`, `observability`

**Проблема.** `learning_period: 3600` в [config/config.yaml:88](config/config.yaml#L88).
Тестовый прогон длился 7 минут → learning **никогда не мог завершиться by design**, но
FINAL-REPORT об этом не сообщает, а пишет размытое «Детектировано мало аномалий (0) →
проверьте profiler». Прогресс обучения (`LearningProgress`, `TimeRemaining`
[anomaly.go:227-234](internal/profiler/anomaly.go#L227-L234)) не экспонирован в метрики/логи.

**Что сделать.**
- Метрики: `ebpf_guard_learning_progress` (0..1), `ebpf_guard_learning_complete` (0/1),
  `ebpf_guard_learning_seconds_remaining`.
- Периодический INFO-лог `learning: 42% (~2050s remaining, 8123 samples)`.
- В `/health` и `status`-subcommand отдавать фазу обучения.
- Явно предупреждать при `learning_period > длительности наблюдения`.

**Критерий приёмки.** Прогресс обучения виден в `/metrics` и в CLI `ebpf-guard status`.

---

## P1-5 — UI/API отдаёт 503 под нагрузкой (health завязан на CPU-watchdog + деление CPU)

**Тип:** bug · **Приоритет:** P1 · **Метки:** `api`, `performance`, `availability`

**Проблема.** Под атакой CPU-watchdog циклично режет сэмплинг (в journal-логе:
`cpu pressure: reducing file sampling` при 46–72% CPU, вплоть до
`escalating — reducing syscall and network sampling`,
[ebpf-guard-journal-attacks.log](server-logs/ebpf-guard-journal-attacks.log)). При этом:
- `/health` возвращает 503, если **любой** коллектор `Healthy=false`
  ([server.go:486-491](internal/exporter/server.go#L486-L491),
  [server.go:500-504](internal/exporter/server.go#L500-L504)) — деградация сэмплинга легко
  переводит коллектор в unhealthy.
- HTTP-сервер делит `GOMAXPROCS` с горячим event-loop без изоляции; при голодании по CPU
  `ReadTimeout: 5s` / `WriteTimeout: 10s`
  ([server.go:189-190](internal/exporter/server.go#L189-L190)) приводят к таймаутам → 503.

**Что сделать (по нарастанию).**
1. Развести liveness/readiness/health: деградация сэмплинга (throttling) — это **не**
   «unhealthy»; ввести состояние `degraded` (200 + флаг), 503 только при реальном отказе
   коллектора/стора.
2. Выделить CPU-бюджет для HTTP: отдельный worker-pool/`GOMAXPROCS`-резерв или вынести
   `/metrics` и UI на приоритетную горутину; рассмотреть `runtime.LockOSThread` для
   HTTP-listener или отдельный маленький пул.
3. Backpressure на ingest вместо голодания HTTP: при CPU-давлении сбрасывать события
   раньше (что watchdog уже частично делает), но не блокировать API-горутины.

**Критерий приёмки.** При синтетической 90% CPU-нагрузке `/metrics` и UI отвечают < 1s и
не отдают 503, пока коллекторы фактически работают (пусть и с урезанным сэмплингом).

---

## P1-6 — Baseline «загрязнён» хостовым шумом: 113k FP до начала атак

**Тип:** bug / detection-quality · **Приоритет:** P1 · **Метки:** `rules`, `false-positive`

**Проблема.** На старте прогона уже было **113366 алертов**
(`attacks-run.log`: «Начальное количество алертов: 113366»). Топ — это активность самой
хост-ОС, не атаки: `sigma_memory_proc_dump` с `"comm":"systemd-journal"` (штатное чтение
`/proc/*/mem`), `fim_library_replaced`/`supply_chain_build_tool_rootwrite`/
`drift_new_library_in_system_dir` (менеджеры пакетов пишут в системные каталоги). Эти FP
хоронят любой реальный сигнал от атак.

**Что сделать.**
- Добавить exception'ы/allowlist для системных демонов (`systemd-journal`, `systemd`,
  `apt`/`dpkg`/`dnf`, `containerd`, `dockerd`) в затронутых правилах.
- Пересмотреть `sigma_memory_proc_dump`, `fim_library_replaced`,
  `supply_chain_build_tool_rootwrite` на предмет контекстных условий (кто родитель, путь).
- Документировать «tuning для baseline» перед первым запуском на хосте.

**Критерий приёмки.** На idle-хосте (без атак) за 10 мин — близко к нулю critical-алертов.

---

## P2-7 — Отчётный скрипт: фантомные метрики из суммирования counter'ов

**Тип:** bug (tooling) · **Приоритет:** P2 · **Метки:** `tooling`, `testing`

**Проблема.** `FINAL-REPORT.txt` одновременно утверждает «Alerts Total: 0 → 0, новых 0» и
«container_escape_proc_write: 8063». Реальные значения counter'ов в `=== METRICS ANALYSIS ===`
внутри `attacks-run.log` — десятки-сотни (напр. `appexploit_lfi_passwd_access … 57`).
Числа 8063/7038 получены суммированием абсолютных значений Prometheus-counter (`..._total`)
по всем снапшотам за прогон вместо взятия дельты `after - before` по конкретной label-серии.
`FINAL-REPORT.json` при этом невалиден — пустые значения (`"before": ,`).

**Что сделать.**
- Считать дельту per-series `after - before` по `ebpf_guard_alerts_total{rule_id=...,severity=...}`.
- Чинить генерацию JSON (пустые поля ломают парсинг).
- Убрать двойной учёт: «топ алертов» и «новых 0» не должны противоречить друг другу.

**Критерий приёмки.** Отчёт показывает согласованную дельту; JSON валиден.

---

## P2-8 — Скрипты атак не генерируют трафик / sqlmap падает

**Тип:** bug (tooling) · **Приоритет:** P2 · **Метки:** `tooling`, `testing`, `attacks`

**Проблема.** В `REQUEST STATISTICS` половина атак отправила **0 запросов**:
`distributed: 0`, `high_frequency: 0`, `password_spraying: 0`. sqlmap 1.6.4 падал:
`error: no such option --dump-table`, `your sqlmap version is outdated`. FINAL-REPORT:
sqlmap/ssrf/ldap-csrf — «Попыток атак: 0» (создавались только файлы результатов).
Без реального трафика к цели тест детекта бессмыслен.

**Что сделать.**
- Обновить sqlmap, убрать несуществующие флаги.
- Починить генераторы `distributed`/`high_frequency`/`password_spraying` (0 запросов = баг
  парсинга ответа/цикла).
- Добавить проверку «фактически отправлено N>0 запросов» как gate перед анализом метрик.

**Критерий приёмки.** Каждая атака в статистике показывает N>0 запросов; sqlmap отрабатывает
без ошибок опций.

---

## P3-9 — Веб-атаки (SQLi/brute-force) не видны на голых kernel-событиях [DONE]

**Тип:** enhancement · **Приоритет:** P3 · **Метки:** `detection-coverage`, `collectors`

**Статус.** Сделано:
- Документация границы покрытия: [docs/l7-detection-coverage.md](docs/l7-detection-coverage.md)
  (кросс-ссылка из [docs/tls-inspection.md](docs/tls-inspection.md)).
- Поведенческий сигнал по частоте соединений: `ConnFrequencyTracker`
  ([internal/correlator/conn_frequency.go](internal/correlator/conn_frequency.go)) считает
  попытки соединения на `(pid, dport)` в скользящем окне 60s, экспонирован в rule engine как
  вычисляемое поле `conn_rate_1m`. Правило `net_high_frequency_connections`
  ([rules/network-anomaly.yaml](rules/network-anomaly.yaml)) алертит при >30 соединений/60s
  на один порт с одного PID (`mitre:T1110`, warning). Тесты:
  [internal/correlator/conn_frequency_test.go](internal/correlator/conn_frequency_test.go).

**Проблема.** SQLi и brute-force — L7-события внутри процесса Node.js. eBPF-guard видит
syscalls/network/file, а не HTTP-payload, поэтому саму инъекцию не детектирует — только
косвенные следствия (чтение `/etc/passwd`, исходящие соединения), которых в Juice Shop
эти атаки не оставили. Отсюда «новых алертов: 0» для SQLmap и brute-force.

**Что сделать.**
- Документировать границу: что именно L7 guard может/не может ловить без TLS-uprobe.
- Рассмотреть корреляцию с L7-логами приложения или расширение TLS-uprobe парсинга.
- Для brute-force: детектор по частоте failed-login на уровне сети/поведения (высокая
  частота коротких соединений к одному порту) как поведенческий сигнал.

**Критерий приёмки.** Есть явная документация покрытия + хотя бы поведенческий сигнал на
high-frequency login (500 запросов из ATTACK 6 должны давать аномалию частоты).
