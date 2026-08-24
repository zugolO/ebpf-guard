# Аудит самозащиты ebpf-guard

Объект: ebpf-guard (`github.com/zugolO/ebpf-guard`), ветка `claude/ebpf-guard-self-protection-audit-u6vmhj`, ~153 тыс. строк Go.
Модель угроз: атакующий имеет выполнение кода в непривилегированном контейнере на ноде и сетевой доступ к ноде.
Аудит только на чтение. План работ — `SELF-PROTECTION-TASKS.md`.

---

## Фаза 1. Разведка

Точка входа одна — `cmd/ebpf-guard/main.go` (4567 строк, Cobra + Viper), там же вся последовательность старта: детект BTF (`internal/bpf/btf.go`), загрузка правил (`loadRulesWithTuning`, `cmd/ebpf-guard/main.go:4329`), создание `correlator.Engine` и `profiler`, подъём коллекторов (`cmd/ebpf-guard/main.go:1290-1500`), HTTP-сервер (`internal/exporter/server.go`), главный цикл ring buffer → корреляция → экспорт. BPF-программы лежат в `bpf/*.bpf.c` и компилируются `bpf2go` в `internal/bpf/*_gen.go`; загрузка и attach — в самих коллекторах (`internal/collector/{syscall,network,fileaccess,dns,tls,lsm,iouring,privesc,bpfmonitor,gpu,http_uprobe}.go`), каждый держит свой `[]link.Link`. Типы программ: raw tracepoint (`tp/raw_syscalls/sys_enter|sys_exit`, `bpf/syscall.bpf.c:42`), syscall-tracepoints (`tp/syscalls/sys_enter_openat` и др., `bpf/fileaccess.bpf.c:188`), kprobe/kretprobe (`tcp_connect`, `commit_creds`, `__x64_sys_bpf`, `__x64_sys_io_uring_*`), uprobe на OpenSSL/CUDA, eBPF LSM (`lsm/bpf_file_open`, `lsm/bpf_socket_connect`, `lsm/bpf_task_kill`, `lsm/kernel_module_request`, `lsm/kernel_read_file`, `bpf/lsm.bpf.c`), XDP (`bpf/xdp_block.bpf.c`) и cgroup-хук (`bpf/cgroup.bpf.c`). Attach везде через `link.*` (bpf_link), пиннинга в bpffs нет ни одного. API — HTTP (не gRPC) на `:9090`: `/metrics`, `/health*`, `/api/v1/{alerts,rules,incidents,status,summary,tuning/exceptions,bpf/reload}`, встроенный дашборд, опциональные `/debug/pprof` и `/debug/state`, опциональный `/gossip/`. Конфиг — Viper-YAML (`internal/config/config.go`, ~2400 строк дефолтов). Деплой: Helm-чарт `deploy/helm/ebpf-guard/` (DaemonSet + RBAC + ConfigMap + ServiceMonitor + PrometheusRule), сырые манифесты `deploy/manifests/`, `Dockerfile` (multi-stage → `gcr.io/distroless/static:debug`), .deb/.rpm через `packaging/nfpm.yaml` с юнитом `scripts/ebpf-guard.service`.

---

## Фаза 2. Чек-лист

Пункты со статусом `OK` — одной строкой в конце таблицы.

| # | Пункт | Вердикт | Ссылка |
|---|---|---|---|
| A1 | Watchdog/heartbeat, детект остановки извне | ЧАСТИЧНО | `internal/watchdog/watchdog.go:265` — heartbeat-гейдж есть, но умирает вместе с процессом; внешнее правило `EbpfGuardDown` есть в `deploy/helm/ebpf-guard/values.yaml:171`, но `prometheusRule.enabled: false` (там же, :165) |
| A2 | Мониторинг `bpf()` — detach/unload своих программ | ЧАСТИЧНО | `bpf/bpf_monitor.bpf.c:125` — только `BPF_PROG_LOAD` и `BPF_MAP_CREATE`; DETACH/MAP_UPDATE/MAP_DELETE не отслеживаются; коллектор выключен по умолчанию (`internal/config/config.go:2204`) |
| A3 | `bpf_link` вместо raw attach | OK | `internal/collector/syscall_iface.go:52`, `internal/collector/network.go:203` |
| A4 | Drop'ы ring buffer как security-событие | ЧАСТИЧНО | `internal/watchdog/watchdog.go:439` — считаются и экспортируются метрикой, алерт не порождается |
| A5 | Rate limiting внутри BPF (per-cgroup/per-pid) | ОТСУТСТВУЕТ | В `bpf/common.h` только глобальное modulo-сэмплирование (`bpf/common.h:342`); token-bucket и per-cgroup ограничений нет |
| A6 | Ограничение размеров мап, поведение при переполнении | OK | `internal/config/config.go:2025-2028`, `bpf/common.h:375` (`ringbuf_full_counters`), `record_map_full` + дренаж в `internal/watchdog/watchdog.go:492` |
| B7 | Проверка подписи/хеша конфига и политик | ЧАСТИЧНО | `internal/correlator/rule_checksum.go:24` реализован, но `internal/correlator/rule_loader.go:244` жёстко передаёт `false`; вызывающих `LoadRulesFromDirWithChecksums` вне тестов нет. Подписи нет вообще |
| B8 | Права на pin-путь в bpffs | N/A | Пиннинга нет: `Pin(`/`LoadPinned` не встречаются в `internal/`; `/sys/fs/bpf` монтируется RW в `deploy/manifests/daemonset.yaml:53` без использования |
| B9 | Периодический reconcile мап с эталоном | ОТСУТСТВУЕТ | `internal/watchdog/watchdog.go:387` сверяет только kernel tag программ (`internal/bpf/attestation.go`); содержимое мап не сверяется |
| B10 | Явный fail-closed/fail-open | ЧАСТИЧНО | `internal/config/config.go:2212` — дефолт `fail-open`; механизм fail-closed есть (`cmd/ebpf-guard/main.go:1605`), но список `collectors.required` пуст по умолчанию |
| C11 | Адрес прослушивания, mTLS, аутентификация | ЧАСТИЧНО | Bearer-токен с constant-time сравнением (`internal/exporter/server_auth.go:145`) — OK; но `bind_address: ":9090"` (`internal/config/config.go:2012`) + `hostNetwork: true` (`deploy/helm/ebpf-guard/templates/daemonset.yaml:35`), TLS нет нигде (`internal/exporter/server.go:342` — `ListenAndServe`) |
| C12 | Утечки через `/metrics` и debug | ЧАСТИЧНО | pprof и `/debug/state` выключены по умолчанию (`internal/config/config.go:2015-2016`) — хорошо; но `/health` без аутентификации отдаёт полный список коллекторов (`internal/exporter/server_auth.go:128`, `internal/exporter/server.go:555`), а `ebpf_guard_*` несёт метку `comm` (`internal/exporter/prometheus.go:145`) |
| C13 | RBAC ServiceAccount | OK | `deploy/manifests/rbac.yaml:8` — `pods/nodes/namespaces` на чтение, `*` и secrets отсутствуют |
| C14 | Контейнер: privileged, caps, hostPath, seccomp | ОТСУТСТВУЕТ | `deploy/helm/ebpf-guard/values.yaml:50` — `privileged: true`, `podSecurityContext: {}` (там же, :45); ни `seccompProfile`, ни `allowPrivilegeEscalation`, ни AppArmor в дефолтном шаблоне нет (профили в `deploy/security/` не подключены); `deploy/manifests/daemonset.yaml:27` — то же |
| C15 | Сброс capabilities после инициализации | ОТСУТСТВУЕТ | Ни `prctl`, ни `capset`, ни работы с securebits в `cmd/` и `internal/` |
| D16 | Границы/обрезка/UTF-8 для строк из ядра | OK | `internal/bpf/events.go:354` и далее — проверка `len(raw) < minSize` перед каждым разбором; `internal/util/bytes.go:11`, `internal/util/strings.go:7`, `internal/exporter/cardinality.go:45` (`SanitizeLabelValue`) |
| D17 | Экранирование в логах/шаблонах/запросах | ЧАСТИЧНО | `internal/exporter/syslog_cef.go:269` (`sanitizeLogField`), `:283` (`escapeSD`), `escapeCEFValue` — OK; но санируются только `Message`/`Comm`/`RuleName`, поля `FilePath` и произвольные `Details` в CEF-расширение попадают без обработки |
| D18 | Паника/OOM от сформированного события | OK | Границы проверяются (D16); дополнительно ограничены очередь (`bpf.event_queue_depth`) и память (`internal/watchdog/memory.go`) |
| E19 | io_uring | ЧАСТИЧНО | `bpf/iouring.bpf.c:44,94` — только факт `io_uring_setup`/`io_uring_enter`; opcode'ы SQE не декодируются, SQPOLL не покрыт; выключено по умолчанию (`internal/config/config.go:2203`). Правила `rules/iouring.yaml` работают только по факту использования |
| E20 | Compat / 32-битные syscalls | ОТСУТСТВУЕТ | `bpf/syscall.bpf.c:42` не проверяет ABI; таблица номеров только x86_64 (`internal/autolearn/syscall_names.go:6`); kprobe'ы навешены на `__x64_sys_*` (`bpf/bpf_monitor.bpf.c:117`, `bpf/iouring.bpf.c:44`) |
| E21 | `ptrace`, `/proc/<pid>/mem`, `process_vm_writev` | ЧАСТИЧНО | 101/310/311 в `DefaultMonitoredSyscalls` (`internal/bpf/sampling.go:298,308-309`) — OK; но запись через `/proc/<pid>/mem` идёт как обычный `write`, а 1 (`write`) в allowlist нет |
| E22 | TOCTOU при чтении аргументов из userspace | ОТСУТСТВУЕТ | `bpf/fileaccess.bpf.c:89` — `bpf_probe_read_user_str` на входе в `openat`, до `getname()`; LSM-путь с `bpf_d_path` используется только для блоклиста (`bpf/lsm.bpf.c:156`) |
| E23 | Устойчивость путей к symlink/bind-mount/`..` | ЧАСТИЧНО | LSM-хук использует канонический `bpf_d_path` — OK, но ключ блоклиста — FNV-32 (`bpf/lsm.bpf.c:117`), а при `bpf_d_path() < 0` (путь > 128 байт) хук разрешает открытие (`bpf/lsm.bpf.c:156`). Правила корреляции матчатся на userspace-строку из E22 |
| E24 | Идентификация субъекта: PID vs cgroup/start time | ЧАСТИЧНО | Enforcement race-free через pidfd (`internal/enforcer/pidfd_linux.go:23`) — OK; но LSM-мапы ключуются голым PID (`bpf/lsm.bpf.c:31,51`), self-exclusion — по TGID (`bpf/common.h:512`) |
| E25 | Allowlist vs blocklist | ЧАСТИЧНО | Syscall-фильтр — allowlist (`bpf/common.h:482`), это правильно; но comm-фильтр — blocklist по подделываемому имени (`bpf/common.h:466`), и whitelist доверия в правилах тоже по comm (`rules/ebpf-subversion.yaml:96`) |
| F26 | govulncheck/gosec/pin/подпись/SBOM | ЧАСТИЧНО | govulncheck блокирующий (`.github/workflows/ci.yml:598`), CodeQL, cosign + SLSA (`.github/workflows/release.yml:17`), SBOM — OK; но gosec с `-no-fail` (`.github/workflows/ci.yml:587`) и экшены на `@master` (`.github/workflows/ci.yml:563,585`) |

**Со статусом `OK`:** A3 (bpf_link), A6 (размеры мап и счётчики переполнения), C13 (RBAC без `*` и secrets), D16 (границы разбора событий), D18 (устойчивость к сформированному событию).

---

## Фаза 3. Отчёт

## Сводка

Самозащита реализована фрагментарно: отдельные механизмы написаны хорошо, но не подключены, а дефолтная конфигурация систематически выбирает доступность вместо наблюдаемости. Три самых опасных пробела. Первый — kernel-side denylist по `comm`, включённый по умолчанию: одного вызова `prctl(PR_SET_NAME,"fluent-bit")` из непривилегированного контейнера достаточно, чтобы все syscall- и файловые события процесса отбрасывались в ядре до ring buffer. Второй — убийство агента не детектируется: `kill`/`tkill`/`tgkill` не входят в kernel-side allowlist syscall'ов, LSM-хук `task_kill` всегда возвращает 0, watchdog умирает вместе с процессом, а внешнее правило `EbpfGuardDown` выключено в дефолтных values. Третий — пакет `internal/selfprotect`, единственный компонент с явной задачей анти-тамперинга, не имеет ни одного вызывающего вне собственных тестов, а BPF-сенсор, который должен его питать, не отслеживает именно те команды `bpf()`, которые детектор ищет. Дополнительно: `startup_policy: fail-open` по умолчанию превращает любой сбой загрузки коллектора в тихую слепоту при статусе healthy, а проверка контрольных сумм правил реализована, вынесена в конфиг и никогда не вызывается. Для заявленного containment AI-агентов текущее состояние не годится: обход мониторинга здесь достигается без эксплойта, штатными средствами из непривилегированного контекста.

## Находки

### [SP-01] Kernel-side denylist по `comm` позволяет ослепить агент одним `prctl`
Severity: critical
Категория: ослепление
Место: `internal/bpf/sampling.go:345`, `bpf/common.h:466`, `internal/config/config.go:2034`
Проблема: `bpf.kernel_filter.enabled` по умолчанию `true`, и `comm_is_denied()` отбрасывает событие до `bpf_ringbuf_reserve()`, если `bpf_get_current_comm()` совпал с записью в `comm_filter_map`. Карта заполняется из `BuildCommDenylist`, куда по умолчанию входит `DefaultNoisyDaemonDenylist()` — `systemd-journal`, `rsyslogd`, `syslogd`, `node_exporter`, `telegraf`, `filebeat`, `fluentd`, `fluent-bit`. `comm` меняется вызовом `prctl(PR_SET_NAME, ...)` без каких-либо привилегий. Комментарий на `internal/bpf/sampling.go:339-344` описывает ровно этот риск, но список всё равно включён по умолчанию — комментарий не является защитой.
Сценарий атаки: (1) атакующий в контейнере вызывает `prctl(PR_SET_NAME,"fluent-bit")`; (2) фильтр в `bpf/syscall.bpf.c:49` и `bpf/fileaccess.bpf.c:203` отбрасывает все его события в ядре; (3) все последующие действия — execve, чтение секретов, монтирование, `setns` — не порождают ни одного события, ни одной метрики и ни одной строки лога; (4) счётчик потерь тоже не растёт, потому что это не переполнение буфера, а решение фильтра.
Решение: убрать user-space демоны из дефолтного denylist (оставить только настоящие kernel-треды, которые `prctl` не переименовывает извне), а для шумных демонов перейти на ключ, который атакующий не контролирует: cgroup id или (dev, inode) исполняемого файла. Отдельно: само переименование в имя из denylist — сигнал, достойный алерта.
Трудоёмкость: M

### [SP-02] Пакет `internal/selfprotect` не подключён — анти-тамперинга в рантайме нет
Severity: critical
Категория: ослепление
Место: `internal/selfprotect/detector.go:1`
Проблема: пакет реализует `OwnedObjects`, `AgentAllowlist` и `Detector.ProcessEvent`, порождающий critical-алерт `self_protection_001` на попытку `BPF_PROG_DETACH`/`BPF_MAP_UPDATE_ELEM`/`BPF_MAP_DELETE_ELEM` по объектам агента. `grep -rn "selfprotect" --include=*.go .` за вычетом самого каталога пакета не даёт ни одного совпадения: `NewDetector` нигде не вызывается, `OwnedObjects` никогда не заполняется ID программ и мап, `EnforceMode` не имеет соответствующего LSM-хука (в `bpf/lsm.bpf.c` нет секции `lsm/bpf`). Это мёртвый код с тестами.
Сценарий атаки: (1) атакующий получает CAP_BPF/CAP_SYS_ADMIN — например, через соседний привилегированный под или через сам агент; (2) перечисляет программы `BPF_PROG_GET_NEXT_ID`, снимает link или обнуляет `syscall_filter_map`; (3) ни одного алерта не возникает — не потому, что событие не дошло, а потому что обработчика не существует.
Решение: создать `Detector` в `main.go`, зарегистрировать ID всех загруженных программ и мап в `OwnedObjects` сразу после attach, направить `ProcessEvent` на поток событий `EventBPFProgram` из `bpfmonitor`. Без этого пакет стоит удалить, чтобы он не читался как реализованная защита.
Трудоёмкость: M

### [SP-03] Убийство агента не детектируется ни одним из четырёх заявленных механизмов
Severity: critical
Категория: ослепление
Место: `internal/bpf/sampling.go:294`, `bpf/lsm.bpf.c:298`, `rules/defense-evasion.yaml:150`, `deploy/helm/ebpf-guard/values.yaml:165`
Проблема: четыре независимых слоя должны бы покрывать самую очевидную атаку — и не покрывают ни один. (1) `DefaultMonitoredSyscalls()` не содержит 62 (`kill`), 37 (`tkill`), 238 (`tgkill`), поэтому `syscall_is_monitored()` (`bpf/common.h:482`) отбрасывает эти события в ядре при дефолтном `kernel_filter.enabled: true`. (2) Из-за этого правило `evasion_auditd_stop` (`rules/defense-evasion.yaml:150`), написанное ровно под «убили security-демон», не может сработать в дефолтной конфигурации — а если бы событие дошло, оно требует `proc.comm in [bash, sh, python3, ...]`, то есть обходится компилированным бинарём. (3) LSM-хук `lsm_task_kill` помечен в коде как audit-only и безусловно возвращает 0 (`bpf/lsm.bpf.c:323`), не сверяя `target_pid` с PID агента. (4) Watchdog — внутрипроцессный (`internal/watchdog/watchdog.go:265`), его heartbeat исчезает вместе с процессом, а внешнее правило `EbpfGuardDown` лежит в `values.yaml` под `prometheusRule.enabled: false`.
Сценарий атаки: (1) атакующий определяет PID агента (в манифесте `hostPID: true`, `deploy/manifests/daemonset.yaml:20`, так что PID виден из любого пода с hostPID, а на ноде — тривиально); (2) `kill -9 <pid>`; (3) событие отброшено в ядре, LSM пропустил, watchdog мёртв, PrometheusRule не установлен; (4) до перезапуска DaemonSet — окно полной слепоты, а при `Restart=on-failure`/`RestartSec=10` в systemd-варианте (`scripts/ebpf-guard.service:10`) атакующий может держать агент выключенным циклом kill.
Решение: добавить 62/37/238 в allowlist; в `lsm_task_kill` сравнивать `BPF_CORE_READ(target, tgid)` с `agent_pid_map` и возвращать `-EPERM` в enforce-режиме, а событие эмитить всегда; включить `prometheusRule` по умолчанию и снизить `for` у `EbpfGuardDown`.
Трудоёмкость: M

### [SP-04] `bpf_monitor` не видит деструктивные команды `bpf()` и выключен по умолчанию
Severity: critical
Категория: ослепление
Место: `bpf/bpf_monitor.bpf.c:125`, `internal/config/config.go:2204`
Проблема: kprobe фильтрует `if (cmd != BPF_PROG_LOAD && cmd != BPF_MAP_CREATE) return 0;`. То есть именно те три команды, которые ищет `selfprotect.dangerousCommands` (`internal/selfprotect/detector.go:23` — `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`, `BPF_PROG_DETACH`), сенсором никогда не порождаются. `BPF_LINK_DETACH` (33) тоже отсутствует, хотя attach везде через bpf_link. Событие не несёт ни `map_id`, ни `prog_id` — только `prog_type` из первых 4 байт attr, — поэтому даже при расширении фильтра нельзя отличить тампер по объектам агента от чужой легитимной операции. Коллектор выключен дефолтом.
Сценарий атаки: (1) процесс с CAP_BPF вызывает `bpf(BPF_LINK_DETACH, ...)` по link'у syscall-коллектора; (2) ни `bpfmonitor`, ни `selfprotect` не реагируют; (3) watchdog заметит отвал через `IsAttached()` не раньше `check_interval` = 30 с (`internal/watchdog/watchdog.go:126`) — при условии, что коллектор корректно отражает состояние link'а.
Решение: пропускать cmd ∈ {2, 3, 8, 9, 33}, доставать из attr идентификаторы объекта (`map_fd`/`prog_fd`/`link_fd` → id), включить коллектор по умолчанию, сопоставлять id с `OwnedObjects` из SP-02.
Трудоёмкость: L

### [SP-05] `startup_policy: fail-open` по умолчанию: сбой коллектора = тихая слепота при статусе healthy
Severity: critical
Категория: целостность
Место: `internal/config/config.go:2212`, `cmd/ebpf-guard/main.go:1605`
Проблема: механизм fail-closed реализован, но включается только если `StartupPolicy == "fail-closed"` И непуст `requiredSet`. Дефолт — `fail-open`, а `collectors.required` по умолчанию пуст. Значит, при неудачной загрузке syscall- или file-коллектора (нет BTF, не тот kernel, отказ верификатора, EPERM на `bpf()`) агент продолжает работать, отдаёт 200 на `/health`, экспортирует heartbeat и не порождает событий. Для containment это худший из возможных режимов: фича считается работающей, пока не окажется, что она не работала.
Сценарий атаки: атака здесь не нужна — достаточно неудачного обновления ядра на ноде. Активный вариант: (1) атакующий добивается отказа загрузки — например, исчерпав `RLIMIT_MEMLOCK`/`memcg` бюджет ноды перед стартом пода агента; (2) агент поднимается без коллектора; (3) `/health/ready` возвращает 200, потому что `requiredCollectors` пуст (`internal/exporter/server.go:566` — при пустом множестве «required» логика опирается на зарегистрированные коллекторы, а незагрузившийся не регистрируется); (4) действия атакующего не наблюдаются.
Решение: дефолт `fail-closed`; `collectors.required` по умолчанию — syscall, file, network; при отсутствии required-коллектора readiness должен быть 503, а процесс — завершаться, а не продолжать в слепом режиме.
Трудоёмкость: S

### [SP-06] Детерминированное modulo-сэмплирование с `file_rate: 50` по умолчанию
Severity: high
Категория: обход детекта
Место: `bpf/common.h:342`, `internal/config/config.go:2043`
Проблема: `should_sample()` возвращает `(new_count % rate) == 0` по глобальному per-CPU счётчику `event_counters`. Это, во-первых, отбрасывает 98 % файловых событий при дефолтном `file_rate: 50` — то есть у произвольного `openat` вероятность быть замеченным равна 2 %. Во-вторых, решение детерминировано и зависит от счётчика, который может двигать любой процесс на той же CPU: фаза наблюдаема и управляема.
Сценарий атаки: (1) атакующий закрепляется на CPU через `sched_setaffinity`; (2) генерирует контролируемые файловые события и по появлению/отсутствию алертов на канареечном пути (`internal/canary/canary.go:26`) вычисляет фазу счётчика; (3) выравнивает фазу так, чтобы `openat("/etc/shadow")` пришёлся на слот с ненулевым остатком; (4) операция не попадает в ring buffer вовсе — это не потеря, а штатное решение фильтра, поэтому `ebpf_guard_bpf_lost_events_total` не растёт.
Решение: `bpf_get_prandom_u32()` вместо счётчика; выделить класс событий, к которым сэмплирование не применяется (execve, ptrace, пути из активных правил, канарейки); дефолтный `file_rate` = 1, а нагрузку регулировать фильтрами по путям, а не слепым прореживанием.
Трудоёмкость: M

### [SP-07] Проверка контрольных сумм правил реализована, но никогда не вызывается
Severity: high
Категория: целостность
Место: `internal/correlator/rule_loader.go:244`, `internal/config/config.go:2353`
Проблема: `VerifyRuleChecksums` (`internal/correlator/rule_checksum.go:24`) написан и покрыт тестами; конфиг имеет `rules.verify_checksums` с дефолтом `false`. Но `LoadRulesFromDir` жёстко вызывает `LoadRulesFromDirWithChecksums(dir, false, "")`, и путь из конфига до этого вызова не доходит: `loadRulesWithTuning` (`cmd/ebpf-guard/main.go:4337`) вызывает именно `LoadRulesFromDir`. Флаг конфигурации не влияет ни на что. Отдельно: `rules/checksums.sha256` лежит в том же каталоге, что и правила, и монтируется той же ConfigMap — контроль целостности ссылается сам на себя, поэтому даже при включении он не защитит от того, кто может писать в каталог правил.
Сценарий атаки: (1) атакующий получает запись в каталог правил (в bare-metal-развёртывании — доступ к `/etc/ebpf-guard/rules`, `rules.local_tuning_path` вообще относительный, `internal/config/config.go:2052`); (2) добавляет exception в overlay (`internal/correlator/tuning_overlay.go:23`), легализующий свои действия; (3) fsnotify-hot-reload (`cmd/ebpf-guard/main.go:1619`) применяет изменение — валидация синтаксиса проходит, целостность не проверяется; (4) в аудит-лог пишется штатная запись `rules_reloaded`, неотличимая от легитимного обновления.
Решение: прокинуть `cfg.Rules.VerifyChecksums` в загрузчик, дефолт `true`, эталон хранить отдельно от каталога правил (Secret или embedded), проверку выполнять и при hot-reload, а не только на старте. Долгосрочно — подпись набора правил, а не хеш.
Трудоёмкость: S

### [SP-08] TOCTOU: имя файла читается из userspace-памяти на входе в `openat`
Severity: high
Категория: обход детекта
Место: `bpf/fileaccess.bpf.c:89`
Проблема: `read_path_once()` вызывает `bpf_probe_read_user_str(out->path, sizeof(out->path), user_filename)` из tracepoint `sys_enter_openat` (`bpf/fileaccess.bpf.c:188`), то есть до того, как ядро скопировало имя через `getname()`. Между чтением probe'ом и копированием ядром атакующий может переписать буфер. Канонический путь через `bpf_d_path` в коде есть, но только в LSM-хуке (`bpf/lsm.bpf.c:156`) и только для блоклиста — детект и правила корреляции опираются на userspace-строку.
Сценарий атаки: (1) поток A в цикле вызывает `openat(AT_FDCWD, buf, ...)`, где `buf` — разделяемая страница; (2) поток B на другом ядре переписывает `buf` между входом в syscall и `getname()`; (3) агент видит `/tmp/benign`, ядро открывает `/etc/shadow`; (4) ни одно правило по путям не срабатывает, событие выглядит безобидным и попадает в baseline профайлера как норма.
Решение: на ядрах с CONFIG_BPF_LSM брать путь из `lsm/file_open` через `bpf_d_path`, tracepoint оставить fallback'ом и помечать источник пути в событии, чтобы корреляция могла понижать доверие к небезопасному источнику.
Трудоёмкость: L

### [SP-09] Больше половины syscall-номеров из поставляемых правил отбрасывается в ядре
Severity: high
Категория: обход детекта
Место: `internal/bpf/sampling.go:294`, `bpf/common.h:482`
Проблема: `syscall_is_monitored()` — allowlist из 22 номеров, зашитый константой. Сверка объединения всех значений `field: nr` в `rules/*.yaml` с этим списком даёт 43 использованных номера, из которых 23 отсутствуют в allowlist: 9 (mmap), 10 (mprotect), 35, 41 (socket), 82 (rename), 83, 87 (unlink), 106 (setgid), 113 (setreuid), 114, 117 (setresuid), 119, 135, 157 (prctl), 162, 206, 246 (kexec_load), 258 (mkdirat), 263 (unlinkat), 317, 320 (kexec_file_load), 323 (userfaultfd), 545. Плюс 62/37/238 из SP-03. Эти правила загружаются, валидируются, отображаются в `/api/v1/rules` и в MITRE-покрытии — и не могут сработать при дефолтном `kernel_filter.enabled: true`. Заявленное покрытие расходится с фактическим, и расхождение ничем не проверяется.
Сценарий атаки: (1) атакующий читает `rules/` из публичного репозитория и `internal/bpf/sampling.go` рядом; (2) выбирает технику, чей syscall лежит вне allowlist, — например, эскалацию через `setresuid`(117) вместо `setuid`(105), удаление следов через `unlinkat`(263), обход через `userfaultfd`(323); (3) действие не порождает события.
Решение: строить `syscall_filter_map` из фактически загруженного набора правил на старте и на каждом hot-reload; добавить тест, который валит сборку при расхождении объединения `nr` из `rules/*.yaml` с содержимым карты.
Трудоёмкость: M

### [SP-10] Compat/32-битный ABI не различается
Severity: high
Категория: обход детекта
Место: `bpf/syscall.bpf.c:42`, `internal/autolearn/syscall_names.go:6`
Проблема: `tp/raw_syscalls/sys_enter` срабатывает и для native x86_64, и для ia32-compat вызовов, но `ctx->syscall_nr` интерпретируется единственной таблицей x86_64 (`syscallNames`), и никакой проверки ABI в `bpf/*.c` нет (поиск `compat`/`ia32`/`audit_arch` даёт ноль совпадений в BPF-коде). Дополнительно kprobe'ы навешены строго на `__x64_sys_*` (`bpf/bpf_monitor.bpf.c:117`, `bpf/iouring.bpf.c:44`), то есть compat-вход в `bpf()` и `io_uring` не покрыт вообще.
Сценарий атаки: (1) атакующий запускает 32-битный бинарь или использует `int 0x80` из 64-битного процесса; (2) `execve` в i386-ABI имеет номер 11 — в таблице x86_64 это `munmap`, поэтому событие либо отбрасывается allowlist'ом, либо атрибутируется как безобидный вызов; (3) правила по `nr: 59` не срабатывают, профайлер учит неверную последовательность.
Решение: добавить в событие поле ABI (различать по `task->thread_info.status & TS_COMPAT` или по регистру `orig_ax`/сегменту), резолвить номера по соответствующей таблице, матчить правила внутри своего ABI; продублировать kprobe'ы на `__ia32_sys_*`.
Трудоёмкость: M

### [SP-11] API агента слушает 0.0.0.0 в hostNetwork без TLS; `/health` без аутентификации раскрывает состав коллекторов
Severity: high
Категория: attack surface
Место: `internal/config/config.go:2012`, `internal/exporter/server.go:342`, `deploy/helm/ebpf-guard/templates/daemonset.yaml:35`, `internal/exporter/server_auth.go:128`
Проблема: `bind_address` по умолчанию `":9090"` — все интерфейсы, а DaemonSet идёт с `hostNetwork: true`, значит API доступен по адресу ноды всей кластерной сети. TLS отсутствует полностью: сервер поднимается через `ListenAndServe` (не `ListenAndServeTLS`), настроек сертификата в `ServerConfig` нет. Bearer-токен, таким образом, ходит по сети в открытом виде и уязвим к перехвату на pod-network. `/health` исключён из аутентификации по префиксу и отдаёт `getHealthStatus()` со списком коллекторов и их состоянием (`internal/exporter/server.go:536`, `:555`). Среди аутентифицированных эндпоинтов есть записывающие: `/api/v1/tuning/exceptions`, `/api/v1/rules/reload`, `/api/v1/bpf/reload` (`internal/exporter/api.go:48-51`).
Сценарий атаки: (1) атакующий из соседнего пода делает `GET http://<nodeIP>:9090/health` и получает точную карту включённых коллекторов — то есть узнаёт, покрыты ли DNS, TLS, LSM, io_uring, прежде чем действовать; (2) выбирает технику в непокрытой области; (3) при наличии перехваченного или утёкшего токена — `POST /api/v1/tuning/exceptions` легализует его активность без правки файлов на диске.
Решение: дефолтный bind — `127.0.0.1:9090`, доступ к метрикам из Prometheus — через отдельный сертификат и mTLS; `ListenAndServeTLS` с обязательным клиентским сертификатом для `/api/v1/*` и `/metrics`; `/health` сократить до статуса без перечня подсистем.
Трудоёмкость: M

### [SP-12] Дефолтный Helm-чарт: privileged, без seccomp, без AppArmor, с RW-монтированием bpffs
Severity: high
Категория: attack surface
Место: `deploy/helm/ebpf-guard/values.yaml:45`, `deploy/helm/ebpf-guard/values.yaml:50`, `deploy/manifests/daemonset.yaml:27`
Проблема: `securityContext: {privileged: true}`, `podSecurityContext: {}` — ни `seccompProfile`, ни `runAsNonRoot`, ни `allowPrivilegeEscalation: false`, ни `readOnlyRootFilesystem`, ни аннотации AppArmor. Профили в `deploy/security/seccomp.json` и `deploy/security/apparmor.profile` существуют, но ни один шаблон чарта на них не ссылается. `/sys/fs/bpf` монтируется на запись (`deploy/manifests/daemonset.yaml:53`) при том, что пиннинг не используется. Hardened-набор есть в `values-secure.yaml` (`:41-53`: drop ALL, явные capabilities, `allowPrivilegeEscalation: false`, RuntimeDefault), но это opt-in — то есть безопасная конфигурация досталась тем, кто и так о ней знает.
Сценарий атаки: (1) атакующий получает выполнение кода в контейнере агента — через уязвимость парсера, зависимость, или `kubectl exec` с скомпрометированным доступом; (2) `privileged: true` + `hostPID: true` + отсутствие `NoNewPrivs` означают, что это сразу root на ноде без единого шага эскалации; (3) агент, чья задача — детектировать container escape, оказывается самым удобным средством его совершить.
Решение: перенести содержимое `values-secure.yaml` в `values.yaml` как дефолт; `values-secure.yaml` после этого не нужен. `/sys/fs/bpf` — `readOnly: true` до появления реального пиннинга.
Трудоёмкость: S

### [SP-13] Финальный образ собран на `distroless/static:debug` — в привилегированном контейнере есть shell
Severity: high
Категория: attack surface
Место: `Dockerfile:26`
Проблема: `FROM gcr.io/distroless/static:debug`. Debug-вариант distroless, в отличие от базового, содержит busybox и `/busybox/sh`. В сочетании с `privileged: true` и `hostPID: true` (SP-12) это даёт готовый интерпретатор в контейнере с полными правами на ноду. Комментарий в CLAUDE.md описывает финальный образ как distroless, что формально верно и практически вводит в заблуждение.
Сценарий атаки: (1) любая возможность выполнить команду в контейнере агента — RCE в обработчике, скомпрометированный CI, `kubectl exec` — сразу даёт интерактивный shell; (2) без busybox тому же атакующему пришлось бы доставлять свой бинарь, что порождает наблюдаемые события (`memfd_create` — 319, есть в allowlist).
Решение: `gcr.io/distroless/static:nonroot` или `:latest` без debug-тега; добавить в CI шаг, проверяющий отсутствие интерпретатора в финальном слое.
Трудоёмкость: S

### [SP-14] Gossip: пустой секрет аутентифицирует любой запрос
Severity: high
Категория: целостность
Место: `internal/gossip/http.go:122`, `internal/config/validate.go:177`, `internal/config/config.go:2275`
Проблема: `authCheck` сравнивает заголовок с `mgr.cfg.Secret` через `subtle.ConstantTimeCompare`. При дефолтном `gossip.secret: ""` и отсутствующем заголовке сравниваются два пустых среза, что даёт 1, то есть успех. Валидация (`internal/config/validate.go`) требует сертификаты при `tls_enabled`, но не требует секрета при `gossip.enabled`, а `gossip.tls_enabled` по умолчанию `false`. Gossip выключен дефолтом, но включается одной строкой конфига — и тогда `/gossip/` на `nodeIP:9090` (см. SP-11) принимает IOC от кого угодно в открытом виде.
Сценарий атаки: (1) оператор включает gossip, не задав секрет — валидация не возражает; (2) атакующий из пода делает `POST http://<nodeIP>:9090/gossip/iocs` без заголовков; (3) внедряет IOC-записи, либо забивая карту до `max_iocs: 100000` (вытесняя настоящие индикаторы), либо помечая легитимные адреса как вредоносные ради шумовой DoS-атаки на команду реагирования.
Решение: отклонять запрос при пустом `mgr.cfg.Secret` независимо от заголовка; требовать в `validate.go` секрет длиной не менее 32 байт при `gossip.enabled: true`; дефолт `gossip.tls_enabled: true`.
Трудоёмкость: S

### [SP-15] Потери событий трактуются как метрика производительности, а не как потеря видимости
Severity: high
Категория: ослепление
Место: `internal/watchdog/watchdog.go:439`, `deploy/helm/ebpf-guard/values.yaml:165`
Проблема: `runDropTracking` раз в 10 секунд опрашивает `DropTracker.LostEvents()` и инкрементирует `ebpf_guard_bpf_lost_events_total`. `alertFunc` при этом не вызывается ни разу — в отличие от отвала программы (`internal/watchdog/watchdog.go:334`) и от несовпадения tag (`:421`), где алерты есть. Соответствующего правила нет и во внешнем `prometheusRule` — в `values.yaml` перечислены правила на heartbeat, alert rate, reload, memory/CPU pressure и collector down, но не на потери событий и не на `ebpf_guard_bpf_attestation_violations_total`. Плюс сам `prometheusRule.enabled: false`.
Сценарий атаки: (1) атакующий создаёт форк-бомбу из отслеживаемых syscall'ов, переполняя 4 МБ ring buffer (`bpf/common.h:292`); (2) в окне переполнения выполняет целевое действие; (3) событие теряется, счётчик растёт, но никто не уведомлён — а поскольку per-cgroup ограничения отсутствуют (см. таблицу, A5), шум из одного контейнера гарантированно вытесняет события всех остальных.
Решение: превышение порога потерь за окно должно порождать critical-алерт `watchdog_events_lost` через ту же `alertFunc`; добавить правила на потери и на нарушения аттестации в дефолтный `prometheusRule` и включить его.
Трудоёмкость: S

### [SP-16] Правила eBPF-subversion доверяют строке `comm`
Severity: medium
Категория: обход детекта
Место: `rules/ebpf-subversion.yaml:96`
Проблема: правило `ebpf_subversion_unauthorized_caller` считает деструктивный вызов `bpf()` подозрительным только если `comm` не входит в список `["ebpf-guard","systemd","systemd-cgroups","containerd","dockerd","runc"]`. `comm` подделывается через `prctl` (та же примитива, что в SP-01). Долг зафиксирован в самом файле (`rules/ebpf-subversion.yaml:62-70`) с указанием причины: syscall-коллектор передаёт `nr`/`arg0..arg5`/`comm`/`uid`, но не идентификатор целевого BPF-объекта.
Сценарий атаки: (1) `prctl(PR_SET_NAME,"runc")`; (2) `bpf(BPF_PROG_DETACH, ...)`; (3) правило пропускает вызов как легитимную операцию контейнерного рантайма.
Решение: зависит от SP-04 — как только событие несёт `map_id`/`prog_id`, условие правила надо перевести на сверку объекта с `OwnedObjects`, а whitelist по `comm` убрать.
Трудоёмкость: M

### [SP-17] io_uring покрыт только по факту использования; операции не декодируются
Severity: medium
Категория: обход детекта
Место: `bpf/iouring.bpf.c:44`, `bpf/iouring.bpf.c:94`, `internal/config/config.go:2203`
Проблема: kprobe'ы на `io_uring_setup` и `io_uring_enter` фиксируют PID, флаги, fd и `to_submit`, но не читают submission queue entries, поэтому opcode операции (`IORING_OP_OPENAT`, `IORING_OP_CONNECT`, `IORING_OP_WRITE`) неизвестен. Файловый и сетевой коллекторы висят на syscall-tracepoint'ах, которых io_uring не вызывает, — значит операция не видна вообще. При `IORING_SETUP_SQPOLL` ядро забирает SQE из kernel-треда без `io_uring_enter`, так что не наблюдается даже факт submission. Коллектор выключен по умолчанию.
Сценарий атаки: (1) атакующий создаёт кольцо с `IORING_SETUP_SQPOLL`; (2) отправляет `IORING_OP_OPENAT` на `/etc/shadow` и `IORING_OP_CONNECT` на C2 через SQE; (3) правила по `nr` и путям не срабатывают, потому что соответствующих syscall'ов не было; в лучшем случае (при включённом коллекторе) фиксируется «процесс использовал io_uring» без указания, что именно он сделал.
Решение: читать SQE через `bpf_probe_read_user` в `io_uring_enter` и эмитить opcode + аргументы; для SQPOLL — kprobe на `io_submit_sqes`/`io_issue_sqe`; в containment-режиме, пока декодирования нет, честнее запрещать `io_uring_setup` политикой, чем считать область покрытой.
Трудоёмкость: L

### [SP-18] Capabilities не сбрасываются после инициализации
Severity: medium
Категория: attack surface
Место: отсутствует — в `cmd/` и `internal/` нет вызовов `prctl`, `capset` или работы с securebits
Проблема: агенту полный набор привилегий нужен только на этапе загрузки и attach BPF-программ. После этого он остаётся привилегированным на всё время жизни процесса, хотя разбор событий, корреляция и HTTP-обслуживание в привилегиях не нуждаются. Соответственно, цена любой уязвимости в парсере событий, в HTTP-обработчиках или в зависимости — сразу максимальная.
Сценарий атаки: (1) атакующий эксплуатирует уязвимость в userspace-части агента (например, в разборе DNS-пакета, `internal/collector/dns_parse.go`, или в обработчике API); (2) исполнение попадает в контекст с CAP_SYS_ADMIN/CAP_BPF и `hostPID`; (3) escape на ноду не требует дальнейших шагов.
Решение: после успешного attach всех коллекторов сбросить всё, кроме необходимого для enforcement (kill/nftables), и выставить `PR_SET_NO_NEW_PRIVS`. Перезагрузка BPF (`/api/v1/bpf/reload`) при этом должна выполняться через сохранённые fd, а не через повторную загрузку.
Трудоёмкость: M

### [SP-19] systemd-юнит запрещает `bpf(2)` собственным seccomp-фильтром
Severity: medium
Категория: целостность
Место: `scripts/ebpf-guard.service:27`, `packaging/nfpm.yaml:37`
Проблема: `SystemCallFilter=@system-service @network-io ~@privileged` в сочетании с `SystemCallErrorNumber=EPERM`. `bpf` входит в systemd-группу `@privileged`, поэтому отрицание `~@privileged` заставляет `bpf(2)` возвращать EPERM. Этот юнит устанавливается в `/lib/systemd/system/` из .deb/.rpm. В сочетании с `startup_policy: fail-open` (SP-05) результат — агент, который стартует, отвечает 200 на `/health`, шлёт heartbeat и не загрузил ни одной программы. Остальная часть юнита при этом добротная (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectKernelModules`).
Сценарий атаки: атака не требуется — сценарий реализуется штатной установкой пакета. Для атакующего это подарок: в пакетной установке агент по умолчанию слеп, а внешне здоров.
Решение: явно вернуть нужные вызовы (`@bpf`, `perf_event_open`) после группового отрицания либо отказаться от `~@privileged`; добавить smoke-тест на пакет, проверяющий `ebpf_guard_bpf_programs_loaded == 1` после `systemctl start`. Проверить утверждение на целевом дистрибутиве перед правкой — состав `@privileged` зависит от версии systemd.
Трудоёмкость: S

### [SP-20] LSM-блоклист путей: 32-битный хеш и «разрешить» при длинном пути
Severity: medium
Категория: обход детекта
Место: `bpf/lsm.bpf.c:117`, `bpf/lsm.bpf.c:156`
Проблема: `path_blocklist` ключуется значением `fnv32a()` от результата `bpf_d_path`, ограниченного 128 байтами. Два следствия. Первое: 32-битный хеш в мапе на 256 записей даёт практически достижимые коллизии — атакующий может подобрать безобидный путь, коллидирующий с заблокированным, и вызвать отказ в его открытии у легитимных процессов. Второе: если `bpf_d_path()` возвращает отрицательное значение (в том числе `-ENAMETOOLONG` для пути длиннее буфера), хук инкрементирует `LSM_STAT_FILE_OPEN_ALLOW` и возвращает 0 — то есть провал разрешения пути трактуется как «разрешить».
Сценарий атаки: (1) атакующий делает bind-mount каталога с заблокированным файлом в путь длиной больше 128 байт; (2) `bpf_d_path` не помещается в буфер и возвращает ошибку; (3) хук разрешает открытие; (4) параллельно можно подобрать коллизию к пути, который используют легитимные процессы, и устроить точечный отказ в обслуживании, маскирующий основную активность.
Решение: ключ — LPM по полному пути или пара (dev, inode); в enforce-режиме провал `bpf_d_path` должен вести к отказу, а не к разрешению, с обязательным audit-событием.
Трудоёмкость: M

### Прочее — по одной строке

- Reconcile содержимого BPF-мап с эталоном отсутствует: `internal/watchdog/watchdog.go:387` сверяет только kernel tag программ, поэтому подмена записи в `syscall_filter_map` или `comm_filter_map` не обнаруживается (medium, целостность).
- Per-cgroup/per-pid rate limiting внутри BPF-программ отсутствует (`bpf/common.h` — только глобальное сэмплирование), поэтому один контейнер может вытеснять события всех остальных (medium, ослепление).
- LSM-мапы `lsm_blocklist` и `lsm_agent_whitelist` ключуются голым PID (`bpf/lsm.bpf.c:31,51`), без учёта start time — при переиспользовании PID блокировка или whitelist достаётся чужому процессу (medium, обход детекта).
- gosec в CI запускается с `-no-fail` (`.github/workflows/ci.yml:587`), а `securego/gosec` и `aquasecurity/trivy-action` подключены по `@master` (`:585`, `:563`) — сборка зависит от подвижной ссылки на сторонний репозиторий (medium, supply chain).
- В CEF/syslog санируются только `Message`, `Comm` и `RuleName` (`internal/exporter/syslog_cef.go:234`), тогда как `FilePath` и произвольные ключи `Details` попадают в расширение без обработки (low, обход детекта).
- `rules.local_tuning_path` по умолчанию — относительный путь `rules/local-tuning.yaml` (`internal/config/config.go:2052`), разрешаемый относительно рабочего каталога процесса (low, целостность).

---

## Фаза 4

План работ — в `SELF-PROTECTION-TASKS.md`: три волны и таблица сценариев для attack-lab.
