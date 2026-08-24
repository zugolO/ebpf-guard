# SELF-PROTECTION-TASKS

План работ по самозащите ebpf-guard. Составлен по итогам аудита (см. `SELF-PROTECTION-AUDIT.md`).
Сортировка внутри волны — по (severity × обратная трудоёмкость).

Модель угроз: атакующий имеет выполнение кода в непривилегированном контейнере на ноде,
сетевой доступ к ноде. Цели — ослепить агент, подменить политики, использовать агент как
вектор эскалации.

---

## Волна 1 — блокеры

Без закрытия этих пунктов агент нельзя ставить на прод в режиме containment.
Каждый из них в одиночку сводит детект к нулю силами непривилегированного процесса
или силами дефолтной конфигурации.

- [ ] SP-01: Убери user-space comm из дефолтного denylist и перестань использовать comm как фильтр доверия в ядре
      Обоснование: SP-01 — `internal/bpf/sampling.go:345` (`DefaultNoisyDaemonDenylist`), `bpf/common.h:466` (`comm_is_denied`), `internal/config/config.go:2034` (`kernel_filter.enabled=true`)
      Файлы: `internal/bpf/sampling.go`, `bpf/common.h`, `internal/config/config.go`
      Критерий готовности: процесс, вызвавший `prctl(PR_SET_NAME,"fluent-bit")`, порождает те же события, что и до вызова; дефолтный `DefaultNoisyDaemonDenylist()` пуст либо ключ фильтра — (cgroup_id, exe-inode), не comm
      Тест: `prctl-rename-evasion` — procecc переименовывается в каждое имя из denylist, выполняет execve+openat, ожидается детект во всех итерациях
      Оценка: M

- [ ] SP-05: Смени дефолт `collectors.startup_policy` на `fail-closed` и заполни `collectors.required`
      Обоснование: SP-05 — `internal/config/config.go:2212`, `cmd/ebpf-guard/main.go:1605`
      Файлы: `internal/config/config.go`, `deploy/helm/ebpf-guard/values.yaml`, `config/config.yaml`
      Критерий готовности: при принудительном сбое загрузки syscall-коллектора агент завершается с ненулевым кодом, `/health/ready` отдаёт 503 до завершения, в логе — причина
      Тест: `collector-load-failure` — запуск с недоступным BTF/повреждённым объектом; ожидается non-zero exit, а не healthy-агент без детекта
      Оценка: S

- [ ] SP-03: Заведи детект убийства агента, не зависящий от самого агента
      Обоснование: SP-03 — `internal/bpf/sampling.go:294` (kill/tkill/tgkill вне allowlist), `bpf/lsm.bpf.c:298` (task_kill всегда allow), `rules/defense-evasion.yaml:150`
      Файлы: `internal/bpf/sampling.go`, `bpf/lsm.bpf.c`, `deploy/helm/ebpf-guard/values.yaml`
      Критерий готовности: (а) 62/37/238 в `DefaultMonitoredSyscalls`; (б) `lsm_task_kill` возвращает `-EPERM` при target==agent tgid в enforce-режиме и всегда шлёт событие; (в) `prometheusRule.enabled=true` по умолчанию и `EbpfGuardDown` c `for: 30s`
      Тест: `kill-agent` — SIGKILL по агенту с ноды; ожидается алерт до смерти процесса + срабатывание `EbpfGuardDown` не позже 90 с
      Оценка: M

- [ ] SP-02: Подключи `internal/selfprotect` к пайплайну или удали пакет
      Обоснование: SP-02 — `internal/selfprotect/detector.go:1` (ноль вызывающих вне пакета)
      Файлы: `cmd/ebpf-guard/main.go`, `internal/selfprotect/detector.go`, `internal/collector/bpfmonitor.go`
      Критерий готовности: `grep -rn "selfprotect\." --include=*.go cmd/ internal/ | grep -v internal/selfprotect/` непуст; `Detector.ProcessEvent` вызывается на каждом `EventBPFProgram`; ID программ/мап регистрируются в `OwnedObjects` при загрузке коллекторов
      Тест: `selfprotect-wiring` — синтетическое `EventBPFProgram` с `Cmd=BPF_PROG_DETACH` от чужого PID даёт алерт `self_protection_001` в store
      Оценка: M

- [ ] SP-04: Расширь `bpf_monitor` на деструктивные команды и включи его по умолчанию
      Обоснование: SP-04 — `bpf/bpf_monitor.bpf.c:125` (только PROG_LOAD/MAP_CREATE), `internal/config/config.go:2204` (`enabled=false`)
      Файлы: `bpf/bpf_monitor.bpf.c`, `internal/collector/bpfmonitor.go`, `internal/config/config.go`
      Критерий готовности: kprobe пропускает события для cmd ∈ {2,3,8,9,33} и извлекает `map_fd`/`prog_fd`/`target_fd` из attr; коллектор включён по умолчанию; событие несёт ID объекта, а не только comm
      Тест: `bpf-detach-link` — сторонний процесс с CAP_BPF снимает link агента; ожидается critical-алерт с ID программы
      Оценка: L

- [ ] SP-11: Переведи API на mTLS и убери привязку к 0.0.0.0 при hostNetwork
      Обоснование: SP-11 — `internal/config/config.go:2012` (`bind_address=":9090"`), `internal/exporter/server.go:342` (`ListenAndServe`, TLS отсутствует), `deploy/helm/.../daemonset.yaml:35` (`hostNetwork: true`), `internal/exporter/server_auth.go:128` (`/health` без аутентификации)
      Файлы: `internal/exporter/server.go`, `internal/config/config.go`, `deploy/helm/ebpf-guard/templates/daemonset.yaml`
      Критерий готовности: `ListenAndServeTLS` с обязательным клиентским сертификатом для `/api/v1/*` и `/metrics`; дефолтный bind — `127.0.0.1:9090`; `/health` отдаёт только `{"status":...}` без перечня коллекторов
      Тест: `api-from-pod` — curl с соседнего пода на `nodeIP:9090/health` и `/api/v1/rules`; ожидается отказ соединения либо TLS-handshake failure
      Оценка: M

- [ ] SP-12: Сделай hardened-профиль дефолтом Helm-чарта
      Обоснование: SP-12 — `deploy/helm/ebpf-guard/values.yaml:49` (`privileged: true`, `podSecurityContext: {}`), `deploy/helm/ebpf-guard/values-secure.yaml:41`
      Файлы: `deploy/helm/ebpf-guard/values.yaml`, `deploy/manifests/daemonset.yaml`
      Критерий готовности: в `values.yaml` — `privileged: false`, `capabilities.drop: [ALL]` + явный add, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, `readOnlyRootFilesystem: true`, `/sys/fs/bpf` c `readOnly: true`; `values-secure.yaml` становится избыточным
      Тест: `helm-default-psp` — `helm template` + проверка политикой (kyverno/conftest) на отсутствие `privileged: true`
      Оценка: S

---

## Волна 2 — укрепление

Закрывает реалистичные сценарии обхода и подмены политик.

- [ ] SP-07: Включи проверку контрольных сумм правил и вынеси эталон из каталога правил
      Обоснование: SP-07 — `internal/correlator/rule_loader.go:244` (жёстко `false`), `internal/config/config.go:2353`
      Файлы: `internal/correlator/rule_loader.go`, `cmd/ebpf-guard/main.go:4329`, `internal/config/config.go`
      Критерий готовности: `loadRulesWithTuning` передаёт `cfg.Rules.VerifyChecksums`; дефолт — `true`; путь эталона отделён от `rules_dir` (отдельный Secret/embedded); подмена одного байта в правиле останавливает старт и блокирует hot-reload
      Тест: `rule-tamper` — правка `rules/privesc.yaml` на смонтированном томе; ожидается `RuleReloadFailing` и сохранение старого набора правил
      Оценка: S

- [ ] SP-06: Замени детерминированное modulo-сэмплирование и подними `file_rate`
      Обоснование: SP-06 — `bpf/common.h:342` (`(new_count % rate) == 0`), `internal/config/config.go:2043` (`file_rate: 50`)
      Файлы: `bpf/common.h`, `internal/config/config.go`
      Критерий готовности: решение о сэмплировании использует `bpf_get_prandom_u32()`; события с `security_relevant`-разметкой (execve, ptrace, открытие путей из правил) не сэмплируются никогда; дефолтный `file_rate` = 1
      Тест: `sampling-phase-attack` — генератор шума синхронизирует фазу счётчика и выполняет `openat("/etc/shadow")` в «слепом» слоте 100 раз; ожидается 100 детектов
      Оценка: M

- [ ] SP-09: Синхронизируй kernel-side syscall allowlist с номерами, используемыми в правилах
      Обоснование: SP-09 — `internal/bpf/sampling.go:294` vs `rules/*.yaml` (23 из 43 номеров вне allowlist)
      Файлы: `internal/bpf/sampling.go`, `internal/correlator/rule_loader.go`
      Критерий готовности: allowlist вычисляется из загруженного набора правил на старте и на hot-reload, а не задан константой; правило, ссылающееся на номер вне allowlist, отклоняется на валидации либо расширяет карту
      Тест: `rule-vs-kernel-filter` — юнит-тест, сверяющий объединение `field: nr` по всем `rules/*.yaml` с содержимым `syscall_filter_map` после старта; расхождение = падение теста
      Оценка: M

- [ ] SP-08: Переведи файловый детект с userspace-аргументов на LSM/`bpf_d_path`
      Обоснование: SP-08 — `bpf/fileaccess.bpf.c:89` (`bpf_probe_read_user_str` на `sys_enter_openat`)
      Файлы: `bpf/fileaccess.bpf.c`, `bpf/lsm.bpf.c`, `internal/collector/fileaccess.go`
      Критерий готовности: на ядрах с CONFIG_BPF_LSM путь для событий берётся из `lsm/file_open` через `bpf_d_path`; tracepoint-путь остаётся только как fallback и помечается в событии полем `path_source`
      Тест: `openat-toctou` — два потока: один вызывает `openat` в цикле, второй переписывает буфер имени между probe и `getname()`; ожидается, что в алерте фигурирует реально открытый путь
      Оценка: L

- [ ] SP-14: Запрети пустой `gossip.secret` и включи TLS для gossip
      Обоснование: SP-14 — `internal/gossip/http.go:122` (`ConstantTimeCompare("","")==1`), `internal/config/validate.go:177` (проверки secret нет), `internal/config/config.go:2275`
      Файлы: `internal/gossip/http.go`, `internal/config/validate.go`
      Критерий готовности: `Handler` отклоняет запрос при пустом `mgr.cfg.Secret`; `validate.go` требует `gossip.secret` длиной ≥ 32 при `gossip.enabled=true`; `gossip.tls_enabled` по умолчанию `true`
      Тест: `gossip-empty-secret` — запуск с `gossip.enabled=true, secret=""`; ожидается отказ старта, а не принимающий IOC-эндпоинт
      Оценка: S

- [ ] SP-15: Трактуй потери в ring buffer как security-событие
      Обоснование: SP-15 — `internal/watchdog/watchdog.go:439` (`runDropTracking` только инкрементирует метрику), `deploy/helm/ebpf-guard/values.yaml:165` (`prometheusRule.enabled: false`)
      Файлы: `internal/watchdog/watchdog.go`, `deploy/helm/ebpf-guard/values.yaml`
      Критерий готовности: превышение порога drop-rate за окно вызывает `alertFunc` с critical-алертом `watchdog_events_lost`; в `prometheusRule` есть правило на `ebpf_guard_bpf_lost_events_total` и на `ebpf_guard_bpf_attestation_violations_total`
      Тест: `ringbuf-flood` — форк-бомба syscall'ов из контейнера, затем целевое действие; ожидается алерт о потере видимости, а не молчание
      Оценка: S

- [ ] SP-10: Различай ABI вызова (native / ia32 compat)
      Обоснование: SP-10 — `bpf/syscall.bpf.c:42` (`raw_syscalls/sys_enter` без проверки arch), `internal/autolearn/syscall_names.go:6` (таблица только x86_64)
      Файлы: `bpf/syscall.bpf.c`, `bpf/common.h`, `internal/autolearn/syscall_names.go`, `pkg/types/event.go`
      Критерий готовности: событие несёт поле `abi`; номера из compat-ABI резолвятся по i386-таблице; правило по `nr` матчится только внутри своего ABI
      Тест: `compat-execve` — `int 0x80` с `eax=11` (i386 execve) из 32-битного бинаря; ожидается детект execve, а не «munmap»
      Оценка: M

- [ ] SP-16: Замени whitelist по `comm` в правилах eBPF-subversion на идентификацию по объекту
      Обоснование: SP-16 — `rules/ebpf-subversion.yaml:96` (whitelist `comm`), долг зафиксирован в самом файле на строке 62
      Файлы: `rules/ebpf-subversion.yaml`, `bpf/bpf_monitor.bpf.c`
      Критерий готовности: условие правила опирается на `map_id`/`prog_id` из события (см. SP-04) и на `OwnedObjects`, а не на строку `comm`
      Тест: `bpf-detach-renamed` — атакующий переименовывается в `runc` и вызывает `bpf(BPF_PROG_DETACH)`; ожидается critical-алерт
      Оценка: M

- [ ] SP-19: Проверь, что systemd-юнит не запрещает `bpf(2)`
      Обоснование: SP-19 — `scripts/ebpf-guard.service:27` (`SystemCallFilter=@system-service @network-io ~@privileged`, `bpf` входит в `@privileged`), `packaging/nfpm.yaml:37`
      Файлы: `scripts/ebpf-guard.service`
      Критерий готовности: юнит явно возвращает нужные вызовы (`~@privileged` + `@bpf perf_event_open`) либо отказывается от группового отрицания; smoke-тест на пакет подтверждает загрузку хотя бы одной BPF-программы
      Тест: `deb-install-smoke` — установка .deb в VM, `systemctl start`, проверка `ebpf_guard_bpf_programs_loaded == 1`
      Оценка: S

- [ ] SP-13: Собери финальный образ на `distroless/static` без debug-варианта
      Обоснование: SP-13 — `Dockerfile:26` (`gcr.io/distroless/static:debug`)
      Файлы: `Dockerfile`
      Критерий готовности: в образе нет `/busybox/sh`; проверка в CI (`docker run --entrypoint /busybox/sh` завершается ошибкой)
      Тест: `image-no-shell` — CI-шаг, проверяющий отсутствие интерпретатора в финальном слое
      Оценка: S

- [ ] SP-18: Сбрасывай capabilities после загрузки BPF
      Обоснование: SP-18 — отсутствует; в `cmd/` и `internal/` нет ни одного вызова `prctl`/`capset`/`SecBits`
      Файлы: `cmd/ebpf-guard/main.go`
      Критерий готовности: после успешного attach всех коллекторов агент сбрасывает всё, кроме минимально необходимого для enforcement, и выставляет `PR_SET_NO_NEW_PRIVS`; `/proc/self/status` в рантайме показывает урезанный `CapEff`
      Тест: `caps-after-init` — чтение `/proc/<agent>/status` через 30 с после старта; `CapEff` не равен полному набору
      Оценка: M

- [ ] SP-20: Уйди от 32-битного хеша пути в LSM-блоклисте
      Обоснование: SP-20 — `bpf/lsm.bpf.c:117` (`fnv32a`), `bpf/lsm.bpf.c:156` (при `bpf_d_path() < 0` — allow)
      Файлы: `bpf/lsm.bpf.c`, `internal/collector/lsm.go`
      Критерий готовности: ключ блоклиста — LPM по полному пути либо (dev, inode); путь длиннее буфера не приводит к разрешению по умолчанию в enforce-режиме
      Тест: `lsm-path-bypass` — bind-mount `/etc` в путь длиной > 128 байт, затем открытие заблокированного файла через него; ожидается отказ
      Оценка: M

---

## Волна 3 — зрелость

- [ ] SP-21: Убери `-no-fail` у gosec и запинь версии GitHub Actions
      Обоснование: SP-F1 — `.github/workflows/ci.yml:585` (`securego/gosec@master`), `.github/workflows/ci.yml:587` (`-no-fail`), `.github/workflows/ci.yml:563` (`trivy-action@master`)
      Файлы: `.github/workflows/ci.yml`
      Критерий готовности: все `uses:` указывают на commit SHA; gosec-находки уровня HIGH валят сборку
      Тест: n/a (CI-политика); проверяется намеренным внесением known-bad паттерна в отдельной ветке
      Оценка: S

- [ ] SP-22: Введи reconcile содержимого BPF-мап с эталоном в userspace
      Обоснование: SP-B9 — отсутствует; `internal/watchdog/watchdog.go:387` (`runAttestation`) сверяет только tag программ, не содержимое мап
      Файлы: `internal/watchdog/watchdog.go`, `internal/bpf/attestation.go`
      Критерий готовности: периодический проход сверяет `syscall_filter_map`, `comm_filter_map`, `path_blocklist`, `agent_pid_map` с userspace-эталоном; расхождение = critical-алерт + восстановление
      Тест: `map-poison` — внешняя запись в `syscall_filter_map` (обнуление ключа execve); ожидается алерт и восстановление записи ≤ интервала reconcile
      Оценка: M

- [ ] SP-23: Добавь per-cgroup rate limiting внутри BPF-программ
      Обоснование: SP-A5 — отсутствует; в `bpf/common.h` нет ни одного token-bucket/per-cgroup ограничителя, есть только глобальное сэмплирование
      Файлы: `bpf/common.h`, `bpf/syscall.bpf.c`, `bpf/fileaccess.bpf.c`
      Критерий готовности: один cgroup не может вытеснить события другого cgroup из ring buffer; при флуде из одного контейнера события из соседних продолжают доходить
      Тест: `ringbuf-flood-isolation` — контейнер A флудит, контейнер B выполняет детектируемое действие; ожидается детект действия B
      Оценка: L

- [ ] SP-24: Опиши модель угроз самозащиты в репозитории
      Обоснование: SP-F2 — `SECURITY.md` описывает процесс раскрытия уязвимостей, но не модель угроз агента; в `deploy/security/README.md` нет раздела о самозащите
      Файлы: `SECURITY.md`, `docs/THREAT-MODEL.md` (создать)
      Критерий готовности: документ фиксирует границы доверия (ядро / агент / нода / кластер), явно перечисляет, что агент НЕ защищает (root на ноде, CAP_BPF у соседа), и связывает каждое ограничение с конкретным тестом attack-lab
      Тест: n/a (документация); ревью с чек-листом покрытия сценариев ниже
      Оценка: M

- [ ] SP-25: Собери CFP-материал по результатам attack-lab
      Обоснование: SP-F2 — производная от SP-24 и раздела сценариев ниже
      Файлы: `docs/`
      Критерий готовности: воспроизводимый набор из сценариев ниже с зафиксированным «до/после» по каждому
      Тест: полный прогон attack-lab на двух версиях (до волны 1 и после)
      Оценка: M

---

## Сценарии для attack-lab

Атаки на сам агент, которые стоит воспроизвести как регрессионные тесты.
Колонка «ожидаемый детект» — это критерий приёмки соответствующей задачи,
а не описание текущего поведения.

| # | Сценарий | Действие атакующего | Ожидаемый детект |
|---|---|---|---|
| 1 | `prctl-rename-evasion` | `prctl(PR_SET_NAME,"fluent-bit")`, затем execve/openat | События порождаются как обычно; переименование в имя из denylist само по себе — алерт (SP-01) |
| 2 | `kill-agent` | SIGKILL/SIGSTOP по PID агента с ноды | Алерт `lsm_task_kill` до доставки сигнала; `EbpfGuardDown` ≤ 90 с (SP-03) |
| 3 | `bpf-detach-link` | Процесс с CAP_BPF снимает bpf_link агента | Critical `self_protection_001` с prog_id; watchdog переприкрепляет (SP-02, SP-04) |
| 4 | `bpf-detach-renamed` | То же, но comm подменён на `runc` | Тот же алерт — идентификация по объекту, не по comm (SP-16) |
| 5 | `map-poison` | Внешняя запись в `syscall_filter_map`/`comm_filter_map` | Алерт о расхождении + восстановление эталона (SP-22) |
| 6 | `ringbuf-flood` | Форк-бомба syscall'ов, затем целевое действие под шумом | Алерт о потере видимости; целевое действие всё равно детектится (SP-15) |
| 7 | `ringbuf-flood-isolation` | Флуд из контейнера A, атака из контейнера B | Действие B детектируется (SP-23) |
| 8 | `sampling-phase-attack` | Синхронизация фазы счётчика сэмплирования под `openat` | Детект в 100 % итераций (SP-06) |
| 9 | `iouring-bypass` | `openat`/`connect`/`write` через SQE io_uring, режим SQPOLL | Детект операции по её opcode, а не только факта `io_uring_setup` (SP-17) |
| 10 | `compat-execve` | `int 0x80`, `eax=11` из 32-битного бинаря | Детект execve с корректным ABI (SP-10) |
| 11 | `openat-toctou` | Перезапись userspace-буфера имени между probe и `getname()` | В алерте — реально открытый путь (SP-08) |
| 12 | `lsm-path-bypass` | Bind-mount в путь > 128 байт, открытие заблокированного файла | Отказ в открытии (SP-20) |
| 13 | `rule-tamper` | Правка файла правил / добавление exception в tuning-overlay | Старт прерван либо hot-reload отклонён; алерт (SP-07) |
| 14 | `api-from-pod` | `curl nodeIP:9090/health`, `/api/v1/rules`, `/api/v1/tuning/exceptions` с соседнего пода | Соединение отклонено; попытка залогирована (SP-11) |
| 15 | `gossip-empty-secret` | POST IOC на `/gossip/` без заголовка секрета | 401; агент с пустым секретом не стартует (SP-14) |
| 16 | `collector-load-failure` | Порча BTF/объекта, чтобы коллектор не поднялся | Ненулевой exit, `/health/ready` = 503 (SP-05) |
| 17 | `rbac-escape` | Использование токена SA агента из соседнего пода | Токен недоступен; RBAC не даёт ничего сверх чтения pods/nodes/namespaces |
| 18 | `agent-shell` | `kubectl exec`/nsenter в контейнер агента, запуск `/busybox/sh` | Интерпретатора нет в образе (SP-13) |
