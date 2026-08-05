# ebpf-guard — задачи по итогам прогонов атак

**Прогон №1** (11:25–11:32 UTC): SQLmap/brute-force/SSRF/LDAP-CSRF против Juice Shop, ~7 мин.
**Прогон №2** (18:27:43–18:34:04 UTC, после исправлений): те же категории атак, ~6.5 мин,
логи в `server-logs/`. Агент рестартовал в 18:27:18 (learning с нуля, `learning_period: 300`),
baseline снят через 25 с после рестарта.
**Прогон №3 — idle** (2026-08-03 19:41 → 2026-08-04 04:41 UTC, 9 часов **без единой атаки**):
`deploy/docker-test-setup/idle-run.sh`, 109 срезов с интервалом 5 мин, данные в
`server-logs/idle-20260803_194120/`. Финальный рестарт агента для проверки P0-3.
**Прогон №4 — атака** (2026-08-04 18:09:54 → 18:21:33 UTC, ~11.5 мин, стенд 89.125.2.154,
версия `f505252`): sqlmap → bruteforce → ssrf → ldap/csrf по Juice Shop. Данные в
`server-logs/` (плоско, без подкаталога). Агент стартовал в 17:55:14, обучение завершилось
в 18:00:14, baseline снят в 18:09:52 — то есть **baseline содержит ~2 часа idle-трафика**
(16:08 → 18:09), что делает его же и вторым idle-замером. Конфиг: `track_open+track_write`,
пороги watchdog 200/320/150.

Ниже — статусы задач по итогам прогонов №2 и №3, а также новые задачи из idle-прогона.

---

## Сводка статусов после прогона №2

| Задача | Статус |
|---|---|
| P0-1 — цепочка процессов в инциденте | ❌ ПОДТВЕРЖДЁН idle-прогоном (`process_chain: null` в 1768/1768) |
| P0-2 — вердикт «атака» | ⚠️ работает механически, но на idle даёт 100% FP — см. P1-13 |
| P0-3 — persistence профайлера | ❌ ПОДТВЕРЖДЁН БАГ: включён, отрабатывает, learning **не переживает рестарт** |
| P1-4 — видимость learning | ✅ сделано |
| P1-5 — 503 под нагрузкой | ✅ не воспроизвелось (и на 9-часовом idle тоже) |
| P1-6 — FP-шум baseline | ❌ ПОДТВЕРЖДЁН И ХУЖЕ: 35619 алертов за 9 ч idle, 81% — системные демоны |
| P2-7 — отчётный скрипт | ✅ СДЕЛАНО (JSON валиден, метрики берутся из `/debug/state`, per-attack счётчик по `jq length`, фаза обучения из `/api/v1/status`) |
| P2-8 — скрипты атак | ✅ в основном (gate работает, остатки в P3-16) |
| P3-9 — L7-покрытие | ✅ сделано |
| P1-10 — `/debug/state` нули | ✅ СДЕЛАНО (провайдеры подключены; при ревью исправлены снимок-вместо-живых-счётчиков, 2 ошибки компиляции, hot-reload) |
| P1-11 — cardinality anomaly_score | ⚠️ УЛУЧШЕНО (660 серий вместо 3601), но 56% серий с пустым `comm` |
| P2-12 — `*_write` на open | ✅ СДЕЛАНО (13 правил на `op: write`, закреплено тестом с двух сторон + WARN при `track_write: false`) |
| P1-13 — ложные «подтверждённые атаки» | ❌ РЕЗКО ХУЖЕ: 1768 FP за 9 ч idle (было «30% ложных») |
| P2-14 — специфичность сетевых правил | ✅ СДЕЛАНО (при ревью найдены и закрыты ещё 2 loopback-правила; ≤2 алерта на соединение) |
| P1-17 — агент алертит на себя | ✅ СДЕЛАНО (canary — по PID; остальные — пара `comm + путь`; при ревью исправлены comm-only exceptions и 2 некомпилирующихся теста) |
| P2-15 — нет `anomalies_total` | ✅ СДЕЛАНО: метрика добавлена, лог «learning complete» есть, покрыт тестами |
| P2-20 — DNS ERROR при shutdown | ✅ СДЕЛАНО (при ревью дополнено `ErrClosed`/`os.ErrClosed`, иначе была регрессия в бесконечный ERROR-цикл) |
| P3-16 — остатки по скриптам атак | ✅ СДЕЛАНО (`--ignore-code=401`, итоговый gate падает от любого под-гейта с ненулевым exit code, счёт по ответам любого кода) |
| P1-18a — обратная связь в CPU-watchdog | ✅ СДЕЛАНО (dwell 30 с → 3 мин, дедупликация переходов, метрика `cpu_degraded_fraction`; при ревью исправлен незадействованный дефолт в конфиге) |
| P1-18b, P1-19, P2-21 | 🆕 новые задачи из idle-прогона №3 (P1-18 разделена на a/b) |

---

## Сводка статусов после прогона №4 (атака, 2026-08-04, `f505252`)

Первый прогон, где «сделанные» задачи этапа 1 проверены **под атакой и при
`track_write: true`**. Часть из них проверку не прошла.

| Задача | Было | Стало после №4 |
|---|---|---|
| P0-1 — цепочка процессов | ❌ подтверждён на idle | ❌ **подтверждён на атаке**: 114/114 `chain unknown`, 114/114 одно-PID |
| P0-3 — persistence профайлера | ❌ баг | ❌ **третье подтверждение**; `profiler_state_restored 1` врёт |
| P0-24 — UTF-8-паника | ✅ исправлено | ✅ **держит на боевом трафике**: 0 паник, 0 рестартов |
| P1-6 — FP-шум baseline | ✅ сделано (1-я волна) | ❌ **откат**: 9664 алерта за 2 ч idle при `track_write: true` (~4800/ч, темп не изменился) |
| P1-10 — `/debug/state` | ✅ сделано | ⚠️ **частично**: `engine_stats`/`rules` живые, `profiler_stats` — нули |
| P1-11 — cardinality | ⚠️ улучшено, плато 660 | ❌ **регресс**: 1282 → 6319 серий за 11.5 мин, `/metrics` 107 → 414 КБ |
| P2-12 — `*_write` на open | ✅ сделано | ⚠️ работало за счёт `track_write: false`; при `true` шум вернулся |
| P1-13 — ложные «атаки» | ❌ хуже | ❌ **и на атаке 0% точности**: 570 FP за 2 ч idle + 114 под атакой, все на `sshd`; реальная атака инцидентом не стала |
| P1-17 — агент алертит на себя | ✅ сделано | ⚠️ **частично**: canary ✅ 0 (было 903), но 1220 алертов `comm=ebpf-guard` за 2 ч idle |
| P1-18a — CPU-watchdog | ⚠️ частично | ⚠️ **без изменений**: флаппинга нет, но пороги 200/320 при потреблении 153% — регулятор отключён, а не починен |
| P2-15 — `anomalies_total` | ✅ сделано | ✅ подтверждено: 28 → 87, лог `learning complete` есть |
| P2-20 — DNS ERROR при shutdown | ✅ сделано | ✅ подтверждено: 0 ERROR за прогон |
| P2-7 — отчётный скрипт | ✅ сделано | ❌ **регресс** → вынесено в **P2-28** (JSON снова невалиден) |
| P0-22 — 1.5 ядра на пустом хосте | 🆕 | ❌ подтверждён: 152% idle → 153.3% под атакой; file = 99.4% потока |
| **P0-25** | — | 🆕 потеря 52% network / 55% syscall-событий под атакой при `visibility_reduced: false` |
| **P0-26** | — | 🆕 DNS-коллектор дал 0 событий за прогон при `healthy: true` |
| **P1-27** | — | 🆕 инцидент без `comm`: 684 из 684 |
| **P2-28** | — | 🆕 регресс отчётного скрипта (P2-7) |

**Главный вывод прогона №4.** Детект под атакой работает — 43 типа, 852 алерта от
атакующих процессов, сеть даёт яркий сигнал (7 → 22 555 событий). Не работает всё, что
стоит **после** детекта: корреляция собирает инциденты исключительно на `sshd` и ни одного
на реальной атаке (P1-13, P0-1), при этом половина сетевых событий до корреляции вообще не
доходит (P0-25), а агент рапортует полную видимость. Плюс проверка «сделанных» задач при
`track_write: true` показала, что часть этапа 1 держалась на выключенном коллекторе.

---

## Этап 1 — защита от «починили тишину ценой слепоты»

Этап 1 (P1-6, P1-17, P2-12, P2-14) — это **ослабление детекта**: каждый allowlist,
self-exception и comm-фильтр сужает то, что агент видит. Чтобы тишина на idle не
была куплена слепотой под атакой, добавлен машинный контроль —
[stage1_detection_integrity_test.go](internal/correlator/stage1_detection_integrity_test.go).
Он гоняет атакующие сигналы из эталонного прогона по **реальному** каталогу
`rules/` (586 правил) и падает, если детект потерян:

| Проверка | Что гарантирует |
|---|---|
| `TestStage1_AttacksStillDetected` | 10 сценариев по-прежнему детектятся: SSRF (метаданные облака + нестандартный порт), brute-force по SSH, SSH-туннель, кража `/etc/shadow`, скрейпинг `/proc/<pid>/mem`, кража приватного ключа, container escape через `/proc/1/environ`, cron-бэкдор, reverse shell на внешний высокий порт |
| `TestStage1_LoopbackNotExfiltration` | loopback не классифицируется как exfil; одно соединение → ≤2 алерта (критерий приёмки P2-14) |
| `TestStage1_NetworkRuleSpecificity` | `curl` больше не объявляется ssh-клиентом, веб-сервером, CI-раннером и СУБД одновременно |
| `TestStage1_P2_12_WriteRulesRequireWrite` | read-only open **не** поднимает `*_write`-правило, но реальный write — поднимает (обе стороны критерия P2-12) |
| `TestStage1_P2_12_InertRulesAreReported` | write-зависимые правила перечислимы для стартового WARN при `track_write: false` |
| `TestP1_17_SelfExclusion` | на каждое из 8 правил: свой доступ подавлен, чужой — алертит, подделка `comm` не даёт невидимости |

Ключевой принцип, зафиксированный в тестах: **exception привязан к паре
`comm + путь`, никогда к одному `comm`**. Иначе скомпрометированный процесс,
переименовавший себя в `sshd`/`ebpf-guard`/`irqbalance`, становится невидимым.
Тест `TestP1_17_SelfExclusion` проверяет это явно (пункт 3 — подделка comm) и
не даст вернуться к comm-only exception незаметно.

Это не отменяет живой прогон №2 на стенде — тесты покрывают логику правил, но не
поведение коллекторов, сэмплинг и корреляцию под нагрузкой.

---

## Результаты детекта в прогоне №2 (для контекста)

Атаки **обнаружены** — в отличие от прогона №1 сигнал связный:

- 1710 новых алертов, 70 уникальных правил; **1159 (68%) — от процессов атаки**
  (sqlmap 376, curl 376, docker-proxy 407).
- sqlmap: `netintr_loopback_high_port` 47, `beacon_fixed_interval` 31,
  `c2_periodic_beacon_pattern` 29, `net_high_frequency_connections` 23.
- brute-force (500 запросов high_frequency): `net_high_frequency_connections` +
  `net_portscan_indicator` — критерий приёмки P3-9 выполнен.
- SSRF/LDAP/CSRF через docker-proxy: `webshell_ssrf_internal_network` 61,
  `web_internal_recon` 61, `owasp_web_ssrf_outbound` 66.
- Корреляция: 60 critical `incident_confirmed_attack`, score 50–68, 3–5 MITRE-тактик.
- Профайлер после завершения обучения дал 12 алертов `anomaly_detection`
  (sqlmap→:3000, curl→/etc, bash→sqlmap-results).

Оговорки: сами SQLi **не удались** (401 на login, поиск не инъектируем, Juice Shop
детектился sqlmap'ом как «WAF/IPS») — детект сработал по факту сканирования, не по
успешной эксплуатации. Специфичность правил низкая — см. P2-14.

---

## Результаты idle-прогона №3 (9 часов без атак) — главный вывод

**Ни одной атаки не было. Агент выдал 35619 алертов, из них 15740 critical и
1768 «подтверждённых атак».**

| Показатель | Значение | Ожидалось |
|---|---|---|
| Алертов за 9 ч | 35619 (~3960/час, **1.1 алерта в секунду**) | близко к нулю |
| Critical | 15740 (44%) | 0 |
| `incident_confirmed_attack` | **1768** | **0** (критерий приёмки P1-13) |
| Шум от системных демонов | 28918 (**81%**) | — |
| Алерты на self-poll агента (`curl` от idle-run.sh) | 4725 (13%) | 0 |
| Алерты на сам `ebpf-guard` | 6293 (18%) | 0 |
| Циклы CPU-watchdog reduce↔recover | 813 пар (каждые **40 с**, всю ночь) | 0 |
| file-событий обработано | **43.4 млн** (≈1340/с на простаивающем хосте) | — |
| RSS агента | 202 МБ → 224 МБ (плато) | плато ✅ |
| `process_resident_memory_bytes` | 207 МБ → 356 МБ | — |
| Серии `profiler_anomaly_score` | 264 → 619 (макс 701, плато) | ограничено ✅ |
| `events_dropped_total` | 0 по всем коллекторам | 0 ✅ |
| SQLite store | 31.2 МБ за 9 ч idle | — |
| Незапланированных падений/рестартов | 0 | 0 ✅ |

**Что подтвердилось хорошего:** утечки памяти нет (RSS вышел на плато 224 МБ),
cardinality `anomaly_score` перестала расти неограниченно (плато ~660 серий вместо
прогноза «десятки тысяч за час»), потерь событий нет, агент за 9 часов не упал,
API держался (`healthy:true` во всех 109 срезах), rule exceptions из P1-6 работают
(`sigma_memory_proc_dump` подавлен 3032 + 2303 раза).

**Что оказалось хуже прогноза:** практически весь остальной список гипотез из раздела
«Idle-прогон» подтвердился, а P1-13 подтвердился катастрофически — 1768 ложных
«подтверждённых атак» вместо нуля. **Агент в текущем виде непригоден к продакшену:
оператор получит ~4000 алертов в час на полностью простаивающем сервере.**

**Нарастание, а не стационар.** Алерты за час: 1425 → 2820 → 3181 → 3637 → 3962 →
3939 → 4325 → 4556 → 4698. Инциденты за час: 71 → 123 → 145 → 155 → 201 → 186 → 224 →
244 → 252. Поток шума **растёт со временем**, а не выходит на плато — см. P1-19.

---

## P0-1 — Инциденты не коррелируют цепочку атаки между процессами

**Тип:** bug / feature · **Приоритет:** P0 · **Метки:** `correlation`, `detection-quality`
· **Статус:** ⚠️ ЧАСТИЧНО

**Сделано.** `types.Incident` получил `RootPID` и `ProcessChain`
([pkg/types/incident.go:26-27](pkg/types/incident.go#L26-L27)), группировка по корню
process-tree и слияние реализованы в
[internal/correlator/incident.go:241-294](internal/correlator/incident.go#L241-L294),
есть unit-тесты ([incident_test.go:272-293](internal/correlator/incident_test.go#L272-L293)).

**Что осталось.** В реальном прогоне цепочка **не наполняется ни разу**: все 60 новых
`incident_confirmed_attack` имеют `"process_chain": null` и `root_pid == pid` самого алерта.
Сообщение буквально: `... in process chain unknown (score 58.0)`. То есть
`getProcessChain` получает алерт с пустым `ProcessTree` — LineageTracker не наполняет
дерево на пути алерта, и группировка деградирует до старого `(pid, namespace)`.

**Что сделать.**
- Проследить путь `LineageTracker → Alert.ProcessTree` в `engine.go` и убедиться, что
  дерево прикрепляется к алерту до попадания в `IncidentTracker.Add`.
- Добавить e2e-тест (не unit): синтетические события `bash → curl → sqlmap` через
  движок целиком → один инцидент с непустым `ProcessChain`.
- Метрика/лог диагностики: доля инцидентов с пустым `ProcessChain`.

**Подтверждение idle-прогоном №3.** Ситуация не изменилась и стала статистически
бесспорной: **1768 из 1768** (100%) `incident_confirmed_attack` имеют
`"process_chain": null`, во всех сообщение `in process chain unknown`, во всех
`root_pid == pid`. Ни одного инцидента с непустой цепочкой за 9 часов.

**Критерий приёмки.** В прогоне атак ≥80% `incident_confirmed_attack` имеют непустой
`process_chain`, и хотя бы один инцидент объединяет ≥2 разных PID.

**Подтверждение прогоном №4 (атака, 2026-08-04) — критерий приёмки провален по обоим
пунктам, и это первая проверка на реальной атаке.** Из 114 новых
`incident_confirmed_attack`:

- **114/114 (100%)** содержат `in process chain unknown` — как и 1768/1768 на idle;
- **114/114 состоят из алертов ровно одного PID** (проверено разбором `details.alert_ids`,
  где PID закодирован в id алерта). Ни один инцидент не объединил два разных процесса —
  при том, что атака шла цепочкой `bash → sqlmap`, `bash → curl` и через `docker-proxy`;
- у **45 из 114** все алерты инцидента имеют **один и тот же timestamp** с точностью до
  наносекунды — это одно файловое событие, размноженное перекрывающимися правилами, а не
  цепочка (см. P1-13, P2-14).

То есть на реальной атаке группировка деградировала до `(pid, namespace)` ровно так же,
как на idle. Гипотеза «на idle цепочек нет, потому что нет атаки» **опровергнута**:
атака была, цепочки процессов были, `ProcessChain` пуст.

---

## P0-2 — Нет вердикта «атака»: инцидент не повышает серьёзность и не скорится

**Тип:** feature · **Приоритет:** P0 · **Метки:** `correlation`, `detection-quality`
· **Статус:** ✅ DONE

**Сделано и подтверждено прогоном.**
- Скоринг инцидента + вердикт: `AlertRuleIDConfirmedAttack`
  ([incident.go:51](internal/correlator/incident.go#L51)), эмит синтетического алерта
  ([engine.go:2015](internal/correlator/engine.go#L2015)).
- Метрика: `ebpf_guard_incidents_total{verdict="attack"} 12 → 72`,
  `{verdict="suspicious"} 28 → 203`.
- Алерты: `ebpf_guard_alerts_total{rule_id="incident_confirmed_attack",severity="critical"} 72`
  (60 новых за время атак), score 50–68, 3–5 MITRE-тактик на инцидент.

**Остаточная проблема вынесена в P1-13** (30% ложных «подтверждённых атак»).

---

## P0-3 — Persistence состояния profiler'а: learning не переживает рестарт

**Тип:** bug · **Приоритет:** P0 · **Метки:** `profiler`, `learning`
· **Статус:** ❌ БАГ ПОДТВЕРЖДЁН ПРОГОНАМИ №3 и 2026-08-04

**Сделано.** `LoadState` на старте + периодический автосейв
([main.go:454-480](cmd/ebpf-guard/main.go#L454-L480)), `SaveState` в graceful-shutdown
([main.go:1988](cmd/ebpf-guard/main.go#L1988)), конфиг с `save_interval_seconds`
([config.go:1062-1072](internal/config/config.go#L1062-L1072)).

**Теперь проверено — и не работает.** В idle-прогоне
`state_persistence: {enabled: true, path: /var/lib/ebpf-guard/profiler-state.json,
save_interval_seconds: 300}` был **включён**, механизм отработал, но learning всё равно
потерялся:

```
before restart: "learning_complete": true,  "learning_progress": 1, "learning_samples": 396262
after  restart: "learning_complete": false, "learning_progress": 0.066, "learning_samples": 27420
```

Журнал показывает, что и сохранение, и загрузка реально произошли:

```
04:41:32 INFO graceful shutdown: saving profiler state  path=/var/lib/ebpf-guard/profiler-state.json
04:41:32 INFO profiler: restored persisted state        path=...  learning_complete:false
```

**Корневая причина найдена: восстановленное состояние затирается через ~200 строк
после загрузки.**

Порядок вызовов в [cmd/ebpf-guard/main.go](cmd/ebpf-guard/main.go):

1. **main.go:456** — `prof.LoadState(...)` восстанавливает `learner.startTime`,
   `learner.sampleCount`, `learner.learningComplete` и профили
   ([persistence.go:352-377](internal/profiler/persistence.go#L352-L377)).
2. **main.go:668** — `correlator.NewCorrelationEngineWithConfig(engineCfg)`, а внутри
   него ([engine.go:802-806](internal/correlator/engine.go#L802-L806)):

```go
sharedLearner = profiler.NewBaselineLearner(config.LearningPeriod, config.MinLearningSamples)
if ce.anomalyDetector != nil {
    ce.anomalyDetector.SetSharedLearner(sharedLearner)   // ← затирает restored state
}
```

3. `SetSharedLearner` ([anomaly.go:636-640](internal/profiler/anomaly.go#L636-L640))
   подменяет `ad.learner` **новым, пустым** learner'ом и вдобавок явно сбрасывает
   атомик: `ad.learningComplete.Store(false)`.

То есть `LoadState` отрабатывает корректно, а затем создание движка выбрасывает всё
восстановленное. Отсюда и наблюдаемая картина: лог `restored persisted state` есть,
`ebpf_guard_profiler_state_restored 1` есть, а `learning_complete` после рестарта
`false` с прогрессом 0.066 — обучение честно пошло с нуля по новому таймеру.

**Дополнительно: сохраняется пустой набор профилей.** Файл на диске **173 байта** после
9 часов и 396262 сэмплов — это ровно заголовок `ProfilerState` с опущенным
`"profiles"` (`omitempty`). Даже после починки п.1 восстанавливать будет нечего:
`SaveState` ([persistence.go:283-295](internal/profiler/persistence.go#L283-L295))
обходит `ad.profileManager.shards` того детектора, на котором его вызвали, а реальные
профили копятся в **per-worker** детекторах `ce.ingestPool[i].ad`
([engine.go:815-829](internal/correlator/engine.go#L815-L829)), созданных отдельно и
`main.go` неизвестных.

**Что сделать.**
- Передавать восстановленный learner в движок вместо создания нового: либо
  `EngineConfig` получает готовый `*BaselineLearner`, либо `SetSharedLearner`
  переносит состояние (`startTime`, `sampleCount`, `learningComplete`) из старого
  learner'а в новый, а не сбрасывает атомик безусловно.
- Научить `SaveState` собирать профили со **всех** per-worker детекторов пула
  (агрегация на уровне движка), иначе на диск и дальше будет уезжать `{}`.
- Логировать при сохранении число профилей и размер файла:
  `state saved profiles=N bytes=M` — 173 байта должны были насторожить сразу.
- Логировать периодический автосейв на INFO: за 9 часов при `save_interval_seconds: 300`
  ожидалось ~108 срабатываний, в журнале **нет ни одного** упоминания.
- Unit-тест round-trip недостаточен (он зелёный) — нужен тест на **реальном пути**:
  события через `NewCorrelationEngineWithConfig` → завершение обучения → `SaveState` →
  новый движок → `LoadState` → `learning_complete == true` и профили на месте.

**Критерий приёмки.** После `systemctl restart` `ebpf_guard_learning_complete` равен 1
сразу (без 5-минутного переобучения), а файл состояния весит больше нескольких КБ.

> **Повторное подтверждение (прогон 2026-08-04, стенд 89.125.2.154).** Баг воспроизвёлся
> ровно как описано. Перед рестартом `learning_complete: true`, файл на диске 174 байта;
> сразу после рестарта `learning_complete: false`, `sample_count: 0`, обучение пошло с нуля.
> Содержимое файла после shutdown:
> ```json
> {"saved_at":"2026-08-04T17:50:22Z","learning_period":3600000000000,
>  "learning_complete":false,"learning_start_time":"2026-08-04T16:08:45Z","sample_count":0}
> ```
> **Новая деталь:** в сохранённом состоянии `learning_period` = **3600 c** (1 час), хотя
> в `config-test.yaml` стоит `learning_period: 300` (5 минут). То есть на диск уезжает не
> тот период, что в конфиге, — сохраняется дефолтный часовой learner (тот самый пустой,
> который создаётся в движке и затирает восстановленный). Это ещё одно проявление корневой
> причины: сохраняется состояние **не того** learner'а. При приёмке проверять и это поле.
> На стенде файл удалён, профайлер переобучился за 5 минут — на прогон атаки не влияет.

> **Третье подтверждение (прогон №4, тот же стенд).** Журнал старта 17:55:14 показывает
> тот же разрыв между «состояние восстановлено» и «состояния нет»:
> ```
> 17:55:14 INFO graceful shutdown: saving profiler state  path=/var/lib/ebpf-guard/profiler-state.json
> 17:55:14 INFO profiler: restored persisted state        path=...  learning_complete:false
> 18:00:14 INFO profiler: learning complete               samples=1826675 elapsed_seconds=300
> ```
> `restored persisted state` с `learning_complete:false` — и следом полные 300 с
> переобучения с нуля до 1.83 млн сэмплов. Механизм отрабатывает, восстанавливать нечего.
> **Практическое последствие, видимое в этом прогоне:** первые 5 минут после каждого
> рестарта профайлер слеп, и это ровно то окно, в которое атакующий и будет рестартовать
> агента. Плюс: `metrics-before/after` дают `ebpf_guard_profiler_state_restored 1` в обоих
> срезах — метрика рапортует успех при фактическом нуле восстановленного состояния, то есть
> **на неё нельзя опираться в приёмке** (проверять `learning_complete` и размер файла).

---

## P0-24 — Паника агента на невалидном UTF-8 в `comm` (Prometheus label) — ✅ ИСПРАВЛЕНО

**Тип:** bug · **Приоритет:** P0 · **Метки:** `exporter`, `prometheus`, `crash`, `security`
· **Статус:** ✅ ИСПРАВЛЕНО (commit `33312da`, прогон 2026-08-04)

**Симптом.** Idle-прогон 2026-08-04 упал через 8 минут после старта:

```
panic: label value "\xfe\xff" is not valid UTF-8
goroutine 122 [running]:
prometheus.(*GaugeVec).WithLabelValues(...)
exporter.(*AnomalyScoreGuard).SetAnomalyScore  internal/exporter/cardinality.go:111
exporter.SetAnomalyScoreWithGuard              internal/exporter/cardinality.go:246
correlator.(*CorrelationEngine).ingestWithAD   internal/correlator/engine.go:1547
systemd: Main process exited, code=exited, status=2/INVALIDARGUMENT
```

**Корневая причина.** `comm` приходит из ядра (`e.Comm[16]`) и **контролируется атакующим** —
процесс может назвать себя любыми байтами. Значение шло в `WithLabelValues` без валидации,
а `client_golang` **паникует** на метке, не являющейся валидным UTF-8. Единственный путь входа
kernel-строк в метки — `SetAnomalyScore` (`pid` числовой, безопасен; `comm` — нет);
[engine.go:1547](internal/correlator/engine.go#L1547) передаёт `util.InternBytes(e.Comm[:])`
сырьём.

**Почему это критично именно под атакой.** Обфусцированные имена процессов, пути с бинарными
байтами, exploit-payload'ы — ровно тот класс данных, что порождает атака. То есть краш **более
вероятен под атакой, чем на idle**: агент падал бы посреди прогона, теряя события и разрывая
корреляционные цепочки. Это не косметика, а отказ в обслуживании, триггерируемый извне.

**Исправление** ([cardinality.go](internal/exporter/cardinality.go)). Добавлена
`SanitizeLabelValue` (невалидные байты и управляющие символы → `\xNN`, как в проверенной
`enforcer.sanitizeComm`), вызывается в начале `SetAnomalyScore` — **до** формирования ключа
мапы. Порядок принципиален: если чистить только в точке `WithLabelValues`, то `evictLowest`
звал бы `DeleteLabelValues` с сырыми байтами и не удалял бы серию, созданную с чистым →
утечка серий. Fast-path `isPlainLabelValue` не трогает обычный ASCII (99%+ comm).

**Тесты** ([cardinality_utf8_test.go](internal/exporter/cardinality_utf8_test.go)): точный байт
из паники (`\xfe\xff`), набор враждебных строк, фаззинг всех 256 байтов на инвариант «выход
всегда валидный UTF-8», и тест на порядок — вытеснение должно оперировать санитизированным
ключом. Зелёные с `-race` на стенде.

**Осталось подумать.** Другие точки, где kernel-строки могут попасть в метки, проверены —
`EventsTotal`/`AlertsTotal` берут K8s-метаданные и `rule_id`, не сырые байты. Но санитизацию
стоит поднять на уровень **декодирования события** (один раз при чтении из ring buffer), а не
латать per-callsite: тогда и логи, и store, и будущие метки получат чистое значение из одного
места. Это отдельная задача — сейчас закрыта именно точка краша.

---

## P1-4 — learning_period непрозрачен: нет видимости прогресса

**Тип:** enhancement · **Приоритет:** P1 · **Метки:** `profiler`, `observability`
· **Статус:** ✅ DONE (остаток — P3-15)

**Сделано и подтверждено прогоном.**
- Метрики `ebpf_guard_learning_progress` (0.05 → 1.0), `ebpf_guard_learning_complete`
  (0 → 1), `ebpf_guard_learning_seconds_remaining` (284.97 → 0)
  ([prometheus.go:135-153](internal/exporter/prometheus.go#L135-L153)).
- Периодический INFO-лог: `profiler: learning in progress progress=20% samples=83706`.
- Фаза обучения в `/api/v1/status` через `AgentHealth`
  ([health.go:42-52](internal/exporter/health.go#L42-L52)).
- После завершения обучения профайлер реально заработал: 12 алертов `anomaly_detection`.

**Примечание.** `/health` фазу обучения не отдаёт (она в `/api/v1/status`) — тестовые
скрипты дёргают `/health` и не видят её. Это не баг агента, а вопрос к скриптам (P2-7).

---

## P1-5 — UI/API отдаёт 503 под нагрузкой

**Тип:** bug · **Приоритет:** P1 · **Метки:** `api`, `performance`, `availability`
· **Статус:** ✅ НЕ ВОСПРОИЗВОДИТСЯ

**Доказательство из прогона №2.** Ни одного 503 за всё время. `/health` в обоих
снимках: `{"healthy":true,"ready":true,...}`. `ebpf_guard_events_dropped_total = 0` по
всем коллекторам. CPU-watchdog эскалировал до level 2 один раз
(`escalating — reducing syscall and network sampling`, cpu 70.1% в 18:33:28) — API это
пережил без отказов.

**Что осталось (опционально).** Явное состояние `degraded` (200 + флаг) при
`VisibilityReduced=true` в самом `/health`, чтобы деградация сэмплинга была видна тем,
кто смотрит только на `/health`. Держим как nice-to-have.

---

## P1-6 — Baseline «загрязнён» хостовым шумом

**Тип:** bug / detection-quality · **Приоритет:** P1 · **Метки:** `rules`, `false-positive`
· **Статус:** ⚠️ БОЛЬШОЙ ПРОГРЕСС, НЕ ЗАКРЫТО

**Прогресс.** Было 113366 алертов на старте — стало **161** за 25 с. Названные в задаче
правила подавлены: `fim_library_replaced` — 0, `supply_chain_build_tool_rootwrite` — 0,
`sigma_memory_proc_dump` — 4 (и уже не от `systemd-journal`, а от `ps`/`dbus-daemon`).

**Что осталось.** 551 из 1710 новых алертов (**32%**) — не атака:

| comm | алертов | характерные правила |
|---|---|---|
| sshd | 151 | `rootkit_pam_module_added` 13, `sigma_utmp_wtmp_modified` 12, `sigma_log_deletion` 9 |
| ebpf-guard (сам агент) | 111 | `cred_proc_maps_mass_read` 22, `sigma_cpu_info_access` 21, `canary_004` 6 |
| cron | 101 | `fim_group_write` 8, `fim_shadow_write` 5, `rootkit_pam_module_added` 6 |
| irqbalance | 36 | `container_escape_proc_write` 36 (запись в `/proc/irq/*/smp_affinity`) |
| grep / ps / prometheus / grafana / systemd-journal | ~50 | `cred_proc_maps_mass_read`, `sigma_memory_proc_dump` |

**Что сделать.**
- Allowlist/exception для `sshd`, `cron`, `irqbalance`, `prometheus`, `grafana` в
  затронутых правилах (с привязкой к пути, а не только к comm).
- Самоисключение агента: `ebpf-guard` не должен алертить на собственные чтения
  `/proc/*/maps` и на срабатывание собственных canary-файлов.
- См. также P2-12 — часть этих FP растёт из open-vs-write.

**Результат idle-прогона №3 — критерий приёмки провален с большим запасом.**
За 9 часов простоя: **35619 алертов, 15740 critical** (вместо «близко к нулю»),
средний темп **~4000 алертов в час**. Распределение по источникам:

| comm | алертов | доля | характерные правила |
|---|---|---|---|
| sshd | 9664 | 27% | `sigma_sensitive_file_chmod` 988, `drift_new_library_in_system_dir` 822, `webshell_sensitive_file_read` 739, `rootkit_pam_module_added` 711 |
| cron | 7042 | 20% | `sigma_passwd_shadow_read` 633, `appexploit_lfi_passwd_access` 633 |
| **ebpf-guard (сам агент)** | 6293 | 18% | `sigma_cpu_info_access` 1554, `cred_proc_maps_mass_read` 1439, canary_001..005 903 |
| **curl (self-poll idle-run.sh)** | 4725 | 13% | `webshell_network_connection_web_proc`, `net_portscan_indicator`, `exfil_*` |
| irqbalance | 3229 | 9% | `container_escape_proc_write` 3229 |
| prometheus | 1179 | 3% | `container_escape_init_proc` 1178 |
| grafana / systemd-journal / ps / grep | ~1350 | 4% | `cred_proc_maps_mass_read`, `sigma_*` |

**81% алертов — от системных демонов**, ещё 18% — от самого агента. Полезного сигнала
нет вообще: атак не было.

**Что работает.** Механизм rule exceptions рабочий и его надо просто расширить —
`ebpf_guard_rule_exceptions_total` показывает 3032 подавления
`sigma_memory_proc_dump` по исключению `ebpf-guard-self`, 2303 по `systemd-journal`,
85 по `systemd-sysctl`. То есть инфраструктура есть, покрыты 3 пары правило↔процесс из
нужных десятков.

**Что сделать (уточнено после idle-прогона).**
- Расширить exceptions на top-источники: `irqbalance` → `container_escape_proc_write`
  (`/proc/irq/*/smp_affinity`), `prometheus` → `container_escape_init_proc`,
  `sshd`/`cron` → PAM/shadow/utmp-правила, `grafana` → `cred_proc_maps_mass_read`.
- Самоисключение агента сделать сплошным, а не точечным — см. новую задачу **P1-17**
  (сейчас `ebpf-guard-self` покрывает одно правило из полутора десятков).
- См. также P2-12 — `curl`- и `cron`-шум растёт из open-vs-write.

**Критерий приёмки.** На idle-хосте (без атак) за 10 мин — близко к нулю critical-алертов.
Проверяется повторным idle-прогоном.

**Статус: ✅ СДЕЛАНО (первая волна, требуется повторный idle-прогон для подтверждения).**

1. **Корневая причина (P2-12) устранена в самих правилах, не патчем поверх.**
   Все `*_write`/`*_modified`-правила из таблицы (`fim_passwd_write`,
   `rootkit_passwd_modified`, `fim_shadow_write`, `fim_group_write`,
   `mitre_nsswitch_modified`, `container_escape_proc_write`,
   `sigma_utmp_wtmp_modified`, `rootkit_ld_preload_written`,
   `rootkit_shared_lib_written_to_system`, `rootkit_proc_sysctl_write`,
   `rootkit_kernel_image_write`, `sigma_proc_sysrq_write`,
   `owasp_web_suspicious_write`) теперь требуют `op: write` через
   `condition_group` (`op eq write` AND путь), а не срабатывают на голый `open`.
   Со stand-конфигом (`track_open=true`, `track_write=false`) это обнуляет
   весь класс шума от sshd/cron/curl/irqbalance по построению — целевого
   write-события коллектор не поставляет, править списком comm не пришлось.
2. **Расширены exceptions** на оставшиеся top-источники, не покрытые пунктом 1:
   `irqbalance` → `container_escape_proc_write`
   ([rules/container-escape.yaml](rules/container-escape.yaml)), `prometheus` →
   `container_escape_init_proc` (там же), `grafana`/`grafana-server` добавлены в
   `not_in` условие `cred_proc_maps_mass_read`
   ([rules/credential-access.yaml](rules/credential-access.yaml)) — правило и
   раньше матчило по comm в самом условии, а не через `exceptions:`, поэтому
   расширен именно этот список.
3. **Ревью нашло и исправило дефект в исходной правке:** восемь блоков правил
   в `rootkit-detection.yaml`, `sigma-linux.yaml`, `mitre-additional.yaml`,
   `owasp-web.yaml` были сдвинуты на один лишний пробел (3-space indent вместо
   2) при добавлении `condition_group` — YAML грузился с ошибкой
   `did not find expected '-' indicator` на `mitre_nsswitch_modified` и падал
   бы весь rule-set (586 правил) при старте агента. Отступ выровнен по всем
   восьми блокам, весь `rules/`-каталог теперь грузится чисто
   (`LoadRulesFromDir` → 586 правил, проверено тестом).
4. sshd/cron → PAM/shadow/utmp специально **не** получили comm-based
   exceptions (в отличие от плана выше) — пункт 1 закрывает их шум на уровне
   `op:write`, а не ослаблением условия по процессу; в проде, где write
   реально трекается, `sshd`/`cron`, пишущие в `/etc/shadow` или `utmp`, всё
   ещё обязаны алертить — это ровно те процессы, легитимная запись которых в
   эти файлы неотличима от компрометации без анализа содержимого изменения.

5. **Ревью сузило exceptions из п. 2 до пары «comm + путь».** В исходной
   правке `irqbalance` и `prometheus` были привязаны только к `comm`, то есть
   любой процесс с таким именем получал полную невидимость на
   `container_escape_proc_write` (весь `/proc/sys/*`, `/proc/bus/*`) и
   `container_escape_init_proc` (весь `/proc/1/*`, включая `environ`). Теперь
   `irqbalance` ограничен `/proc/irq/`, `prometheus` — `/proc/1/{cgroup,stat,status}`.
   `grafana` в `cred_proc_maps_mass_read` остаётся в `not_in`-списке по comm,
   как и остальные девять записей этого списка (`gdb`, `strace`, `ps`, …) —
   это исходный дизайн правила, а не новое ослабление.

**Что осталось.** Нужен повторный 9-часовой idle-прогон для подтверждения, что
темп алертов действительно приблизился к нулю (критерий приёмки), и проверка,
что write-трекающий прогон (когда `track_write: true`) не восстанавливает
старый объём шума на легитимных sshd/cron-операциях — если восстановит,
понадобятся точечные exceptions по пути и признакам легитимности (не по
одному comm), как и предупреждала первоначальная формулировка задачи.

**Проверка прогоном №4 — ровно тот сценарий, о котором предупреждал абзац выше:
`track_write: true`, и старый объём шума восстановился. Статус откатывается на ❌.**

Baseline прогона №4 = **2 часа idle с `track_write: true`** (16:08 → 18:09, до первой
атаки). Результат — **9664 алерта, ≈4800/час**, то есть темп idle-шума **не изменился**
относительно прогона №3 (~3960/час), несмотря на весь этап 1:

| comm (idle-baseline, 2 ч) | алертов | доля |
|---|---|---|
| sshd | 3891 | 40% |
| **ebpf-guard (сам агент)** | 1220 | 13% |
| cron | 1184 | 12% |
| `""` (инциденты) | 575 | 6% |
| curl (self-poll) | 499 | 5% |
| prometheus | 365 | 4% |
| grafana | 276 | 3% |
| landscape-sysin, grep, systemd-logind, systemd-journal, find | ~890 | 9% |

Топ правил на idle: `cred_proc_maps_mass_read` 683, `container_escape_init_proc` 615,
`sigma_sensitive_file_chmod` 603, `owasp_web_sensitive_file_read` 574,
`sigma_passwd_shadow_read` 572, `appexploit_lfi_passwd_access` 572,
`incident_confirmed_attack` 570, `webshell_sensitive_file_read` 550.

**Что это говорит про этап 1.** Починка P2-12 (`op: write`) работала на стенде №3 только
потому, что там `track_write: false` — правила были обездвижены конфигурацией, а не
исправлены по существу. Ровно этот риск и был записан в P2-12 («что осталось: прогон с
`track_write: true`»). Как только коллектор начал поставлять write-события, `sshd`/`cron`
снова набирают тысячи critical. При этом заметьте: `sigma_sensitive_file_chmod` (603) и
`sigma_passwd_shadow_read` (572) — это **read/chmod-правила**, они не зависят от
`track_write` вовсе и шумели бы в любом случае; их этап 1 не покрыл.

**Под атакой картина та же:** из 2282 новых алертов **1430 (63%) — не от атакующих
процессов**, из них 938 от `sshd` (`sigma_sensitive_file_chmod` 93,
`webshell_sensitive_file_read` 92, `owasp_web_sensitive_file_read` 91,
`sigma_passwd_shadow_read` 86, `appexploit_lfi_passwd_access` 86 …).

**Что сделать дополнительно.**
- Разобрать, **что именно** `sshd` делает с `/etc/passwd`/`/etc/shadow`/utmp при каждом
  логине, и построить exception по паре «comm + путь + op», а не отключать правила.
  Отдельно: почему `sshd` матчит правила класса `webshell_*`/`owasp_web_*`/`appexploit_*` —
  это правила про веб-процессы, `sshd` в их списке `proc.comm` быть не должен вовсе
  (тот же дефект специфичности, что чинили в P2-14 для сетевых правил, но для файловых).
- Правила `sigma_sensitive_file_chmod` и `sigma_passwd_shadow_read` не зависят от
  `track_write` — им нужна собственная работа по специфичности.

**Критерий приёмки без изменений**, проверять **обязательно при `track_write: true`** —
на `track_write: false` он выполняется тривиально и ничего не доказывает.

---

## P2-7 — Отчётный скрипт: несогласованные метрики

**Тип:** bug (tooling) · **Приоритет:** P2 · **Метки:** `tooling`, `testing`
· **Статус:** ✅ СДЕЛАНО

**Закрыто (этап 0.5).** Все шесть пунктов ниже исправлены:

1. `FINAL-REPORT.json` валиден — значения подставляются из тех же переменных, что и
   текстовый отчёт, и инициализированы нулём, а не пустой строкой.
2. Label-агрегация: `idle-run.sh` суммирует серии через
   `grep '^ebpf_guard_alerts_total{' | awk '{s+=$NF}'`; `run-all-attacks.sh` берёт точные
   счётчики из `/debug/state` (`engine_stats.total_alerts`), что надёжнее греп-суммы.
3. `anomalies_total` читается из `profiler_stats.anomalies_total` — имя синхронизировано
   с метрикой, добавленной в P2-15.
4. Per-attack счётчик: `wc -l` по JSON-массиву на одной строке всегда давал 1/1/0 —
   заменён на `jq 'length'` в `sqlmap-attacks.sh` и `bruteforce-attacks.sh`.
5. Число попыток sqlmap считается по строкам лога, а не по одному файлу.
6. Добавлен опрос `/api/v1/status` (baseline и final) — в отчёте появился блок
   `Learning Phase` с `learning_complete`/`learning_progress`, которых нет в `/health`.

**Исправлено ранее.** Дельта по id работает: «ТОП НОВЫХ АЛЕРТОВ (дельта baseline → final по id)»
даёт реалистичные 66/63/62 вместо фантомных 8063. Сумма по метрикам сходится с API
(baseline 161, final 1871 — совпадает с числом алертов в JSON).

**Что осталось.**
1. `FINAL-REPORT.json` **всё ещё невалиден** — пустые значения: `"before": ,` `"after": ,`
   `"new": ` во всех трёх блоках.
2. Ключевые метрики врут: «Alerts Total: 0 → 0, Новых: 0» рядом с «70 типов, 1710 алертов».
   Скрипт грепает `ebpf_guard_alerts_total` без label-агрегации (метрика существует только
   с лейблами) — надо суммировать серии.
3. «Anomalies Total: 0» — грепается несуществующее имя метрики (см. P2-11).
4. Per-attack блоки печатают «Алерты до атаки: 1 / после: 1 / новых: 0» — счётчик per-attack
   сломан (вероятно, `jq length` по объекту, а не по массиву, либо limit=1).
5. «sqlmap → Попыток атак: 1» при 6 реально выполненных сканах.
6. Скрипты читают `/health` и `/debug/state` вместо `/api/v1/status` — не видят ни фазы
   обучения, ни статистики движка (см. также P1-10).

---

## P2-8 — Скрипты атак не генерируют трафик / sqlmap падает

**Тип:** bug (tooling) · **Приоритет:** P2 · **Метки:** `tooling`, `testing`, `attacks`
· **Статус:** ✅ В ОСНОВНОМ

**Исправлено и подтверждено.** REQUEST GATE: 978 запросов, **все сценарии > 0**:
`high_frequency: 500`, `distributed: 200`, `session_bruteforce: 100`, `enumeration: 72`,
`password_spraying: 72`, `api_bruteforce: 21`, `credential_stuffing: 13` — раньше три из
них были нулями. Ошибок `no such option --dump-table` больше нет.

**Остатки вынесены в P3-16** (устаревший sqlmap, ложный FAILED-gate).

---

## P3-9 — Веб-атаки (SQLi/brute-force) не видны на голых kernel-событиях

**Тип:** enhancement · **Приоритет:** P3 · **Метки:** `detection-coverage`, `collectors`
· **Статус:** ✅ DONE, ПОДТВЕРЖДЕНО ПРОГОНОМ

`net_high_frequency_connections` дал 61 новый алерт (sqlmap 23, docker-proxy 38) —
критерий приёмки «500 запросов из high_frequency должны давать аномалию частоты»
выполнен. Документация покрытия: [docs/l7-detection-coverage.md](docs/l7-detection-coverage.md).

---

# Новые задачи из прогона №2

## P1-10 — `/debug/state` отдаёт нули: провайдеры не подключены

**Тип:** bug · **Приоритет:** P1 · **Метки:** `api`, `observability`

**Проблема.** Финальный снимок `/debug/state` (18:34:04, uptime 405 с):

```json
"rules": [],
"engine_stats": {"total_events":0,"total_alerts":0,"dropped_events":0,"rules_loaded":0},
"profiler_stats": {"learning_complete":false,"learning_progress":0,"anomalies_total":0}
```

В ту же секунду метрики показывают 563k событий, 1871 алерт,
`ebpf_guard_learning_complete 1`, а журнал — `rules loaded count=586`.

**Причина.** `SetEngineProvider` / `SetProfilerProvider`
([debug.go:137-148](internal/exporter/debug.go#L137-L148)) **не вызываются нигде** из
`main.go` — ровно та же болезнь, что была у `SaveState` в P0-3. Обработчик молча отдаёт
нулевые структуры ([debug.go:211-217](internal/exporter/debug.go#L211-L217)).

**Последствие.** Тестовые скрипты читают именно `/debug/state` и получают ложную картину
«агент ничего не видит». Часть противоречий в FINAL-REPORT растёт отсюда.

**Что сделать.**
- Подключить оба провайдера в `main.go` рядом с `SetRulesProvider`
  ([main.go:805](cmd/ebpf-guard/main.go#L805)).
- Наполнить `rules` в debug-state (сейчас всегда пустой массив).
- Тест: после N событий `/debug/state` показывает `total_events > 0` и `rules_loaded == 586`.
- Профилактика класса ошибок: линт/тест, проверяющий, что все `Set*Provider` вызваны.

**Подтверждено idle-прогоном №3 — не починено.** Провайдеры так и не подключены:
`grep SetEngineProvider\|SetProfilerProvider cmd/` не даёт ни одного вызова (есть только
`SetRulesProvider` на [main.go:805](cmd/ebpf-guard/main.go#L805)). Во **всех 109 срезах**
`/debug/state` отдаёт те же нули, включая финальный на 9-м часу:
`total_events: 0, total_alerts: 0, rules_loaded: 0, rules: []`,
`learning_complete: false` — при том что метрики в ту же секунду показывают
43.4 млн событий, 35971 алерт и `ebpf_guard_learning_complete 1`.

**Критерий приёмки.** `/debug/state` согласован с `/metrics` по событиям, алертам,
числу правил и фазе обучения.

**Статус: ✅ СДЕЛАНО (исправлено при ревью).** Провайдеры подключены в
[main.go](cmd/ebpf-guard/main.go) рядом с `SetRulesProvider`, `rules` наполняются.
При ревью в первоначальной реализации найдены и исправлены три дефекта:

1. **Провайдер отдавал снимок, а не живые счётчики.** `EngineStatsAdapter` был
   структурой, в которую значения `engine.GetStats()` записывались **один раз** на
   старте — то есть в `/debug/state` навсегда уезжали нули, ровно тот же симптом,
   что и в исходной задаче. Заменено на `EngineStatsFunc`/`ProfilerStatsFunc` —
   функции-адаптеры, вызываемые на **каждый запрос**
   ([debug.go](internal/exporter/debug.go)).
2. **Не компилировалось: несовместимые типы.** `dbg.SetProfilerProvider(prof)`
   передавал `*profiler.Profiler`, чей `GetStats()` возвращает
   `profiler.ProfilerStats`, тогда как интерфейс `exporter.ProfilerProvider`
   требует `exporter.ProfilerStats` — разные типы, интерфейс не удовлетворялся.
   Добавлена явная конвертация.
3. **Не компилировалось: несуществующие константы.** Самописный
   `eventTypeToString` ссылался на `types.EventHTTP`, `EventKubeAudit`,
   `EventLSM`, `EventKmod`, `EventTLSFingerprint` — ни одной из них нет в
   [pkg/types/event.go](pkg/types/event.go). Функция удалена целиком в пользу
   канонического `EventType.String()`, который в этом файле прямо задокументирован
   как единственный источник истины для строковых меток.
4. **Правила не обновлялись при hot-reload** — `SetRules` вызывался только на
   старте, поэтому после перезагрузки правил `/debug/state` показывал стартовый
   набор. Добавлено обновление в обработчике hot-reload.

**Проверка прогоном №4: половина починена, половина — нет.**

`engine_stats` и `rules` **заработали** — в `debug-state-after.json` живые значения:
`total_events: 9402622`, `total_alerts: 4297`, `rules_loaded: 591`, массив `rules` длиной
591. Это ровно то, чего не было в 109 срезах idle-прогона. ✅

`profiler_stats` **по-прежнему отдаёт нули**, и это уже не «провайдер не подключён», а
рассинхрон с реальностью в ту же секунду:

```
/debug/state : "profiler_stats": {"learning_complete": false, "learning_progress": 0,
                                  "profiles_active": 0, "anomalies_total": 0}
/metrics     :  ebpf_guard_learning_complete 1   ebpf_guard_learning_progress 1
                ebpf_guard_anomalies_total 87
/api/v1/status: "learning_complete": true, "learning_progress": 1, "learning_samples": 1826675
журнал 18:00:14: profiler: learning complete samples=1826675
```

Три источника из четырёх согласны, что обучение завершено и аномалий 87 — а `/debug/state`
показывает необученный профайлер с нулём аномалий. Причём `anomalies_total` в P2-15
специально доводили до наполнения именно ради `/debug/state`.

**Гипотеза о причине (проверить).** Это тот же корень, что и в P0-3: `main.go` отдаёт
`ProfilerStatsFunc` тот `*profiler.Profiler`, который создан в `main`, а реально
работающие профайлеры — это per-worker детекторы `ce.ingestPool[i].ad` внутри движка
(engine.go:815-829). Провайдер честно опрашивает пустой объект. Если так, то P0-3 и этот
пункт чинятся одной правкой — агрегацией статистики по пулу на уровне движка.

**Дополнительно: `dropped_events` в двух источниках расходятся на порядок.**
`/debug/state` → `dropped_events: 103867`, `/metrics` → `events_dropped_total` суммарно
**1155880**. Это, судя по всему, разные счётчики (движок vs коллекторы), но наружу они
выходят под неразличимыми именами — оператор, глядящий на `/debug/state`, недооценит
потерю событий в 11 раз. Нужно либо развести имена (`engine_dropped` vs
`collector_dropped`), либо отдавать оба. См. также новую задачу P0-25.

**Статус: ⚠️ ЧАСТИЧНО** — `engine_stats`/`rules` сделаны, `profiler_stats` нет,
критерий приёмки («`/debug/state` согласован с `/metrics` по … фазе обучения») не выполнен.

---

## P1-11 — Cardinality explosion в `ebpf_guard_profiler_anomaly_score`

**Тип:** bug · **Приоритет:** P1 · **Метки:** `metrics`, `performance`, `cardinality`

**Проблема.** Гейдж экспонируется **per-PID** и мёртвые PID никогда не удаляются:

- baseline: 0 серий (обучение не завершено) → final: **3601 серия** за 6 минут;
- `/metrics` вырос с 26 КБ до 247 КБ, 90% payload — эта одна метрика;
- часть серий с пустым лейблом: `ebpf_guard_profiler_anomaly_score{comm="",pid="653377"} 0`;
- большинство значений — 0 (бесполезны).

Cardinality guard экспортера на эту метрику не распространяется.

**Что сделать.**
- Удалять серию при завершении PID (hook на exit / TTL по последнему обновлению).
- Не экспонировать нулевые/подпороговые значения; либо заменить per-PID гейдж на
  гистограмму распределения score + top-N по `comm`.
- Не публиковать серии с пустым `comm`.
- Прогнать под cardinality guard, добавить тест на верхнюю границу числа серий.

**Idle-прогон №3: главное опасение снято, остаток — косметика.** Прогноз «десятки тысяч
серий за час» **не подтвердился**: за 9 часов число серий вышло на плато
264 → 619 (максимум 701 по 109 срезам), `/metrics` вырос 26 КБ → 71 КБ и дальше не рос.
Утечки серий по мёртвым PID нет.

**Что осталось.** 367 из 660 серий (**56%**) по-прежнему с пустым `comm`:
`ebpf_guard_profiler_anomaly_score{comm="",pid="..."}`. Пункт «не публиковать серии с
пустым `comm`» не сделан; он же уполовинит текущую cardinality. Приоритет можно снизить
до P2.

**Критерий приёмки.** За час работы на активном хосте число серий метрики ограничено
сверху (например ≤ 500) и размер `/metrics` не растёт монотонно.
На idle: ✅ плато ~660; серий с пустым `comm` — ноль (не выполнено).

**Прогон №4: плато не подтвердилось на активном хосте — приоритет назад до P1.**
Именно этот критерий («за час на **активном** хосте ≤500 серий») и проверялся впервые:
idle-плато ~660 было получено на хосте без нагрузки, где новые PID почти не появляются.

| Момент | Серий `profiler_anomaly_score` | Всего серий в `/metrics` | Размер `/metrics` |
|---|---|---|---|
| baseline 18:09:52 (после 2 ч работы) | **1282** | 1480 | 107 КБ |
| final 18:21:33 (+11.5 мин атаки) | **6319** | 6524 | **414 КБ** |

За 11.5 минут число серий выросло в **4.9 раза**, `/metrics` — с 107 КБ до 414 КБ, и 97%
payload — снова эта одна метрика. Плато нет: атака порождает много короткоживущих PID
(sqlmap, curl, форки shell), серия на каждый создаётся и **не удаляется после смерти
процесса** — исходный диагноз задачи («мёртвые PID никогда не удаляются») подтверждён
именно на том профиле нагрузки, где он и должен был проявиться.

Экстраполяция: 5000 серий за 11.5 мин ≈ 26 тыс./час под нагрузкой — то есть прогноз
«десятки тысяч за час», снятый по итогам idle-прогона, был снят **преждевременно**.
Cardinality guard (`AnomalyScoreGuard`, тот самый, что чинили в P0-24) на этой метрике
либо не ограничивает, либо имеет лимит существенно выше 6319 — проверить его фактический
`max_series` и то, что `evictLowest` реально вызывается.

**Пустой `comm` — 2380 из 6319 (37%)**, пункт по-прежнему не сделан (было 56% на idle).

**Уточнённый критерий приёмки.** Число серий ограничено сверху **на attack-прогоне**
(а не только на idle), размер `/metrics` за 10 минут атаки растёт не более чем в 1.5 раза,
серий с пустым `comm` — ноль. **Статус: ❌ регресс относительно вывода idle-прогона.**

---

## P2-12 — Правила `*_write` / `*_modified` срабатывают на open, а не на write

**Тип:** bug / detection-quality · **Приоритет:** P2 · **Метки:** `rules`, `false-positive`

**Проблема.** В конфиге стенда fileaccess-коллектор трекает **только open**
(`track_open=true, track_read=false, track_write=false` — журнал 18:27:18), при этом летят
правила, семантически заявляющие запись/модификацию:

| Правило | Новых | От кого |
|---|---|---|
| `fim_passwd_write` (critical) | 30 | cron, sshd |
| `rootkit_passwd_modified` (critical) | 30 | cron, sshd |
| `fim_shadow_write` (critical) | 10 | cron 5, sshd 5 |
| `mitre_nsswitch_modified` | 29 | curl |
| `fim_resolv_conf_modified` | 29 | curl |
| `container_escape_proc_write` | 47 | irqbalance 36 |

`curl`, открывающий `/etc/resolv.conf` и `/etc/nsswitch.conf` для резолвинга, помечается
как «модификация nsswitch» — это чистый critical-FP и системный источник шума из P1-6.

**Что сделать.**
- Проверять флаги открытия (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`) в условии правил, а
  не только путь; при отсутствии информации о флагах — не эмитить `*_write`/`*_modified`.
- Либо требовать реальных write-событий (`track_write`) для этого класса правил и явно
  логировать при старте, что правила отключены из-за конфигурации коллектора.

**Idle-прогон №3: подтверждено, это главный драйвер ночного шума.** Ровно тот же
сценарий с `curl` воспроизвёлся 382 раза за 9 часов простоя — `curl`, опрашивающий API
агента, открывает `/etc/resolv.conf` и `/etc/nsswitch.conf` для резолвинга и получает
`fim_resolv_conf_modified` 382 + `mitre_nsswitch_modified` 382, которые затем
складываются в 218 «подтверждённых атак» (P1-13). Счётчики за idle-окно:

| Правило | Алертов за 9 ч idle | От кого |
|---|---|---|
| `container_escape_proc_write` | 3672 | irqbalance 3229 |
| `sigma_sensitive_file_chmod` (critical) | 1860 | sshd 988 |
| `fim_passwd_write` (critical) | 990 | cron, sshd |
| `rootkit_passwd_modified` (critical) | 1016 | cron, sshd |
| `mitre_nsswitch_modified` | 382 | curl |
| `fim_resolv_conf_modified` | 382 | curl |
| `fim_shadow_write` (critical) | 320 | cron, sshd |
| `fim_group_write` (critical) | 403 | cron, sshd |

Конфигурация коллектора та же (`track_open=true`, write не трекается), так что все эти
`*_write`/`*_modified` — заведомо о фактах открытия, а не записи.

**Критерий приёмки.** `curl`, читающий `/etc/resolv.conf`, не порождает
`fim_resolv_conf_modified`. Ни одно `*_write`-правило не срабатывает на read-only open.

**Статус: ✅ СДЕЛАНО.**

1. Все 13 `*_write`/`*_modified`-правил переведены на
   `condition_group: op eq write AND <путь>` — проверено по каталогу.
2. **Критерий приёмки закреплён тестом с двух сторон**
   ([stage1_detection_integrity_test.go](internal/correlator/stage1_detection_integrity_test.go)):
   read-only open пути **не** поднимает правило, а реальный write по тому же
   пути — поднимает. Второе важнее первого: без него «починка» деградирует в
   отключение правила, и это было бы незаметно.
3. **Добавлен недостающий пункт задачи — предупреждение при старте.** Правила
   с `op: write` не могут сработать, пока `collectors.file_ops.track_write`
   равен `false` (а это **значение по умолчанию**,
   [config.go:2098](internal/config/config.go#L2098)). Теперь агент на старте
   логирует WARN со списком и числом обездвиженных правил
   (`correlator.RulesRequiringFileOp`, вызывается в
   [main.go](cmd/ebpf-guard/main.go)). Иначе оператор видит тишину и считает,
   что FIM работает, тогда как весь класс правил просто выключен конфигурацией
   коллектора.

**Что осталось.** Прогон с `track_write: true` — убедиться, что легитимные
write-операции sshd/cron не восстанавливают прежний объём шума. Если
восстановят, точечные exceptions делать по паре «путь + признак легитимности»,
а не по одному `comm` (см. дефект, найденный в P1-17).

---

## P1-13 — Ложные «подтверждённые атаки»: 30% под атакой, 100% на idle

**Тип:** bug / detection-quality · **Приоритет:** P1 · **Метки:** `correlation`, `false-positive`

**Проблема.** Из 60 новых `incident_confirmed_attack` (critical):

- **42 — истинные**: curl 32, sqlmap 8, docker-proxy 2 (реальные атакующие процессы);
- **18 — ложные**: sshd 8, cron 7, grafana / ps / сам ebpf-guard по 1.

Более того, **12 `incident_confirmed_attack` были уже в baseline** — то есть за 25 секунд
простоя, до начала любых атак, агент уже «подтвердил» 12 атак. Скоринг набирает порог на
шумовых алертах из P1-6/P2-12: у sshd/cron легко набирается 4 правила из 3+ тактик
(`rootkit_pam_module_added` + `sigma_utmp_wtmp_modified` + `fim_shadow_write` + …).

**Idle-прогон №3: подтверждено и на порядок хуже — 1768 ложных «подтверждённых атак»
за 9 часов при нулевой атакующей активности.** Метрика:
`ebpf_guard_incidents_total{verdict="attack"} 1782`, `{verdict="suspicious"} 2878`.
Точность вердикта `attack` на idle — **0%**.

Механика FP видна насквозь. 68 различных сигнатур инцидентов, топ-3:

```
264×  appexploit_lfi_passwd_access + drift_new_library_in_system_dir +
      rootkit_pam_module_added + sigma_failed_login_syscall + sigma_sensitive_file_chmod   (sshd)
218×  appexploit_lfi_passwd_access + appexploit_xxe_file_read + fim_passwd_write +
      fim_resolv_conf_modified + mitre_nsswitch_modified                                   (curl)
192×  exfil_db_nonstandard_port_connect + exfil_outbound_high_port +
      exfil_repeated_outbound_to_same_ip + netintr_loopback_high_port +
      netintr_ssh_non_standard_port                                                        (curl → localhost)
```

Показательный случай: **обычный `curl` к API самого агента** читает `/etc/resolv.conf`,
`/etc/nsswitch.conf` и `/etc/passwd` при резолвинге — и получает вердикт
`Confirmed attack: 5 alerts from 5 rules across 4 MITRE tactics (credential-access,
impact, initial-access, privilege-escalation) ... (score 59.0)`. Скрипт мониторинга
опрашивал API раз в 5 минут и тем самым сгенерировал сотни «подтверждённых атак».

Распределение `alert_count`: 1474 инцидента из 1768 состоят ровно из **5** алертов,
score 50–59 у 1371 из них — то есть порог берётся «впритык» на фиксированном наборе
шумовых правил, а не на реальном разнообразии сигнала.

**Что сделать (уточнено).**
- Не учитывать в скоринге алерты от процессов из allowlist (P1-6) — это, судя по
  сигнатурам, убирает большую часть 1768 FP механически.
- Поднять требования к вердикту `attack`: требовать ≥1 алерт от неизвестного/недоверенного
  бинаря, либо сетевой сигнал, либо более высокий порог по score.
- Резать инциденты, где все N алертов порождены **одним событием** (у 218×-сигнатуры
  все пять алертов имеют один и тот же timestamp с точностью до микросекунд и один PID) —
  это не цепочка атаки, а одно чтение файла, размноженное перекрывающимися правилами (P2-14).
- Отдельно проверить вклад правил из P2-12 — вероятно, после их починки FP уйдут сами.

**Критерий приёмки.** На idle-хосте за 10 мин — ноль `incident_confirmed_attack`.

**Прогон №4: критерий провален, точность вердикта на атаке — 0%.**

Baseline прогона №4 — это 2 часа работы **до начала атак** (16:08 → 18:09). За это время
агент выдал **570 `incident_confirmed_attack`** (≈285/час) при полном отсутствии атакующей
активности. Критерий «за 10 мин ноль» провален примерно в 47 раз.

Под атакой — 114 новых инцидентов. Разбор по `comm` **всех 114**:

| comm инцидента | шт |
|---|---|
| `""` (пусто) | **114** |

Инцидент **не наследует `comm`** от породивших его алертов — поле пустое во всех 114
(и во всех 570 baseline). Это отдельный дефект: оператор видит `Confirmed attack: 5 alerts
… (score 59.0)` без единого указания на процесс. Восстановить источник можно только
разбором `details.alert_ids`. Сделав это, получаем состав:

| Реальный источник (по alert_ids) | Инцидентов | Это атака? |
|---|---|---|
| `sshd` (файловые чтения при логине) | большинство | ❌ нет |
| прочие системные | остаток | ❌ нет |

Топ-сигнатуры новых инцидентов — **ни одной сетевой, ни одного атакующего процесса**:

```
31×  appexploit_lfi_passwd_access + appexploit_xxe_file_read +
     owasp_web_sensitive_file_read + sigma_passwd_shadow_read + sigma_sensitive_file_chmod
12×  appexploit_lfi_passwd_access + appexploit_xxe_file_read +
     owasp_web_sensitive_file_read + sigma_passwd_shadow_read + webshell_sensitive_file_read
12×  appexploit_lfi_passwd_access + appexploit_xxe_file_read +
     owasp_web_sensitive_file_read + sigma_sensitive_file_chmod + webshell_sensitive_file_read
```

Это `sshd`, читающий `/etc/passwd`/`/etc/shadow` при аутентификации, размноженный пятью
перекрывающимися правилами. Распределение `alert_count`: **102 из 114 состоят ровно из 5
алертов**, score 59 у 77 из них — тот же «впритык взятый порог на фиксированном наборе
шумовых правил», что и на idle, с точностью до конкретных правил.

**Новое и важное: пока агент выдавал 114 «подтверждённых атак» на sshd, реальная атака
инцидентом не стала ни разу.** sqlmap (283 алерта), curl (167), docker-proxy (402) дали
`net_portscan_indicator` 80, `c2_periodic_beacon_pattern` 79, `beacon_fixed_interval` 79,
`webshell_ssrf_internal_network` 77 — сигнал есть, инцидент по ним **не собрался**.
То есть корреляция не просто шумит — она шумит на легитимном и молчит на атакующем.
Причина, вероятно, общая с P0-1: группировка идёт по одному PID, а атакующий трафик
размазан по множеству короткоживущих PID (sqlmap форкает), тогда как sshd стабильно
держит один PID и потому легко набирает порог.

**Дополнить «что сделать».**
- Наполнять `comm`/`process_chain` в самом инциденте (сейчас пусто во всех 684) — без
  этого инцидент невозможно триажить, и метрика точности не считается автоматически.
- Проверить обратную сторону: почему набор из `portscan + beacon + ssrf + high_frequency`
  от одного sqlmap **не** даёт вердикта, хотя это учебный пример атаки. Возможно, порог
  берётся по числу *разных правил на один PID*, а не по значимости правил.

**Уточнённый критерий приёмки.** (1) На idle за 10 мин — ноль `incident_confirmed_attack`;
(2) **на attack-прогоне ≥1 инцидент указывает на реальный атакующий процесс** (sqlmap/curl/
docker-proxy), и доля инцидентов на системных демонах < 20%. Сейчас: 0% и 100%.

---

## P2-14 — Низкая специфичность сетевых правил: один connect = 7 алертов

**Тип:** detection-quality · **Приоритет:** P2 · **Метки:** `rules`, `alert-fatigue`
· **Статус:** ✅ СДЕЛАНО

**Проблема.** Одно TCP-соединение на `localhost:3000` поднимает семь правил
одновременно, все ровно по 66 новых алертов:

```
webshell_network_connection_web_proc  66
supply_chain_cicd_runner_network      66
owasp_web_ssrf_outbound               66
netintr_ssh_non_standard_port         66
net_portscan_indicator                66
exfil_repeated_outbound_to_same_ip    66
exfil_db_nonstandard_port_connect     66
```

Атака видна, но классификация мусорная: обращение к веб-порту 3000 названо
«SSH на нестандартном порту», «подключение к БД на нестандартном порту» и
«сеть CI/CD-раннера» одновременно. Аналитик получает 7 разных гипотез на одно событие.

**Что сделать.**
- Пересмотреть условия: `netintr_ssh_non_standard_port` не должен срабатывать без
  признаков SSH; `exfil_db_nonstandard_port_connect` — без признаков БД-порта/протокола.
- Ввести приоритет/дедупликацию перекрывающихся сетевых правил (одно событие → одно
  наиболее специфичное правило + остальные как контекст в details).
- Учитывать loopback отдельно: `::1`/`127.0.0.1` — не «исходящий exfil».

**Idle-прогон №3: подтверждено на трафике мониторинга.** Обычный `curl` к
`localhost:19090` (health-check самого стенда) поднимает тот же веер правил —
`webshell_network_connection_web_proc` 327, `exfil_db_nonstandard_port_connect` 327,
`netintr_ssh_non_standard_port` 383, `owasp_web_ssrf_outbound`, `net_portscan_indicator`,
`webshell_outbound_high_port`, `exfil_repeated_outbound_to_same_ip`. Пять из них
складываются в 192 инцидента «подтверждённая атака» (P1-13).

Особенно наглядно: `curl` назван «apache/nginx/httpd worker initiated outbound TCP —
reverse shell», «SSH на нестандартном порту» и «подключение к БД на нестандартном порту»
одновременно — для одного localhost-запроса к порту 19090. Пункт «loopback — не exfil»
подтверждается как обязательный.

**Критерий приёмки.** Одно TCP-соединение порождает ≤2 алерта; loopback-соединения не
классифицируются как exfiltration.

**Сделано.** Семь правил из таблицы выше исправлены в `rules/`:

1. **Loopback исключён у всех семи правил** (`daddr not_in_cidr 127.0.0.0/8, ::1/128`):
   `exfil_db_nonstandard_port_connect`, `exfil_repeated_outbound_to_same_ip`,
   `net_portscan_indicator`, `netintr_ssh_non_standard_port`, `owasp_web_ssrf_outbound`,
   `supply_chain_cicd_runner_network`, `webshell_network_connection_web_proc`,
   `webshell_outbound_high_port` — это одно и то же напрямую снимает наблюдавшийся
   в idle-прогоне кейс `curl → localhost:19090`.
2. **Добавлена специфичность по процессу** там, где правило называет конкретную роль,
   но раньше матчило вообще любой процесс:
   - `netintr_ssh_non_standard_port` теперь требует `proc.comm in [ssh, sshd]` —
     раньше срабатывал на любое соединение с портом ≠22/2222 от кого угодно.
   - `owasp_web_ssrf_outbound`, `webshell_network_connection_web_proc`,
     `webshell_outbound_high_port` теперь требуют `proc.comm` из списка веб-процессов
     (`nginx, apache2, httpd, php-fpm, node, python, gunicorn, uwsgi, java, tomcat`) —
     раньше срабатывали на любой процесс, хотя название и описание заявляли
     «web server process».
   - `supply_chain_cicd_runner_network` теперь требует `proc.comm` из списка CI/CD
     раннеров (`actions-runner, gitlab-runner, drone-runner, tekton, jenkins-agent,
     buildkite-agent`).
   - `exfil_db_nonstandard_port_connect` теперь требует `proc.comm in [mysqld,
     postgres, mongod, redis-server]` — раньше срабатывал на любой процесс с
     «нестандартным» портом назначения.
3. `net_portscan_indicator` и `exfil_repeated_outbound_to_same_ip` уже имели
   осмысленные условия (длительность/повтор + список comm-исключений) — им
   потребовалось только исключение loopback.
4. Полный `rules/`-каталог по-прежнему грузится чисто: `LoadRulesFromDir` → 586
   правил (то же число, что и до правки), проверено тестом на реальном каталоге
   `rules/` — новых полей условий с опечаткой быть не должно, но неизвестные `field`
   отклоняются на этапе загрузки, так что тест это же и подтверждает.

**Ревью нашло два пропущенных правила — исправлено.** Список из семи правил был
неполон: на loopback-соединение `curl → 127.0.0.1:19090` продолжали срабатывать
ещё два, оба с семантикой «наружу»:

- `exfil_outbound_high_port` — «данные уходят на внешний VPS», при этом на
  loopback данные хост не покидают вовсе;
- `owasp_reverse_shell_pattern` — в описании прямо сказано «connecting to
  **external** IP», но условие проверяло только `dport > 10000` и адрес не
  смотрело.

Обоим добавлено `daddr not_in_cidr [127.0.0.0/8, ::1/128]`. `netintr_loopback_high_port`
оставлен как есть — это единственное правило, которое про loopback и должно быть.
После правки критерий приёмки выполняется: одно loopback-соединение → **≤2 алерта**,
ни один из них не exfil-класса.

**Критерий приёмки закреплён тестами**
([stage1_detection_integrity_test.go](internal/correlator/stage1_detection_integrity_test.go)):
`TestStage1_LoopbackNotExfiltration` (loopback не exfil, ≤2 алерта на соединение) и
`TestStage1_NetworkRuleSpecificity` (`curl` больше не объявляется ssh-клиентом,
веб-сервером, CI-раннером и СУБД одновременно).

**Что осталось.** Приоритет/дедупликация перекрывающихся сетевых правил (одно
событие → одно наиболее специфичное правило + остальные как контекст в details) не
реализована — с добавленной специфичностью пересечения по одному и тому же событию
должны стать значительно реже (правила теперь не пересекаются по любому не-loopback
соединению без разбора), но общий механизм приоритезации/дедупликации в движке
корреляции не добавлялся. Требует повторного прогона (атака + idle) для
подтверждения снижения числа правил на одно соединение до ≤2 на живом трафике.

---

## P2-15 — Нет метрики `ebpf_guard_anomalies_total` и лога завершения обучения

**Тип:** bug / enhancement · **Приоритет:** P2 · **Метки:** `metrics`, `profiler`, `observability`

**Проблема.**
1. Метрики `ebpf_guard_anomalies_total` не существует ни в baseline, ни в final —
   отсюда «Anomalies Total: 0» в отчёте, хотя аномалии реально были (12 алертов
   `anomaly_detection`, score до 1.0 у bash/sqlmap).
2. Ни в одном из двух запусков нет лога о **завершении** обучения: прогресс логируется
   `20% → 40% → 60% → 80%` и обрывается, хотя метрика переключается в
   `learning_complete 1`. Оператор не видит момента перехода в рабочую фазу.

**Idle-прогон №3: оба пункта подтверждены, не починены.** В `metrics-end.txt` за 9 часов
строк с `anomalies_total` — **0**. В журнале за 9 часов `learning complete` — **0**
вхождений; прогресс, как и раньше, логируется `20% → 40% → 60% → 80%` и обрывается
(всего 4 строки), хотя `ebpf_guard_learning_complete` переключился в 1. Момент перехода
в рабочую фазу оператор по журналу увидеть по-прежнему не может.

**Что сделать.**
- Добавить counter `ebpf_guard_anomalies_total` (и/или по типам аномалий).
- Логировать `profiler: learning complete (N samples, D elapsed)` на INFO.
- Синхронизировать имена метрик с тем, что грепает отчётный скрипт (P2-7).

**Статус: ✅ СДЕЛАНО.** Оба пункта закрыты, замечаний при ревью нет.

1. Counter `ebpf_guard_anomalies_total` добавлен
   ([prometheus.go](internal/exporter/prometheus.go)), инкремент — в `dispatchAlerts`
   рядом с `RecordAlert`, то есть на **неагрегированном** потоке алертов: счётчик
   не задваивается агрегатором и учитывает ровно те аномалии, что прошли
   dedup/rate-limit.
2. `profiler: learning complete` логируется на INFO с числом сэмплов и elapsed
   ([baseline.go](internal/profiler/baseline.go)). Строка эмитится **ровно один
   раз**: под write-lock стоит повторная проверка `if !bl.learningComplete`, иначе
   при вызове `IsLearningComplete()` на горячем пути лог бы дублировался.
   Покрыто тестами ([baseline_logging_test.go](internal/profiler/baseline_logging_test.go)):
   единственная строка при переходе, отсутствие дублей при повторных вызовах и
   при 32 конкурентных читателях.

Дополнительно `ProfilerStats.AnomaliesTotal` теперь наполняется реальными данными
(`Profiler.GetStats`, [profiler.go](internal/profiler/profiler.go)) и виден в
`/debug/state` — это же значение раньше грепал отчётный скрипт (P2-7).

---

## P3-16 — Остатки по скриптам атак: устаревший sqlmap и ложный gate

**Тип:** bug (tooling) · **Приоритет:** P3 · **Метки:** `tooling`, `testing`

**Проблема.**
1. sqlmap 1.6.4 — во всех шести прогонах `[WARNING] your sqlmap version is outdated`.
   Атаки 1–3 не дали инъекций: login отдал 401 (нет авторизации в запросе), Juice Shop
   задетектился как «WAF/IPS». То есть SQLi по факту **не доставлены**.
2. Gate противоречит сам себе: секция LDAP/CSRF печатает
   `GATE: FAILED — файлы с 0 попытками: csrf_enumeration_...txt`, а итоговый
   `ATTACK TRAFFIC GATE: OK`. Итоговый gate не учитывает провал под-гейтов.
3. Счётчик попыток в `csrf_enumeration` ложно даёт 0 — файл реально содержит ответы
   `HTTP/1.1 500 Internal Server Error`, просто паттерн подсчёта не матчит код 500.

**Что сделать.**
- Обновить sqlmap; для login-эндпоинта передавать валидные креды/`--ignore-code 401`.
- Итоговый gate должен падать, если упал любой под-gate.
- Считать попытки по числу HTTP-ответов любого кода, а не по списку «успешных».

**Критерий приёмки.** Все под-гейты зелёные, итоговый gate честно отражает их сумму,
sqlmap выполняет хотя бы один успешный инъекционный тест.

**Статус: ✅ СДЕЛАНО (этап 0.5).**

1. `--ignore-code=401` добавлен в `attack_login_blind` и `attack_time_based`: Juice Shop
   отдаёт 401 на любой неверный пароль, из-за чего sqlmap считал каждую пробу общей
   неудачей и не подтверждал инъекцию. Проверка версии (`>= 1.7`) с подсказкой по
   обновлению уже была в скрипте.
2. Итоговый gate собирает статус всех четырёх под-скриптов из их `summary-*.txt` и
   падает, если упал любой. Тело `generate_final_report` выполняется в subshell
   (`{ ... } | tee`), поэтому обычная переменная не пережила бы выход из pipeline —
   провал передаётся через флаг-файл, а `check_final_gate` завершает `full_run` с
   ненулевым кодом. Раньше exit code был 0 всегда, и CI не видел провала.
3. Счёт попыток в `ldap-csrf-attacks.sh` расширен на формат `HTTP/1.1 <код> <причина>`:
   `attack_csrf_enumeration` использует `curl -D -` и пишет сырые заголовки, которые не
   матчились шаблоном `: [0-9]{3}$`, поэтому ответы 500 давали ложный 0.

---

# Новые задачи из idle-прогона №3

## P1-17 — Агент алертит на самого себя: 6293 алерта за ночь, включая свои же canary

**Тип:** bug / detection-quality · **Приоритет:** P1 · **Метки:** `false-positive`,
`rules`, `self-monitoring`

**Проблема.** 18% всего ночного шума (6293 из 35619) — алерты, где `comm == "ebpf-guard"`,
то есть агент детектирует собственную работу как атаку:

| Правило | Алертов | Что на самом деле делает агент |
|---|---|---|
| `sigma_cpu_info_access` | 1554 | читает `/proc/cpuinfo` для hardware profile / watchdog |
| `cred_proc_maps_mass_read` | 1439 | сканирует `/proc/*/maps` (integrity scan) |
| `canary_001` … `canary_005` | **903** | **проверяет собственные canary-файлы** |
| `mitre_sandbox_detect_proc_read` | 478 | читает `/proc/*` |
| `container_escape_init_proc` | 475 | читает `/proc/1/*` |
| `owasp_web_sensitive_file_read` | 268 | читает `/etc/*` |
| `sigma_sensitive_file_chmod` | 228 | выставляет права на canary/state-файлы |
| `sigma_sensitive_dir_listing`, `drift_new_file_dir_sensitive` | 360 | создаёт canary-файлы |

**Самый серьёзный подпункт — ложные canary.** Canary-ловушки задуманы как
high-confidence индикатор («no legitimate process should read this file»), но **100% из
903 срабатываний — это сам агент**, а не атакующий:

```
canary_001 ... comm: "ebpf-guard", pid: 658043
"A process accessed the canary trap file /etc/shadow.canary.
 This is a high-confidence indicator of attacker reconnaissance —
 no legitimate process should read this file."
```

Причина: верификатор `internal/canary/canary.go` раз в
`canary.verify_interval` (дефолт 60 с, [config.go:2203](internal/config/config.go#L2203))
читает/статит canary-файлы, а fileaccess-коллектор видит это как доступ и поднимает
правило. Ловушка ловит собственного сторожа. Именно это обесценивает самый
высокоточный детектор в продукте: в реальном инциденте настоящее срабатывание canary
утонет среди сотен своих.

**Что сделать.**
- Исключить PID самого агента из правил на `/proc/*`, `/etc/*` и canary целиком —
  расширить существующий механизм exceptions (`exception_name="ebpf-guard-self"`,
  который уже работает для `sigma_memory_proc_dump`) на весь класс.
- Для canary — исключение по PID агента обязательно на уровне матчинга событий, а не
  фильтрацией постфактум; либо верифицировать целостность по метаданным без открытия
  файла (`stat` вместо `open`), либо помечать собственные операции флагом в BPF-карте.
- Добавить регресс-тест: на idle-хосте `comm == "ebpf-guard"` не должен порождать ни
  одного алерта.

**Критерий приёмки.** За 1 час idle ноль алертов с `comm == "ebpf-guard"`; правила
`canary_*` срабатывают только на посторонние процессы.

**Статус: ✅ СДЕЛАНО (требуется подтверждающий idle-прогон).**

1. **Canary — исключение по PID, а не по comm.** `Manager` захватывает
   `os.Getpid()` при инициализации ([canary.go](internal/canary/canary.go)) и
   выдаёт каждому `canary_*`-правилу exception `ebpf-guard-self` с условием
   `pid == <PID агента>`. Это строго сильнее comm-фильтра: подделать comm
   тривиально (`prctl(PR_SET_NAME)`), PID агента — нет. Для этого в
   `getFieldValue` добавлено поле `pid` для file- и syscall-событий, и оно
   же внесено в `validFileFields`/`validSyscallFields`.
2. **Остальные правила — exception по паре `comm + путь`, никогда по одному
   comm.** Восемь правил (`sigma_cpu_info_access`, `cred_proc_maps_mass_read`,
   `mitre_sandbox_detect_proc_read`, `container_escape_init_proc`,
   `owasp_web_sensitive_file_read`, `sigma_sensitive_file_chmod`,
   `sigma_sensitive_dir_listing`, `drift_new_file_dir_sensitive`) получили
   `condition_group` вида `proc.comm == ebpf-guard AND <конкретный путь>`.
   Путь в каждом случае — ровно то, что агент реально трогает
   (`*.canary`, `/proc/cpuinfo|meminfo|version`, `/proc/<pid>/maps`,
   `/proc/self/cgroup`, `/proc/1/cgroup|stat|status`), а атакующие примитивы
   на тех же правилах остаются видимыми: `/etc/shadow`, `/etc/sudoers`,
   `/proc/<pid>/mem`, `/proc/1/environ`, `/etc/cron.d/*`.
3. **Ревью исходной правки нашло два дефекта, оба исправлены:**
   - *Все восемь exceptions были привязаны только к `comm`* — процесс,
     переименовавший себя в `ebpf-guard`, становился полностью невидимым на
     `/etc/shadow` и `/root/.ssh/`. Заменено на пары `comm + путь` (п. 2).
     Тем же способом сужены и exceptions из P1-6: `irqbalance` теперь
     ограничен `/proc/irq/`, `prometheus` — метаданными `/proc/1/`.
   - *Оба новых тест-файла не компилировались* и молча не запускались:
     тег `// +build !windows` без парного `//go:build` игнорируется Go 1.17+
     только при наличии второй строки, а внутри были вызовы
     `NewRuleEngineWithCache(nil, rules)` с перепутанными аргументами и
     несуществующий `mgr.Files()`. Тесты переписаны, тег снят (логика чисто
     userspace, eBPF не нужен), теперь реально исполняются.
4. **Регресс-тест усилен до трёх утверждений** на каждое правило
   ([p1_17_self_exclusion_test.go](internal/correlator/p1_17_self_exclusion_test.go)):
   (1) свой доступ подавлен, (2) тот же доступ от чужого процесса **по-прежнему
   алертит**, (3) процесс с подделанным `comm == ebpf-guard` **не получает
   невидимости** на атакующем пути. Третий пункт машинно запрещает вернуться к
   comm-only exception.

**Прогон №4: canary починены полностью, остальное — нет. Статус ⚠️ ЧАСТИЧНО.**

✅ **Главный подпункт закрыт.** `canary_001..005` — **ноль** срабатываний и на 2-часовом
idle-baseline, и под атакой (было 903 за ночь, 100% на самого агента). Исключение по PID
работает; самый высокоточный детектор продукта перестал ловить собственного сторожа.
`ebpf_guard_rule_exceptions_total` вырос 2676 → 3720 за прогон — механизм активен.

❌ **Критерий приёмки («за 1 час idle ноль алертов с `comm == ebpf-guard`») не выполнен.**

| Правило | idle-baseline (2 ч) | под атакой (11.5 мин) |
|---|---|---|
| `cred_proc_maps_mass_read` | — | 79 |
| `mitre_sandbox_detect_proc_read` | — | 68 |
| `supply_chain_pkg_tmp_staging` | — | 6 |
| `sigma_binary_in_tmp_executed` | — | 6 |
| `privesc_suid_suspicious_path` | — | 6 |
| **Всего `comm == ebpf-guard`** | **1220 (13% baseline)** | **165** |

`cred_proc_maps_mass_read` и `mitre_sandbox_detect_proc_read` — ровно те два правила из
списка п.2, которым добавляли `condition_group` «`comm == ebpf-guard` AND конкретный путь».
Они продолжают срабатывать, то есть агент читает **не те пути**, что перечислены в
exception (например `/proc/<pid>/maps` других процессов при integrity-скане, а не только
`/proc/self/`). Нужно снять фактические пути из алертов и расширить условие по ним —
но по-прежнему парой «comm + путь», не одним comm.

**Новое (в задаче не было): три правила, которых нет в исходной таблице** —
`supply_chain_pkg_tmp_staging`, `sigma_binary_in_tmp_executed`, `privesc_suid_suspicious_path`
(по 6 алертов). Агент что-то делает в `/tmp` (вероятно временные файлы стора/экспорта) и
детектит это как staging пакетов и запуск бинаря из `/tmp`. Их надо добавить в тот же
класс exceptions.

**Замечание по методу.** Регресс-тест из п.4 зелёный, а на стенде — 1220 алертов за 2 часа.
Тест проверяет пути, которые *записаны в exception*; он по построению не может обнаружить
путь, который агент трогает, но в exception не внесён. Нужен тест противоположного знака:
прогнать реальный набор путей, которые агент открывает за N минут работы (снять
`strace`/собственным коллектором), и убедиться, что ни один не поднимает правило.

---

## P1-18 — CPU-watchdog осциллирует всю ночь: 813 циклов reduce↔recover, по одному каждые 40 с

**Тип:** bug · **Приоритет:** P1 · **Метки:** `watchdog`, `performance`, `sampling`
· **Разделена на [P1-18a](#p1-18a--разорвать-контур-обратной-связи-в-watchdog) (симптом, Go)
и [P1-18b](#p1-18b--сократить-объём-file-событий-фильтрацией-путей-в-ядре) (первопричина, BPF)**

**Проблема.** На полностью простаивающем хосте агент 813 раз за ночь снизил и 814 раз
восстановил сэмплинг. Журнал за 9 часов на **99% состоит из этих двух сообщений**
(1626 строк из 1787):

```
19:32:23 WARN cpu pressure: reducing file sampling   cpu_pct=50.2% threshold=40.0%
19:32:53 INFO cpu pressure: recovered — restoring…   cpu_pct=1.3%  threshold=20.0%
19:33:08 WARN cpu pressure: reducing file sampling   cpu_pct=50.6% threshold=40.0%
19:33:38 INFO cpu pressure: recovered — restoring…   cpu_pct=1.2%  threshold=20.0%
```

Медианный период цикла — ровно **40 секунд**, всю ночь без исключений.
Распределение `cpu_pct`: в момент reduce — min 40.2 / p50 **50.0** / max 64.8;
в момент recover — min 0.3 / p50 **1.1** / max 6.0.

**Разбор.** Это не «дребезг вокруг порога», гистерезис как раз настроен
(shed 40%, recovery 20%, [cpu.go:150-162](internal/watchdog/cpu.go#L150-L162)). Прыжок
50% → 1.1% означает, что **шеддинг файлового сэмплинга сам по себе и есть причина
падения CPU**: агент грузит ядро собственной обработкой file-событий, снижение
`file_rate` до 0.1 мгновенно роняет нагрузку в пол, watchdog видит 1% и восстанавливает
сэмплинг — и через `minDwell` всё повторяется. Классический контур с положительной
обратной связью: регулятор управляет тем же сигналом, который измеряет.

**Первопричина — объём file-событий.** `ebpf_guard_events_total{type="file"}` =
**43.4 млн за 9 часов простоя** (~1340 событий/с), против 12084 syscall, 778 network и
355 dns за то же время. Файловый коллектор даёт **99.97%** всех событий и в одиночку
держит ~50% ядра на idle-хосте.

**Последствия.**
1. Видимость постоянно скачет: половину времени агент работает с `file_rate: 0.1`,
   то есть **теряет 90% файловых событий** — детект в этот момент дырявый, и момент
   атаки может прийтись ровно на просадку.
2. Журнал непригоден к эксплуатации: полезные записи тонут в 1626 строках флаппинга,
   `WARN` обесценен (821 WARN за ночь, все — этот).
3. Метрика `cpu_pressure_level` бесполезна для алертинга — она пилит 0↔1 круглосуточно.

**Задача разделена на две.** У них разный риск и разный объём: P1-18a — локальная правка
в Go, которая гасит осцилляцию саму по себе; P1-18b — новый код в BPF, который убирает
её первопричину. Делать их одним заходом не нужно и опасно (см. риск в P1-18b).

---

### P1-18a — Разорвать контур обратной связи в watchdog

**Приоритет:** P1 · **Объём:** ~30 строк Go · **Риск:** низкий

Гасит наблюдаемый симптом: 813 циклов за ночь и непригодный к эксплуатации журнал.
Не требует правок в ядерном коде и не влияет на покрытие детекта.

- Разорвать обратную связь: после восстановления требовать выдержки существенно больше
  40 с (минуты), либо оценивать давление по нагрузке **при нормальном сэмплинге**
  (экстраполировать), а не по факту уже задросселированного потока
  ([cpu.go:325-369](internal/watchdog/cpu.go#L325-L369)).
- Логировать переходы с дедупликацией: `reduce/recover` подряд N раз — одна строка с
  счётчиком, не N строк WARN.
- Добавить метрику «доля времени в деградированном сэмплинге» — сейчас понять, сколько
  агент реально видел, можно только грепом журнала.

**Критерий приёмки.** На idle-хосте за час — ноль переходов CPU-watchdog; журнал за
час idle умещается в десятки строк.

**Замечание по порядку работ.** P1-18a нужно делать **до** любого длительного
idle-замера: иначе журнал прогона снова будет на 99% состоять из флаппинга и станет
нечитаемым для проверки остальных задач.

**Статус: ✅ СДЕЛАНО.**

- **Выдержка.** `MinDwell` поднят с 30 с до 3 минут — заметно больше времени, за которое
  восстановленный сэмплинг успевает снова добить CPU до порога.
- **Дедупликация переходов.** Первый переход серии логируется сразу, остальные копятся
  молча и сворачиваются в одну строку с `repeat_count`/`reduce_count`/`recover_count`/
  `run_duration`. Свёртка идёт **по обоим типам сразу**: реальный флаппинг по построению
  чередует reduce и recover, поэтому правило «схлопывать только одинаковые подряд» не
  свернуло бы ничего. Незакрытая серия флашится по истечении `transitionLogGap` (5 мин)
  и при остановке watchdog'а.
- **Метрика.** `ebpf_guard_cpu_degraded_fraction` — доля времени жизни watchdog'а,
  проведённая с урезанным сэмплингом. Интервал засчитывается по состоянию, действовавшему
  на протяжении интервала, до возможного перехода в `evaluate()`.

**Дефект, найденный при ревью (исправлен).** Правка `DefaultCPUConfig()` **не действовала
в проде**: `main.go:539` передаёт `time.Duration(cp.MinDwell) * time.Second` из конфига, а
дефолт Viper `watchdog.cpu_pressure.min_dwell` остался равен 30. Поскольку значение не
нулевое, страховка `if config.MinDwell <= 0` в `NewCPUPressureWatcher` не срабатывала, и
watchdog продолжал работать с прежней 30-секундной выдержкой — то есть флаппинг с периодом
~40 с воспроизвёлся бы на ночном замере в полном объёме. Тесты этого не ловили, потому что
проверяли `DefaultCPUConfig()` напрямую, минуя путь загрузки конфига. Исправлено: дефолт в
[config.go](internal/config/config.go) и `config/config.yaml` подняты до 180 с,
`TestExampleConfigLoadsCPUPressure` теперь пинит именно это значение с комментарием о том,
почему правки только в `DefaultCPUConfig()` недостаточно.

**Критерий «ноль переходов за час idle» проверяется только на стенде** — это свойство
живого хоста под реальной нагрузкой, а не логики, покрываемой unit-тестами.

> **Пересмотр статуса (прогон 2026-08-04).** На стенде флаппинг **воспроизвёлся** при
> порогах 150/250/100: `degraded_fraction = 0.87`, цикл ~3.5 мин вместо прежних ~40 с.
> `MinDwell` растянул период ровно на свою величину, но контур обратной связи не разорвал
> — восстановление file-сэмплинга по-прежнему само пробивает порог. Симптом в логах
> (1626 строк флаппинга) убран дедупликацией, причина — нет. Подробности и предлагаемое
> решение: [P0-22](#p0-22--агент-съедает-15-ядра-на-пустом-хосте-file-коллектор-не-фильтруется-в-ядре-вовсе).
> Фактический статус: **частично сделано**.

> **Прогон №4: флаппинг исчез — но потому, что watchdog фактически отключён порогами.**
> За весь прогон (2 ч idle + 11.5 мин атаки) — **ноль** переходов reduce↔recover:
> `cpu_pressure_level 0`, `cpu_degraded_fraction 0`, `sampling_rates {file:1, network:1,
> syscall:1}`, `visibility_reduced: false` в обоих срезах. Журнал за прогон — 78 INFO и
> 329 WARN, из которых записей о CPU-давлении **одна** (и та — свёртка от предыдущего
> процесса при shutdown в 17:55:13). Дедупликация переходов из P1-18a работает.
>
> Но условие достигнуто ценой порогов `file_shed_threshold: 200` / `all_shed: 320` /
> `recovery: 150` при фактическом потреблении **`cpu_pressure_percent` 152.0% (baseline) →
> 153.3% (под атакой)**. Порог shed — 200% при поле потребления 152%: запас **48
> процентных пунктов**, то есть watchdog не сработает, пока агент не прибавит треть к
> своему и без того полуторакратному расходу ядра. Это подтверждает вывод P0-22: критерий
> «ноль переходов» выполняется отключением регулятора, а не разрывом контура.
>
> **Отдельно показательно:** под атакой CPU вырос со 152% до 153.3% — то есть **+1.3
> процентных пункта** на пике всей атакующей нагрузки. Вся стоимость агента — его
> собственный фоновый file-поток, атака в этом фоне не различима по CPU. Это же означает,
> что CPU-watchdog в принципе не может служить индикатором нагрузки от атаки.
>
> **Фактический статус P1-18a остаётся «частично»:** симптом убран (флаппинга нет, журнал
> читаем), контур обратной связи не разорван и не проверен — при дефолтных порогах он
> воспроизведётся, см. критерий приёмки P0-22.

---

### P1-18b — Сократить объём file-событий фильтрацией путей в ядре

**Приоритет:** P1 · **Объём:** новый код в BPF + `make generate` · **Риск:** средний

Убирает первопричину — 43.4 млн событий за 9 часов простоя (99.97% всего потока).
После P1-18a осцилляция прекратится, но агент по-прежнему будет держать ~50% ядра
впустую, поднимая в userspace 43 млн событий ради ~1600 совпадений с правилами.

**Что уже есть в коде.** `kernel_filter` умеет фильтровать по `comm`
([sampling.go:405](internal/bpf/sampling.go#L405)) и по номеру syscall
([sampling.go:429](internal/bpf/sampling.go#L429)) — соответствующие карты
`comm_filter_map` и `syscall_filter_map` объявлены в
[bpf/common.h:198-233](bpf/common.h#L198-L233).

**Чего нет.** Фильтрации по путям — ни карты, ни логики в
[bpf/fileaccess.bpf.c](bpf/fileaccess.bpf.c). Её нужно писать с нуля: карта префиксов
(LPM-trie по аналогии с уже используемым для IP-адресов,
[common.h:396-412](bpf/common.h#L396-L412)), проверка в хуке `sys_enter_openat` до
отправки события в ring buffer, прокидывание конфигурации из userspace.

**Риск и как его снять.** Ошибка в наборе префиксов означает, что агент перестанет
видеть целый класс файловых событий — то есть ослепнет молча, а idle-прогон при этом
станет **зеленее**. Поэтому:
- не делать в спешке перед длительным замером;
- сразу после — **прогон атак**, а не только idle: детект по файловым правилам
  (`fim_*`, `canary_*`, `cred_*`) обязан остаться на уровне прогона №2;
- начинать с денилиста заведомо мусорных путей, а не с аллоулиста «нужных» —
  ошибка в денилисте стоит дешевле.

**Критерий приёмки.** `ebpf_guard_events_total{type="file"}` на idle-хосте падает на
порядок; CPU агента в покое — единицы процентов ядра; attack-прогон детектит файловые
атаки не хуже прогона №2.

---

## P1-19 — Поток шума нарастает со временем, а не выходит на плато

**Тип:** bug · **Приоритет:** P1 · **Метки:** `detection-quality`, `performance`

**Проблема.** При неизменной (нулевой) активности хоста темп алертов монотонно рос
всю ночь — почти втрое от первого часа к девятому:

| Час (UTC) | 19 | 20 | 21 | 22 | 23 | 00 | 01 | 02 | 03 |
|---|---|---|---|---|---|---|---|---|---|
| Алертов | 1425 | 2820 | 3181 | 3637 | 3962 | 3939 | 4325 | 4556 | 4698 |
| Инцидентов | 71 | 123 | 145 | 155 | 201 | 186 | 224 | 244 | 252 |

Ничего в окружении не менялось: нагрузки нет, RSS на плато, cardinality на плато,
`events_dropped_total = 0`. Значит растёт не входной поток, а **склонность движка
срабатывать** — например накапливаются состояния в rate limiter/дедупликаторе, растут
окна корреляции, стареют записи в LineageTracker, либо `drift_*`-правила со временем
считают всё большее число вещей «новым».

Косвенное подтверждение: `drift_new_library_in_system_dir` дал 1260 алертов на хосте,
где за ночь не появилось ни одной новой библиотеки.

**Что сделать.**
- Профилировать рост: снять, какие именно `rule_id` растут по часам (данные есть в
  `server-logs/idle-20260803_194120/snapshots/`), отделить правила с накоплением
  состояния от постоянных.
- Проверить TTL/эвикцию в rate limiter, дедупликаторе, LineageTracker и в состоянии
  `drift_*`-правил — вероятная причина в отсутствии старения.
- Регресс-критерий: темп алертов за 8-й час не должен превышать темп за 2-й более чем
  на 20%.

**Критерий приёмки.** На idle-хосте темп алертов стационарен (плато), а не растёт.

---

## P2-20 — DNS-коллектор роняет ERROR при каждом штатном завершении

**Тип:** bug · **Приоритет:** P2 · **Метки:** `collectors`, `shutdown`, `noise`

**Проблема.** Оба завершения агента за прогон дали единственные два ERROR в журнале
за 9 часов — и оба ложные:

```
19:39:34 ERROR dns: read from ringbuf  error="epoll wait: file already closed"
04:41:32 ERROR dns: read from ringbuf  error="epoll wait: file already closed"
```

Это штатная гонка graceful-shutdown: ring buffer закрывается раньше, чем читающая
горутина выходит из `epoll`. Ошибки нет, но она логируется как ERROR — то есть
единственный ERROR-сигнал, который есть у оператора, зашумлён гарантированным ложным
срабатыванием при каждом рестарте.

**Что сделать.**
- При отменённом контексте / закрытом ringbuf трактовать `os.ErrClosed` (и
  `ringbuf.ErrClosed`) как штатное завершение: логировать на DEBUG или молча выходить.
- Проверить остальные коллекторы на тот же паттерн (у syscall/network/fileaccess
  сообщения `stopping … collector` чистые — вероятно, там обработка уже есть, надо
  выровнять DNS по ним).

**Критерий приёмки.** `systemctl restart` не порождает ни одного ERROR в журнале.

**Статус: ✅ СДЕЛАНО (доработано при ревью).** В
[dns.go](internal/collector/dns.go) обработка ошибки чтения выровнена с
syscall/network/fileaccess-коллекторами.

Замечание при ревью: первоначальная правка **заменила** проверку
`err == ringbuf.ErrClosed` на `ctx.Err() != nil`, а не дополнила её. Это чинило
основной сценарий (отмена контекста), но открывало регрессию: `DNSCollector.Close()`
закрывает reader **независимо от контекста** (dns.go:244), и при закрытии без
отмены ctx цикл не выходил бы, а крутился на `ErrClosed`, печатая ERROR на каждой
итерации — вместо двух ложных ERROR за прогон получился бы бесконечный поток.
Итоговое условие покрывает оба пути: `ctx.Err() != nil || errors.Is(err,
ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed)`. `errors.Is` вместо `==`
важен потому, что наблюдаемая в проде ошибка (`epoll wait: file already closed`)
— обёрнутая, и прямое сравнение её не ловило.

---

## P2-21 — Рост SQLite-хранилища и отсутствие ретенции

**Тип:** enhancement · **Приоритет:** P2 · **Метки:** `store`, `retention`

**Проблема.** `ebpf_guard_store_size_bytes` за 9 часов idle — **31.2 МБ**
(42157 алертов в базе). В пересчёте это ~83 МБ/сутки и ~2.5 ГБ/месяц **на
простаивающем хосте**; под нагрузкой — кратно больше. Метрики бэкапа при этом нулевые
(`store_backup_last_success_timestamp 0`), то есть бэкап ни разу не отработал.

Значительная часть роста — прямое следствие P1-6/P1-13 и уйдёт вместе с шумом, но
ретенция нужна независимо: сейчас в конфиге стенда её нет, и ничто не ограничивает
рост файла.

**Что сделать.**
- Ввести и задокументировать ретенцию по времени и/или числу записей для sqlite-бэкенда,
  с дефолтом, разумным для DaemonSet-развёртывания.
- Добавить метрику числа записей в сторе и возраста самой старой записи.
- Разобраться, почему `store_backup_*` нулевые: бэкап выключен по умолчанию (тогда это
  ок) или сломан молча — как `SetEngineProvider` в P1-10.

**Критерий приёмки.** Размер стора ограничен сверху конфигурацией; на idle-хосте за
сутки файл не превышает заданный лимит.

---

# Новые задачи из прогона 2026-08-04 (стенд 89.125.2.154)

## P0-22 — Агент съедает 1.5 ядра на пустом хосте; file-коллектор не фильтруется в ядре вовсе

**Тип:** bug (архитектурный) · **Приоритет:** P0 · **Метки:** `performance`, `bpf`,
`sampling`, `architecture` · **Связана с** [P1-18a](#p1-18a--разорвать-контур-обратной-связи-в-watchdog),
[P1-18b](#p1-18b--сократить-объём-file-событий-фильтрацией-путей-в-ядре)

### Измерено

Стенд: 4 ядра, Ubuntu 5.15, профиль `balanced`, из нагрузки — только три простаивающих
контейнера (juice-shop, prometheus, grafana) и sshd. Конфиг: `track_open: true`,
`track_write: true`, `track_read: false`.

```
ebpf-guard       153 %CPU     ← агент
MainThread       1.4
grafana          0.9
prometheus       0.5
sshd             0.2
```

**Агент — 153% одного ядра при полном сэмплинге. Всё остальное на хосте вместе — меньше
3%.** Внешней нагрузки, на которую можно списать расход, нет: агент реагирует на
собственный шумовой фон и на простаивающие контейнеры.

Распределение потока за 10 минут:

| Тип события | Количество | Доля |
|---|---|---|
| file | 4 314 586 | **99.7%** |
| syscall | 878 | 0.02% |
| network | 29 | ~0 |
| dns | 9 | ~0 |

При `file_rate: 0.1` (урезанный сэмплинг) за 10 минут — 745 623 file-события; при 1.0 —
~4.3 млн, то есть **~7 200 событий/с** на пустом хосте. Каждое — `struct event` в 314
байт через ring buffer в userspace: ~2.2 МБ/с только на копирование, до всякой
корреляции.

### Первопричина: фильтрация в ядре есть, но file-коллектор её не использует

`kernel_filter` (денилист по `comm`, фильтр по номеру syscall) реализован и работает —
но вызывается **только из [syscall.bpf.c:49,101](bpf/syscall.bpf.c#L49)**:

```
$ grep -rn "comm_is_denied\|kernel_filter_enabled" bpf/*.c
bpf/syscall.bpf.c:49:   if (kernel_filter_enabled()) {
bpf/syscall.bpf.c:50:           if (comm_is_denied())
bpf/syscall.bpf.c:101:  if (kernel_filter_enabled()) {
bpf/syscall.bpf.c:102:          if (comm_is_denied())
```

В [fileaccess.bpf.c](bpf/fileaccess.bpf.c) — **ни одного вызова**. Коллектор, дающий
99.7% потока, не фильтруется в ядре ничем, кроме числового сэмплинга «1 из N», который
режет вслепую: теряет и шум, и атаку в одной пропорции.

Отсюда же и запись в логе старта — `comm_denylist: 15` относится к syscall-коллектору и
на file-поток не влияет вовсе, хотя выглядит как общая настройка.

### Контур обратной связи через собственный I/O агента

`trace_read`/`trace_write` ([fileaccess.bpf.c:181,213](bpf/fileaccess.bpf.c#L181))
эмитят событие на **каждый** `read(2)`/`write(2)` в системе, включая вызовы самого
агента: запись в SQLite (`test-events.db`), audit.jsonl, ответы HTTP API. Агент
обрабатывает событие → пишет в стор → порождает новое событие. Самоисключение
(`selfPID`) реализовано только в userspace и только для canary
([canary.go:86](internal/canary/canary.go#L86)); в BPF его нет.

Это отдельный контур, не тот, что в P1-18. Он не осциллирует — он даёт постоянную
добавку к полу нагрузки, которая растёт вместе с числом алертов.

### Что сегодняшний прогон говорит про P1-18a

P1-18a закрыт как «сделано» (`MinDwell` 30с → 180с + дедуп логов + метрика). Сегодня
на пороге 150/250/100 флаппинг **воспроизвёлся**:

```
16:01:54  lvl=0  cpu=26.3%   file_rate=1     ← восстановление
16:02:24  lvl=1  cpu=129.5%  file_rate=0.1   ← +30 с, снова шеддинг
```

`ebpf_guard_cpu_degraded_fraction = 0.87` — агент провёл 87% времени с урезанной
видимостью. Период вырос с ~40 с до ~3.5 мин ровно на величину `MinDwell`, но контур не
разорван: восстановление file-сэмплинга с 0.1 до 1.0 само поднимает CPU до 130-165%
ядра и пробивает порог заново.

**Вывод: `MinDwell` растянул период, но не устранил причину.** Критерий приёмки P1-18a
(«ноль переходов за час idle») достигается сейчас только тем, что порог задран выше пика
(200/320/150) — то есть watchdog отключён фактически, а не логически. Статус P1-18a
стоит пересмотреть с «сделано» на «частично: симптом в логах убран, контур остался».

### Что делать — архитектурно

Порядок важен: каждый следующий пункт дешевле проверять, когда предыдущий уже срезал
объём.

1. **Применить существующий `kernel_filter` в fileaccess.bpf.c** (дёшево, риск низкий).
   Вызвать `kernel_filter_enabled()`/`comm_is_denied()` в `trace_open`/`trace_read`/
   `trace_write` по образцу syscall.bpf.c. Одно это отсекает поток от заведомо шумных
   демонов, не трогая логику детекта.

2. **Самоисключение в BPF** (дёшево, риск низкий). Передать PID агента в карту и
   отбрасывать его события в ядре до `bpf_ringbuf_reserve`. Разрывает контур
   «запись в стор → событие → запись в стор». Осторожно: атака на сам агент
   (например, запись в его бинарь или конфиг) должна остаться видимой — исключать
   стоит по PID для read/write, но не для open по чувствительным путям.

3. **Фильтрация путей — это P1-18b**, но с уточнением приоритета: сегодняшние цифры
   показывают, что без неё остальное даёт лишь частичный эффект. Ключевое наблюдение
   для реализации: `trace_read`/`trace_write` резервируют событие **до** резолва пути
   ([fileaccess.bpf.c:189,221](bpf/fileaccess.bpf.c#L189)) — `enrich_from_fd` вызывается
   уже после `reserve_event_with_sampling`. Значит фильтр по префиксу пути для read/write
   требует переставить порядок: сначала `bpf_map_lookup_elem(&fd_path_map)`, проверка
   префикса, и только потом резерв. Иначе фильтрация сэкономит корреляцию, но не
   копирование в ring buffer.

4. **Пересмотреть, нужны ли read/write как отдельные события вообще.** Сейчас каждый
   `read(2)` — это 314 байт в userspace ради правил, которым в подавляющем большинстве
   случаев достаточно факта `open` с флагами. Вариант: эмитить write/read-события только
   для fd, чей путь уже прошёл префиксный фильтр (то есть агрегировать в ядре: «процесс
   P писал в /etc/passwd», а не 400 отдельных событий).

5. **Привязать дефолты CPU-watchdog к реальности.** `file_shed_threshold: 40` — это 0.4
   ядра, что **ниже штатного потребления агента** на любом хосте с заметным файловым
   трафиком. Из коробки такой хост гарантированно уходит либо в вечный шеддинг (если
   recovery недостижим), либо во флаппинг. Дефолт должен быть выше измеренного пола
   потребления, а не ниже.

### Как отличать системный шум от атаки

Отдельный вопрос из обсуждения, и он **не решается сэмплированием** — «1 из N» режет
шум и атаку одинаково. Что стоит рассмотреть:

- **Фильтр по пути, а не по объёму.** Атака почти всегда касается ограниченного набора
  каталогов (`/etc`, `/root/.ssh`, `/usr/bin`, `/var/www`, `/proc/*/mem`), а шум —
  ротация логов, `/proc` от мониторинга, кэши рантайма. Денилист шумных путей (не
  аллоулист нужных — ошибка дешевле, см. риск в P1-18b) даёт срез на порядок без потери
  детекта.
- **Уже есть `drift`-механика и baseline профайлера** — они по построению отвечают на
  вопрос «это обычное для данного workload поведение или новое». Сейчас они работают
  *после* того, как событие поднято в userspace. Часть этого решения (стабильный набор
  «обычных» comm+путь для устоявшегося процесса) в принципе выражается картой в ядре.
- **Событие от самого агента и его инфраструктуры — не шум, а артефакт наблюдения.**
  Его надо убирать в ядре (п. 2), а не подавлять правилами постфактум, как сейчас
  делает P1-17.

### Критерий приёмки

- CPU агента на idle-хосте с `balanced` — **единицы процентов ядра**, не 153%.
- `ebpf_guard_events_total{type="file"}` на idle падает **минимум на порядок**.
- `ebpf_guard_cpu_degraded_fraction` ≈ 0 при **дефолтных** порогах watchdog, а не при
  задранных вручную.
- Attack-прогон детектит файловые атаки (`fim_*`, `cred_*`, `canary_*`) **не хуже**
  прогона №2 — проверяется обязательно, иначе оптимизация означает молчаливую слепоту.

### Подтверждение прогоном №4 (атака, 2026-08-04) — и новое следствие

Цифры воспроизвелись, но теперь есть замер **под атакой**, и он добавляет к задаче
новое последствие: переполнение каналов и потерю событий (вынесено в **P0-25**).

| Показатель | idle-baseline (2 ч) | под атакой (11.5 мин) |
|---|---|---|
| `cpu_pressure_percent` | 152.0% | **153.3%** |
| `events_total{type="file"}` | 5 347 337 | 9 374 201 (**+4.03 млн за 11.5 мин ≈ 5800/с**) |
| `events_total{type="syscall"}` | 3 639 | 6 644 (+3 005) |
| `events_total{type="network"}` | 7 | 22 555 (+22 548) |
| `events_total{type="dns"}` | 7 | **7 (+0)** |
| доля file в потоке | 99.93% | **99.4%** |

Три вывода, которых не было в исходной формулировке:

1. **Атака не видна в потреблении.** +4 млн file-событий и вся атакующая нагрузка дали
   прирост CPU в 1.3 п.п. (152 → 153.3). Пол потребления настолько высок, что полезная
   нагрузка в нём тонет — это argument к п.1-4 «что делать» сильнее, чем idle-замер.
2. **Атака видна в сетевом потоке ярко: 7 → 22 555 событий.** Сеть — это 0.2% потока и
   при этом весь полезный сигнал прогона (portscan, beacon, SSRF детектились именно по
   ней). Соотношение «99.4% бюджета на file, весь детект на 0.2% network» — прямой
   аргумент за приоритезацию фильтрации file-потока: она не угрожает сетевому детекту.
3. **DNS-коллектор за весь прогон дал 0 событий** (7 → 7), хотя атака включала обращения
   по именам. Вынесено в **P0-26** — коллектор числится `healthy: true`, но не работает.

### Открытые вопросы (требуют обдумывания, не реализации сходу)

- Где проходит граница между «фильтровать в ядре» и «потерять контекст для корреляции»?
  Часть правил (`lineage`, sequence-профайлер) строится на последовательностях, и
  агрессивная фильтрация в ядре может разорвать цепочку, которую эти правила ищут.
- Стоит ли делать набор префиксов зависимым от загруженных правил (автоматически: какие
  пути реально упоминаются в условиях) вместо ручного списка? Это убирает риск
  рассинхрона «правило есть, а события до него не доходят».
- Нужна ли отдельная метрика «событий отфильтровано в ядре» по причинам — без неё
  ослепление будет выглядеть как улучшение.

### Статус п.1–2: ⏳ КОД СДЕЛАН, ЖДЁТ ЗАМЕРА №1 (волна 0.5, 2026-08-05)

Подняты из волны 4 после закрытия вопроса 1 (очередь общая → file-поток является причиной
потери сетевых событий). Остальные пункты P0-22 (в т.ч. P1-18b — фильтрация произвольных
путей в ядре) остаются в волне 4.

1. **`kernel_filter` применён в `fileaccess.bpf.c`** — `comm_is_denied()` вызывается в
   `trace_open`, `trace_read`, `trace_write` до `reserve_event_with_sampling`, то есть до
   ring buffer. `trace_open_exit` / `trace_openat2_exit` / `trace_close` намеренно **не**
   фильтруются: они не порождают событий, а только ведут карту fd→path, и фильтрация в них
   сломала бы разрешение путей для тех событий, которые проходят.
2. **Самоисключение агента в BPF** — `agent_pid_map` + `pid_is_agent()`
   ([bpf/common.h](bpf/common.h)), PID пишется на старте через
   `KernelFilterController.SetAgentPID`. **По PID, не по путям** — атака на файлы самого
   агента чужим процессом остаётся видимой, как и требовал план.

**Три дефекта, найденные и исправленные при ревью первоначальной правки:**

- **Карты не наполнялись для того коллектора, ради которого всё делалось.** Фильтрующие
  карты объявлены в [bpf/common.h](bpf/common.h), поэтому **каждый скомпилированный BPF-объект
  получает собственный экземпляр**. `enableKernelFilter` вызывался только для syscall-коллектора,
  а `fileaccess.bpf.c` читал свои копии `agent_pid_map`/`comm_filter_map`/`kernel_filter_config`,
  которые всегда оставались нулевыми. То есть и denylist, и самоисключение были бы
  неактивны именно у коллектора, дающего 99.4% потока, — правка не дала бы никакого
  эффекта, и это списали бы на «фильтрация не помогает». `enableKernelFilter` переведена на
  явный набор карт и вызывается **отдельно для каждого коллектора**; у
  `FileaccessCollector` добавлен аксессор `KernelFilterMaps()`.
- **`trace_read` остался без самоисключения** — при том что read даёт наибольший объём
  собственного I/O агента (страницы SQLite, audit.jsonl, перечитывание правил). Из трёх
  hook'ов проверка стояла в двух.
- **PID 0 трактовался как валидный.** `agent_pid_map` — `BPF_MAP_TYPE_ARRAY`, поэтому
  `bpf_map_lookup_elem` **всегда успешен** и до вызова `SetAgentPID` возвращает 0.
  Исходная проверка `if (!agent_pid) return false` от этого не защищала: указатель ненулевой,
  а значение нулевое. Добавлено явное `*agent_pid == 0 → «не настроено»`, и симметрично
  `SetAgentPID(0)` возвращает ошибку, а не молча делает вид, что исключение включено.

**Что проверять на замере №1 (гейт волны 0.5):** file-поток на idle падает кратно
(ожидание с ~5800 до сотен соб./с); CPU агента заметно ниже 152%; `comm=ebpf-guard`
в алертах стремится к нулю; и — обязательно — детект по файловым правилам (`fim_*`,
`canary_*`, `cred_*`) остаётся на уровне прогона №4, а атака **на файлы агента** чужим
процессом по-прежнему алертит.

---

# Новые задачи из прогона №4 (атака, 2026-08-04, версия `f505252`)

## P0-25 — Под атакой теряется 52% сетевых и 55% syscall-событий, при этом агент рапортует полную видимость

**Тип:** bug · **Приоритет:** P0 · **Метки:** `collectors`, `performance`,
`detection-coverage`, `observability` · **Связана с** [P0-22](#p0-22--агент-съедает-15-ядра-на-пустом-хосте-file-коллектор-не-фильтруется-в-ядре-вовсе)

### Измерено

`events_dropped_total{reason="channel_full"}`, дельта за 11.5 минут атаки:

| Коллектор | События (+) | Потеряно (+) | **Доля потерь** |
|---|---|---|---|
| network | 22 548 | **24 426** | **52.0%** |
| syscall | 3 005 | 3 608 | **54.6%** |
| fileaccess | 4 026 864 | 1 120 482 | 21.8% |
| dns | 0 | 1 | — |

**Больше половины сетевых событий не дошло до корреляции.** Сеть — носитель всего
полезного сигнала этого прогона (portscan, C2-beacon, SSRF, high-frequency), и половина
его потеряна. В idle-baseline потери были пренебрежимы (network 5, syscall 253,
fileaccess 7104 за 2 часа) — то есть деградация наступает **ровно под атакой**, когда
агент нужен.

Журнал подтверждает: 325 WARN `event channel full, dropping events`, все — в окне
18:09:23 → 18:21:33, то есть с первой секунды атаки до конца прогона, непрерывно.
Пиковые записи — до 2748 отброшенных за 5-секундное окно.

### Почему это P0, а не «известная перегрузка»

Агент в это же время сообщает **обратное**:

```
/health   : "healthy": true, "visibility_reduced": false,
            "sampling_rates": {"file":1, "network":1, "syscall":1},
            "cpu_pressure_level": 0
все коллекторы: "healthy": true
```

`visibility_reduced` отражает только решения CPU-watchdog (сэмплинг), но **не** потерю
событий из-за переполнения канала. В результате оператор, смотрящий на `/health` или на
`cpu_degraded_fraction`, видит «полная видимость, давления нет» в момент, когда теряется
половина сетевого потока. Это опаснее самой потери: сигнал деградации есть в метриках, но
не заведён в те индикаторы, на которые смотрят.

Кроме того, потери **не связаны с CPU-watchdog вовсе**: пороги 200/320/150 не были
достигнуты (152→153.3%), сэмплинг ни разу не снижался. Узкое место — размер Go-канала
между коллектором и движком, а не процессорное давление. То есть контур защиты от
перегрузки не сработал, потому что измеряет не тот сигнал.

### Что сделать

- **Завести потерю событий в индикаторы деградации.** `visibility_reduced: true` (и
  `/health` → `degraded`) при ненулевом темпе `events_dropped_total`, а не только при
  урезанном сэмплинге. Это же закрывает остаток P1-5.
- **Разобраться с размером канала.** Понять фактическую ёмкость канала
  коллектор→движок и то, почему network с 22 тыс. событий за 11 минут (≈33/с) его
  переполняет. 33 события/с — ничтожный темп; переполнение при нём означает, что канал
  либо общий с file-потоком (5800/с), либо потребитель заблокирован обработкой file.
  **Гипотеза для проверки в первую очередь:** канал один на все коллекторы, и file-поток
  вытесняет из него сетевые события — тогда это прямое следствие P0-22 и чинится
  разделением очередей по типам событий с приоритетом.
- **Приоритезация при переполнении.** Если очередь общая — сбрасывать в первую очередь
  file-события (99.4% потока, наименьшая ценность на событие), никогда не network/dns.
- **Метрика доли потерь**, а не только счётчика: `dropped / (dropped + processed)` по
  коллекторам — 52% в абсолютных числах заметить трудно, в доле — сразу.

### Критерий приёмки

- На attack-прогоне доля потерь по network и dns — **ноль**; по syscall < 1%.
- При любой ненулевой потере событий `/health` показывает деградацию, а не `healthy` с
  `visibility_reduced: false`.

### Статус: ⏳ КОД СДЕЛАН, ЖДЁТ ЗАМЕРА №1 (волна 0, 2026-08-05)

Правка сделана, но **закрытой задача не считается до attack-прогона** — критерий приёмки
сформулирован в терминах прогона, а не тестов.

1. **Раздельные очереди по приоритету.** `PriorityEventCollector`
   ([internal/collector/priority.go](internal/collector/priority.go)) оборачивает каждый
   коллектор и разводит поток на две очереди. Разделение — **по источнику флуда, а не по
   «важности»**: в защищённую очередь уходит всё, кроме `EventFileAccess`. Первоначальная
   правка оставляла syscall в общей очереди с file-потоком, из-за чего критерий
   «syscall < 1%» был недостижим по построению — 5800 file-соб./с вытеснили бы syscall
   ровно так же, как раньше вытесняли network.
2. **Приоритет в главном цикле реализован явно.** Двух-кейсовый `select` приоритета **не
   даёт**: при готовности обоих каналов Go выбирает случайно. Добавлен неблокирующий слив
   защищённой очереди перед обработкой каждого bulk-события
   ([main.go](cmd/ebpf-guard/main.go)), с ограничением `maxProtectedDrainBurst`, чтобы
   file-поток деградировал, но не вставал совсем.
3. **Индикатор деградации.** `/health` отдаёт новое поле `status`
   (`healthy` / `degraded` / `unhealthy`) и `visibility_reduced`, которые поднимаются от
   **факта дропов**, а не от урезания сэмплинга. `/api/v1/status` согласован: раньше
   `VisibilityReduced` там брался только из CPU-watchdog — то есть в прогоне №4 поле
   честно показывало `false`, потому что сэмплинг не снижался. Закрывает и остаток P1-5.
4. **Метрика доли потерь** — `ebpf_guard_events_dropped_fraction{priority=...}`
   (`dropped / (dropped + accepted)` за окно), рядом с существующим счётчиком.

Тесты: [internal/collector/priority_test.go](internal/collector/priority_test.go) —
в т.ч. воспроизведение сценария прогона №4 (990 file-событий против 10 сетевых при
переполненной bulk-очереди: сетевых потеряно **0**), и
[internal/exporter/server_visibility_test.go](internal/exporter/server_visibility_test.go)
— `degraded` при дропах, при этом `healthy: true` (деградация не должна приводить к
рестарту рабочего агента оркестратором).

**Что проверять на замере №1:** доля потерь network/dns = 0, syscall < 1%,
`/health` → `degraded` при любых дропах, и — обязательно — что детект не просел
(43 типа, ≥850 алертов), поскольку приоритизация меняет порядок обработки событий.

---

## P0-26 — DNS-коллектор не поставляет события: 7 за весь прогон, включая атаку

**Тип:** bug · **Приоритет:** P0 · **Метки:** `collectors`, `dns`, `detection-coverage`

### Проблема

`ebpf_guard_events_total{type="dns"}` — **7 в baseline и 7 после атаки. Прирост ноль.**

За 11.5 минут прогона выполнялись sqlmap, bruteforce (1959 попыток), SSRF (106) и
LDAP/CSRF (131) — трафик шёл по именам, `curl` резолвил хосты, при этом файловые правила
фиксировали чтение `/etc/resolv.conf` и `/etc/nsswitch.conf` (тот самый паттерн из P2-12),
то есть резолвинг **происходил**. DNS-коллектор при этом не увидел ничего.

Коллектор числится живым: `{"name":"dns","healthy":true}` в `/health` и в
`collector_stats` `/debug/state`. В журнале нет ни ошибки загрузки, ни предупреждения —
в отличие от честных сообщений соседей:

```
lsm:  kernel does not support LSM BPF, collector in stub mode
kmod: LSM BPF unavailable, kernel module load detection disabled
kmod: cgroup escape collector unavailable   error=... LSM hook not supported
```

DNS молчит и рапортует `healthy`. Единственный след за прогон — одна запись
`event channel full` для dns в 18:12:08, то есть одно событие всё же было и было отброшено.

### Последствия

Весь класс DNS-детекта не проверен ни одним прогоном: `rules/dns-threats.yaml`, DNS-энтропия
и детект mining-пулов в `internal/correlator/`, `netintr_long_dns_session` (сработал 1 раз —
вероятно, по сетевому, а не dns-событию). Эти правила выглядят рабочими в тестах, но на
стенде под ними нет входных данных. То же касается вывода прогона №3 (355 dns-событий за
9 часов ≈ 0.01/с) — тогда это списали на «idle, никто не резолвит».

**Отдельный риск:** 7 событий — не ноль, поэтому мониторинг «коллектор жив» проходит.
Молчаливая слепота целого коллектора при `healthy: true` — тот же класс дефекта, что
`SetEngineProvider` в P1-10 и `SaveState` в P0-3.

### Что проверить

- Socket filter в [bpf/dns.bpf.c](bpf/dns.bpf.c) фильтрует UDP dport 53 — проверить, что
  он приаттачен к правильному интерфейсу. На стенде трафик идёт через docker-bridge и
  loopback (Juice Shop на `localhost:3000`), а фильтр, вероятно, висит на одном
  интерфейсе (`eth0`), мимо которого контейнерный DNS не проходит.
- Резолвинг в контейнерах Docker идёт на `127.0.0.11:53` (встроенный резолвер) — если
  фильтр не слушает loopback, это объясняет ноль напрямую.
- Проверить обратное направление: ответы (sport 53), а не только запросы.

### Критерий приёмки

`dig`/`curl` по внешнему имени с хоста **и** из контейнера порождает событие DNS-коллектора;
на attack-прогоне `events_total{type="dns"}` растёт на сотни, и правила из
`dns-threats.yaml` получают вход. Коллектор, не получивший ни одного события за N минут
при живом резолвинге, должен рапортовать `healthy: false` или WARN в журнале.

### Поправка к разделу «Что проверить» (по коду, 2026-08-05)

Гипотеза про socket filter и интерфейс **неверна — их не существует**. DNS-коллектор
висит на 13 глобальных syscall-tracepoint'ах ([internal/collector/dns.go](internal/collector/dns.go),
[bpf/dns.bpf.c](bpf/dns.bpf.c)) и видит все процессы и любые адреса, включая Docker
`127.0.0.11:53` и cluster-IP CoreDNS. Пункты про «приаттачен не к тому интерфейсу» и
«не слушает loopback» снимаются как основанные на неверной модели. Реальные слепые зоны:
`is_dns_packet` пропускает только AF_INET ([bpf/dns.bpf.c:98-101](bpf/dns.bpf.c#L98-L101)),
то есть IPv6- и TCP-DNS невидимы; fd, `connect()`-нутые до старта агента, не попадают в
`dns_socket_map`; и главный подозреваемый на Ubuntu-стенде — **systemd-resolved**,
через который хостовые процессы резолвят по AF_UNIX (nss-resolve/varlink), так что
порт 53 в их syscalls не появляется вовсе.

### Статус: ⚠️ ЧАСТИЧНО (волна 0, 2026-08-05) — слепота стала видимой, причина не устранена

Сделана **только диагностическая половина**, и это сознательно: пока не выполнена
диагностика на стенде (`dig` ×3), неизвестно, что чинить — «работает, данных не было»,
«слеп на nss-пути» или «сломан декодер». Правка декодера или расширение на AF_UNIX без
этого была бы гаданием.

1. **Коллектор больше не выглядит рабочим, когда он слеп.** Добавлен watchdog
   `watchForStaleness`: при нуле событий за 5 минут поднимается
   `ebpf_guard_dns_collector_stale` и пишется WARN с перечнем вероятных причин и командой
   для проверки. `stale` намеренно **не** равен `healthy: false` — коллектор не сломан
   (ответ на открытый вопрос 4 в [plan.md](plan.md)).
2. **Дефект в первоначальной правке.** Диагностический лог был помещён **внутрь тела
   цикла чтения**, после `reader.Read()`. `Read()` блокируется, когда событий нет, —
   то есть предупреждение «событий ноль» не могло сработать ровно в том случае, ради
   которого писалось; оно печаталось бы только когда события идут. Watchdog вынесен в
   отдельную горутину с собственным таймером и читает счётчик, публикуемый циклом.
3. **Слепые зоны названы в стартовом логе** (`visibility` / `blind_spots`), а не только в
   ISSUES: коллектор, который чисто стартует и рапортует `healthy`, читается как рабочий.
4. Убраны пять метрик (`dns_ipv4_events_seen_total`, `dns_ipv6_events_seen_total`,
   `dns_non_port_53_events_total`, `dns_unknown_family_events_total`), которые были
   объявлены и зарегистрированы, но **никогда не инкрементировались** — то есть добавляли
   в `/metrics` четыре вечных нуля и ещё один способ принять слепоту за здоровье.
   Оставлены `dns_decode_errors_total` (реально пишется) и новый `dns_collector_stale`.

**Что осталось (блокирует закрытие):** диагностика на стенде — `dig example.com @8.8.8.8`,
`dig example.com`, `curl http://example.com`, с хоста и из контейнера, с проверкой
`events_total{type="dns"}` после каждой. По её результату — либо расширение коллектора на
nss-путь, либо запись «DNS на этом стенде не наблюдаем by design» с переносом проверки
DNS-правил на стенд без systemd-resolved.

---

## P1-27 — Инцидент не содержит `comm`: 684 алерта «Confirmed attack» без указания процесса

**Тип:** bug · **Приоритет:** P1 · **Метки:** `correlation`, `usability`, `triage`
· **Связана с** [P0-1](#p0-1--инциденты-не-коррелируют-цепочку-атаки-между-процессами),
[P1-13](#p1-13--ложные-подтверждённые-атаки-30-под-атакой-100-на-idle)

**Проблема.** Все `incident_confirmed_attack` прогона №4 — **570 в baseline и 114 новых,
684 из 684** — имеют пустое поле `comm`:

```json
{"id": "alert-inc-1785867672645-696-attack", "rule_id": "incident_confirmed_attack",
 "severity": "critical", "pid": 693197, "comm": "",
 "message": "Confirmed attack: 5 alerts from 5 rules across 4 MITRE tactics
             (credential-access, discovery, initial-access, persistence)
             in process chain unknown (score 59.0)"}
```

`pid` заполнен, `comm` — нет, `process_chain` — `unknown` (P0-1). Синтетический алерт
инцидента собирается из агрегата и не наследует `comm` ни от одного из породивших его
алертов, хотя все они (`details.alert_ids`) принадлежат одному PID и, значит, одному
процессу с известным `comm`.

**Почему это отдельная задача, а не часть P0-1.** Наполнить `comm` из первого алерта
группы — правка на несколько строк, не требующая починки LineageTracker. Она немедленно
даёт триажируемость: сейчас оператор видит critical «подтверждённая атака» без единого
указания на источник и вынужден разбирать `alert_ids` вручную. Она же делает измеримой
точность вердикта (P1-13): без `comm` долю FP нельзя посчитать автоматически — в этом
анализе её пришлось восстанавливать разбором PID, закодированных в id алертов.

**Побочный эффект, который стоит учесть.** Пустой `comm` уезжает и в Prometheus-метку —
часть серий `ebpf_guard_profiler_anomaly_score{comm=""}` (2380 из 6319, см. P1-11) может
иметь тот же корень: `comm` теряется где-то на пути агрегации, а не только в инциденте.
Стоит проверить, одна ли это причина.

**Что сделать.**
- Наполнять `comm` (и `pid`, если инцидент однопроцессный) из алертов группы; при
  нескольких процессах — `comm` корня цепочки плюс список в `details`.
- Добавить в сообщение имя процесса: `Confirmed attack: … in sshd (pid 693197)` вместо
  `in process chain unknown`.
- Тест: синтетический инцидент из N алертов одного процесса имеет непустой `comm`.

**Критерий приёмки.** Ни один `incident_confirmed_attack` не имеет пустого `comm`;
долю FP можно посчитать группировкой по `comm` без разбора `alert_ids`.

---

## P2-28 — `FINAL-REPORT.json` по-прежнему невалиден, а текстовый отчёт расходится с данными

**Тип:** bug (tooling) · **Приоритет:** P2 · **Метки:** `tooling`, `testing`
· **Регресс относительно** [P2-7](#p2-7--отчётный-скрипт-несогласованные-метрики)

P2-7 закрыт как «✅ СДЕЛАНО», в том числе пункт 1 — «`FINAL-REPORT.json` валиден».
В прогоне №4 он **невалиден ровно тем же способом**, что и до починки:

```json
"alerts": { "before": ,  "after": ,  "new":  },
"events": { "before": ,  "after": ,  "new":  },
"anomalies": { "before": ,  "after": ,  "new":  }
```

Три блока с пустыми значениями — файл не парсится ни одним JSON-парсером. При этом
**текстовый** отчёт те же значения печатает корректно (`Alerts Total: 2187 → 3942`), то
есть подстановка работает для `.txt` и не работает для `.json` — правка P2-7 п.1,
судя по всему, коснулась только текстовой ветки.

**Расхождения текстового отчёта с фактическими данными** (не ошибка агента, ошибка счёта):

| Показатель | FINAL-REPORT | Факт по `alerts-*.json` / `metrics-*` |
|---|---|---|
| Новых алертов | 1755 | **2282** (по дельте id) / 2282 по `alerts_total` |
| Alerts Total before/after | 2187 / 3942 | 2281 / 4563 по `ebpf_guard_alerts_total` |
| Anomalies Total | 0 → 0, новых 0 | **28 → 87** (`ebpf_guard_anomalies_total` существует) |
| Learning Phase | `complete=unknown` | `learning_complete: true` в `/api/v1/status` |
| sqlmap «Попыток атак» | 2 | 283 алерта от `comm=sqlmap` |

- **`anomalies_total` читается неверно** — метрика есть и растёт (28→87, ровно 59 новых,
  что совпадает с 59 алертами `anomaly_detection` в дельте), а отчёт печатает 0 и выдаёт
  рекомендацию «⚠️ Детектировано мало аномалий → проверьте настройку profiler». Это
  ложная рекомендация: профайлер как раз отработал. P2-7 п.3 («имя синхронизировано»)
  не действует.
- **`Learning Phase: unknown`** — P2-7 п.6 добавлял опрос `/api/v1/status`; в этом
  прогоне `/api/v1/status` отдаёт `learning_complete: true`, а отчёт — `unknown`.
  Вероятно, парсится не тот ключ или не тот эндпоинт.
- **Расхождение 1755 vs 2282** — отчёт считает дельту по метрикам, снятым в другой
  момент, чем `alerts-after.json`; либо суммирует не все серии `ebpf_guard_alerts_total`
  (их 52 после атаки против 45 до — появились новые `rule_id`, и если сумма берётся по
  фиксированному списку, новые правила теряются).

**Что сделать.**
- Починить JSON-ветку генерации отчёта (та же инициализация нулём, что в текстовой) и
  **добавить в скрипт проверку `jq . FINAL-REPORT.json`** — без неё регресс повторится
  в третий раз.
- Снимать метрики и `alerts.json` одним срезом; сумму по `ebpf_guard_alerts_total`
  считать по всем сериям.
- Починить чтение `anomalies_total` и `Learning Phase`.

**Критерий приёмки.** `jq . FINAL-REPORT.json` проходит; числа в текстовом и JSON-отчёте
совпадают между собой и с `alerts-*.json` (±0); блок `Learning Phase` не содержит
`unknown` на прогоне, где обучение завершено.

---

# Что подтвердилось хорошего в прогоне №4

Отдельно, чтобы не потерялось за списком проблем — это первый прогон, где следующее
проверено **под реальной атакующей нагрузкой**, а не на idle:

| Проверка | Результат |
|---|---|
| **P0-24, UTF-8-паника** | ✅ **держит на боевом трафике** — 0 паник, 0 рестартов за 26 минут uptime, при том что атака генерирует ровно тот класс данных (обфусцированные имена, бинарные байты), который ронял агент 2026-08-04 |
| Стабильность под нагрузкой | ✅ 0 незапланированных рестартов, `Main process exited` в журнале нет |
| Доступность API | ✅ `healthy: true, ready: true` до, во время и после; ни одного 503 (P1-5) |
| Canary (P1-17, главный подпункт) | ✅ **0** срабатываний `canary_*` против 903 за ночь — исключение по PID работает |
| `/debug/state` engine_stats и rules (P1-10) | ✅ живые значения: 9.4 млн событий, 4297 алертов, 591 правило |
| `ebpf_guard_anomalies_total` (P2-15) | ✅ метрика есть и растёт 28 → 87; лог `profiler: learning complete samples=1826675 elapsed_seconds=300` присутствует |
| Дедупликация логов watchdog (P1-18a) | ✅ журнал читаем: 78 INFO + 329 WARN за прогон вместо 1626 строк флаппинга |
| DNS ERROR при shutdown (P2-20) | ✅ **0 ERROR** в журнале за весь прогон, включая штатное завершение |
| Память | ✅ RSS 293 МБ → 346 МБ под атакой, без признаков утечки за окно прогона |
| Детект как таковой | ✅ атака детектируется: portscan 80, C2-beacon 79+79, SSRF 77, web-recon 77, exfil 77, high-frequency 74 — 43 уникальных типа, 852 алерта от атакующих процессов |

Важная оговорка к последней строке: **детект есть, корреляция его не собирает** — ни один
из этих сигналов не стал инцидентом (см. P1-13), а 114 инцидентов, которые агент выдал,
все до одного построены на `sshd`.

---

# Что проверено idle-прогоном и оказалось в порядке

Эти гипотезы из плана idle-прогона **не подтвердились** — отдельных задач не требуют:

| Гипотеза | Результат |
|---|---|
| Утечка памяти | ✅ RSS вышел на плато: 202 МБ → 224 МБ за 9 ч (рост только в первые 2 ч) |
| P1-11: неограниченный рост cardinality | ✅ плато ~660 серий (прогноз «десятки тысяч» не подтвердился) |
| Потеря событий под нагрузкой | ✅ `events_dropped_total = 0`, `event_queue_dropped_total = 0` по всем коллекторам |
| P1-5: отказы API | ✅ `healthy:true, ready:true` во всех 109 срезах за 9 часов |
| Стабильность агента | ✅ ноль незапланированных рестартов и падений (2 рестарта — оба намеренные) |
| Механизм rule exceptions | ✅ работает: 5420 подавлений за ночь, нужно лишь расширить покрытие (P1-6, P1-17) |
