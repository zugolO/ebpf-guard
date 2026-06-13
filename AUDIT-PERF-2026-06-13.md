# ebpf-guard — Аудит производительности, корректности и готовности к CNCF (2026-06-13)

Независимый аудит: реальная сборка, прогон тестов, микробенчмарков горячего пути и
сравнительных бенчмарков. Документ дополняет `ISSUES.md` (там — безопасность) и
фокусируется на **производительности, узких местах, размере и готовности к
opensource / CNCF Sandbox**.

Каждая задача: файл:строка → проблема → фикс → приоритет → эффект.

---

## Содержание

- [🔴 P0 — Блокеры](#-p0--блокеры)
- [🟠 P1 — Узкие места горячего пути](#-p1--узкие-места-горячего-пути)
- [🟡 P2 — Аллокации на пути алертов](#-p2--аллокации-на-пути-алертов)
- [📊 Бенчмарки против конкурентов](#-бенчмарки-против-конкурентов)
- [📦 Размер бинарника и зависимости](#-размер-бинарника-и-зависимости)
- [🎯 Готовность к CNCF Sandbox](#-готовность-к-cncf-sandbox)
- [📈 Замеренные числа (reference)](#-замеренные-числа-reference)

---

## 🔴 P0 — Блокеры

### P0-1 · Проект не компилировался (ИСПРАВЛЕНО в этой ветке)

**Файл:** `internal/enforcer/enforcer.go:15`

**Проблема.**
Коммит `46910fe ("up")` вынес kill-логику в новый файл `kill.go`, но оставил
ставший лишним импорт `"syscall"` в `enforcer.go`. Go требует, чтобы импорт
использовался в **том же файле**. В результате:

```
internal/enforcer/enforcer.go:15:2: "syscall" imported and not used
```

Пакет `enforcer` не собирался, а вместе с ним каскадно падали:

```
FAIL github.com/zugolO/ebpf-guard/cmd/ebpf-guard      [build failed]
FAIL github.com/zugolO/ebpf-guard/e2e                 [build failed]
FAIL github.com/zugolO/ebpf-guard/internal/enforcer   [build failed]
```

То есть в `main` лежал нерабочий релиз: бинарник `cmd/ebpf-guard` не собирался.

**Фикс.** Удалён мёртвый импорт. `go build ./...` → exit 0, тесты enforcer → ok.
(Уже закоммичено отдельным коммитом в этой ветке.)

### P0-2 · В CI нет блокирующего gate на сборку

**Проблема.**
Сам факт того, что некомпилирующийся коммит попал в `main`, означает, что в
GitHub Actions нет обязательного шага `go build ./...` / `go vet ./...`,
блокирующего мёрж. Для CNCF Sandbox это критично — доверие к проекту падает,
если `main` не собирается.

**Фикс.**
- Добавить в workflow обязательный job: `go build ./...` и `go vet ./...` на
  каждый PR, помеченный как required check в branch protection.
- Добавить `golangci-lint run` (в репозитории уже есть `.golangci.yml`).
- Рассмотреть `staticcheck` — он ловит unused imports/vars до мёржа.

**Приоритет:** P0 — важнее любой оптимизации.

---

## 🟠 P1 — Узкие места горячего пути

> Реальный per-event путь (`EvaluateInto`) уже отличный: no-match 6.5 ns/op,
> match 58 ns/op, 0 allocs. Индекс правил по `event_type` работает. Ниже —
> блокировки, которые берутся **на каждое событие** и мешают масштабированию
> на 100k+ ev/s и многоядерных узлах.

### P1-1 · RWMutex на каждый ProcessEvent — `IsEnabled()`

**Файл:** `internal/profiler/anomaly.go:591`

**Проблема.**
`AnomalyDetector.IsEnabled()` берёт `RWMutex.RLock()` на **каждый** вызов
`ProcessEvent` (anomaly.go:151). Поле `enabled` меняется крайне редко — мьютекс
избыточен и создаёт точку синхронизации между всеми воркерами.

**Фикс.** Заменить `enabled bool` на `atomic.Bool` → lock-free чтение.

**Эффект:** убирает 100k+ захватов лока/сек на высоконагруженных узлах.

### P1-2 · RWMutex на каждый event — `SamplingCorrectionFactor()`

**Файл:** `internal/profiler/anomaly.go:660` (вызов из `:166`)

**Проблема.**
Берёт `RLock` per event, чтобы прочитать map `samplingCorrections`.

**Фикс.** Хранить map за `atomic.Pointer[map[...]float64]`; читать без лока,
заменять целиком при обновлении (copy-on-write).

### P1-3 · Два лока per event + общий менеджер профилей

**Файл:** `internal/profiler/workload.go:224`

**Проблема.**
`WorkloadProfileManager.RecordEvent` берёт два лока подряд (`wpm.mu`, затем
`p.mu`) на каждое событие. При этом **все** ingest-воркеры
(`engine.go:731`, N=8..64) делят один `WorkloadProfileManager`, поэтому
`wpm.mu` — глобальная точка контеншена под нагрузкой.

**Фикс.** Шардировать менеджер по workload-ключу (как `ShardedEventBuffer`),
либо lock-free lookup профиля (sync.Map / CAS) после фазы обучения, когда набор
профилей стабилен.

### P1-4 · `pendingMu` на каждый сгенерированный алерт

**Файл:** `internal/correlator/engine.go:1443` (а также `:860`, `:1536`)

**Проблема.**
```go
ce.pendingMu.Lock()
ce.pending = append(ce.pending, alerts...)
ce.pendingMu.Unlock()
```
Каждый алерт берёт центральный мьютекс; Rego-воркеры (`:860`) конкурируют там же.
При высокой доле матчей — центральное бутылочное горлышко.

**Фикс.** Per-goroutine (per-worker) буферы алертов с периодическим флашем под
одним локом, либо lock-free MPMC-очередь.

### P1-5 · Синхронный OPA-eval блокирует чтение ring buffer

**Файл:** `internal/correlator/engine.go:1423`

**Проблема.**
При заполнении `regoQueue` (default 4096) код в `default`-ветке **синхронно**
выполняет дорогой `evaluateRegoPolicies` прямо в событийной горутине, блокируя
чтение BPF ring buffer → backpressure на весь конвейер коллектор→коррелятор.

**Фикс.** При переполнении — дропать с инкрементом `regoQueueDropped` (метрика
уже есть) и/или растить число OPA-воркеров, но **не** выполнять eval синхронно.

### P1-6 · Один «горячий» PID забивает очередь воркера

**Файл:** `internal/correlator/engine.go:745` (буфер 1024) + `:1029`
(`e.PID & ce.ingestMask`)

**Проблема.**
PID-шардинг направляет все события одного PID в одного воркера с фиксированным
буфером 1024. Один шумный процесс (например, форк-бомба или нагруженный
веб-сервер) переполняет свою очередь и блокирует reader.

**Фикс.** Сделать размер буфера конфигурируемым; рассмотреть адаптивный
backpressure или вторичный overflow-буфер с дроп-метрикой.

---

## 🟡 P2 — Аллокации на пути алертов

> Срабатывают только при матче (не per-event), но видны в бенчах и раздувают
> p99 при всплесках алертов.

### P2-1 · `map[string]interface{}` Details на каждый алерт

**Файлы:** `internal/correlator/engine.go:1294`, `:1381`

**Проблема.**
Details-map аллоцируется на каждый алерт (anomaly, allowlist-violation). Сама
структура `types.Alert` тяжёлая: `BenchmarkAlertIDGeneration` = 1054 ns/op,
**2716 B/op**, 3 allocs — основной вклад это копия `Alert` + map.

**Фикс.** Перейти на типизированные поля в `Alert` вместо `map[string]interface{}`,
либо пул map'ов. Рассмотреть возврат алертов через переиспользуемый буфер
(как `EvaluateInto`), а не slice по значению.

### P2-2 · `fmt.Sprintf` на пути алертов

**Файлы:** `internal/correlator/engine.go:1277` (PID), `:1367` (syscall_nr),
`internal/correlator/rules.go:1179`, `:1220`, `:1222` (hex caps/GPU)

**Проблема.** `fmt.Sprintf("%d"/"0x%x", ...)` аллоцирует.

**Фикс.** `strconv.FormatUint` / ручная hex-конкатенация.

### P2-3 · Конкатенация строк в цикле — `formatAnomalyDescription`

**Файл:** `internal/correlator/engine.go:1861-1873`

**Проблема.** `desc += contrib.Field + "=" + contrib.Value` в цикле —
N аллокаций.

**Фикс.** `strings.Builder` с `Grow`.

### P2-4 · Дорогие, но кэшируемые вычисления

**Файлы:** `internal/correlator/rules.go` (DNS), profiler entropy.

- Shannon-энтропия = 1260 ns/op, DNS-энтропия = 1099 ns/op. Кэш сбивает до
  258 ns (`BenchmarkDNSPrefilter/benign/cached`). **Убедиться, что кэш реально
  горячий в проде** — иначе на каждом DNS-событии ~1.1 µs.
- `MiningPoolDetector.IsMiningPoolIP` = 602 ns/op — проверить, не вызывается ли
  на каждом сетевом событии без префильтра.
- `fnv.New32()` в `shouldSample` (`rules.go:659`) аллоцирует хэшер; вынести в
  `sync.Pool` или развернуть FNV-1 вручную на стеке (актуально только при
  `sample_rate < 1.0`).

### P2-5 · Lineage / Sequence профайлеры

**Файлы:** `internal/profiler/` (lineage, sequence)

- `BenchmarkLineageTrackerUpdate` = 2276 ns/op, 442 B, 4 allocs.
- `BenchmarkSequenceProfilerUpdate` = 1921 ns/op, `CosineDistance` = 654 ns/op.

Это самые тяжёлые узлы профайлера. Если включены глобально — проверить, что они
идут за семплингом / только для подозрительных цепочек, а не на 100% событий.

---

## 📊 Бенчмарки против конкурентов

### B-1 · Сравнительные бенчмарки методологически нечестны (против самих себя)

**Файлы:** `bench/vs_falco_test.go`, `bench/vs_tetragon_test.go`,
`bench/vs_tracee_test.go`

**Проблема.**
Бенчмарки конкурентов меряют **только матчинг**, а ebpf-guard прогоняют через
полный аллоцирующий `Evaluate()` (с генерацией slice алертов и фингерпринтом):

```
BenchmarkFalcoRuleEval        18.5 ns/op    0 allocs   ← только матчинг
BenchmarkEbpfGuardRuleEval    528  ns/op   10 allocs   ← матчинг + генерация алерта
BenchmarkRuleEval_Tracee      11.9 ns/op    0 allocs   ← только матчинг
BenchmarkRuleEval_EbpfGuard  1324  ns/op    3 allocs   ← Evaluate() аллоцирует
BenchmarkRuleEval_EbpfGuard_Callback  78 ns/op  1 alloc ← вот это сопоставимо
```

Получается «ebpf-guard в 70× медленнее Falco», хотя **реальный** матчинг
ebpf-guard — 6–58 ns/op, 0 allocs (см. `BenchmarkRuleEval_Match`). На ревью
CNCF / Hacker News такую таблицу разберут и она ударит по доверию.

**Фикс.**
- Сравнивать **сопоставимый объём работы**: матчинг конкурента vs `EvaluateInto`
  ebpf-guard (0-alloc путь), а не `Evaluate()`.
- Если хочется показать полный путь — показать обе стороны с генерацией алерта
  (и тогда добавить эквивалент output-формирования у конкурента).
- В README/доках чётко отделять «cost of rule match» от «cost of alert emit».

### B-2 · Реальный end-to-end прогон ещё не выполнен

Инфраструктура (`bench/comparative/run.sh`, Vagrantfile, INSTALL.md) описана
корректно и методология честно разделяет `algorithm-only` vs `end-to-end`. Но
сами e2e-числа против настоящих Falco 0.38 / Tetragon 1.1 / Tracee 0.21 ещё не
сняты (нужен reference-VM с ядром, eBPF, root и установленными агентами).

**Фикс.** Прогнать `sudo bench/comparative/run.sh --sweep` на reference-VM,
закоммитить датированные CSV/MD в `bench/comparative/results/` вместе с `env-*.txt`.

---

## 📦 Размер бинарника и зависимости

**Замеры:**
- Бинарник: **57 МБ** обычный, **41 МБ** stripped (`-ldflags="-s -w"`).
- **255 модулей** в графе зависимостей.

Для Go с OPA + k8s client-go + sqlite это в пределах нормы (Tracee ~80 МБ), но
«маленьким» не назвать. Главные тяжеловесы:
`open-policy-agent/opa`, `k8s.io/client-go`, `IBM/sarama` (Kafka),
`charmbracelet/bubbletea` (TUI).

### D-1 · Вынести опциональные подсистемы за build-теги

**Фикс.** Core-агенту в рантайме не нужны OPA, Kafka и TUI одновременно:
- `//go:build rego` — OPA/Rego policy engine.
- `//go:build kafka` — sarama-экспортер.
- TUI (`internal/tui`) — отдельный бинарник или build-тег.

**Эффект:** минус десятки МБ и сотни транзитивных зависимостей в дефолтной
сборке → меньше площадь supply-chain атаки (важный критерий для CNCF).

---

## 🎯 Готовность к CNCF Sandbox

**Уже есть (выше среднего для кандидата):** `LICENSE`, `GOVERNANCE.md`,
`MAINTAINERS.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`ADOPTERS.md`, `SBOM.md`, GoReleaser + cosign + SLSA 3.

**Закрыть до подачи:**
1. **CI-gate на сборку** (P0-2) — `main` обязан собираться. Это сейчас риск №1
   для доверия.
2. **Честные бенчмарки** (B-1) — иначе перформанс-заявления подорвут репутацию.
3. **Реальные adopters** (не примеры) усиливают заявку (для Sandbox не блокируют).
4. **Нейтральность бренда** — подготовить имя/неймспейс (`zugolO`), логотип и
   домен к передаче в нейтральную организацию.
5. **Воспроизводимые e2e-бенчи** (B-2) с зафиксированным reference-hardware.

---

## 📈 Замеренные числа (reference)

> Хост: Intel Xeon @ 2.80 GHz, 4 vCPU, Go 1.25, Linux 6.18. Микробенчмарки
> in-process, без ядра.

**Горячий путь — отлично:**

| Бенчмарк | ns/op | allocs |
|---|---|---|
| RuleEval no-match (по типу) | 6.5 | 0 |
| RuleEval no-match (по условию) | 28 | 0 |
| RuleEval match | 58 | 0 |
| RuleEval multi-rule | 223 | 0 |
| ShardedEventBuffer.Add | 165 | 0 |
| Profiler ProcessEvent | 636 | 0 |
| ShouldSample (deterministic) | 9.6 | 0 |

**Пути с аллокациями (только при матче/алерте):**

| Бенчмарк | ns/op | B/op | allocs |
|---|---|---|---|
| AlertIDGeneration (full Evaluate) | 1054 | 2716 | 3 |
| LineageTrackerUpdate | 2276 | 442 | 4 |
| SequenceProfilerUpdate | 1921 | 0 | 0 |
| ShannonEntropy | 1260 | 0 | 0 |
| DNSEntropy | 1099 | 0 | 0 |
| MiningPoolDetector.IsMiningPoolIP | 602 | 0 | 0 |

---

*Аудит подготовлен автоматизированным код-ревью. P0-1 уже исправлен в этой ветке;
остальные задачи — бэклог для последующих PR.*
