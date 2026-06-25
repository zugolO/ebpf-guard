# ebpf-guard — Backlog задач (аудит 2026-06-13)

Полный список задач по результатам анализа кода, тестов, бенчмарков и сравнения с конкурентами.

---

## Содержание

- [🔴 HIGH — Уязвимости безопасности](#-high--уязвимости-безопасности)
- [🟠 MEDIUM — Уязвимости безопасности](#-medium--уязвимости-безопасности)
- [🟡 LOW — Уязвимости безопасности](#-low--уязвимости-безопасности)
- [🟣 Hardening — Усиление защиты](#-hardening--усиление-защиты)
- [🔵 Тесты и документация](#-тесты-и-документация)
- [🟢 Функциональность и дорожная карта](#-функциональность-и-дорожная-карта)

---

## 🔴 HIGH — Уязвимости безопасности

### H-1 · Предсказуемый fallback-токен авторизации

**Файл:** `cmd/ebpf-guard/main.go:1311–1322`

**Проблема.**
Функция `generateToken()` при ошибке открытия или чтения `/dev/urandom` возвращает
строковую константу `"insecure-fallback-change-me"`. При этом в лог пишется
`"generated admin token (not shown for security)"` — оператор не знает, что токен
публично известен. Итог: любой желающий делает `GET /alerts?token=insecure-fallback-change-me`
и получает полный доступ к API, включая горячую перезагрузку BPF-правил.

Ситуация возникает в seccomp-ограниченном контейнере, блокирующем `openat` на
`/dev/urandom`/`/dev/random`, или при очень раннем старте до монтирования devtmpfs.

Есть ещё одна смежная проблема: даже при успешной генерации токен **никогда не
показывается** в логах (`"not shown for security"`), поэтому оператор в принципе
не может получить токен из pod-логов и не может использовать CLI-команды
`ebpf-guard alerts` / `ebpf-guard status` без ручного патча конфига.

**Сценарий атаки:**
1. Агент деплоится в seccomp-профиль, блокирующий `openat` на devtmpfs.
2. Агент стартует, лог: `"admin token: [not shown for security]"`.
3. Атакующий отправляет `GET /alerts` с заголовком `Authorization: Bearer insecure-fallback-change-me` — полный доступ.
4. Атакующий загружает вредоносный YAML с правилом `action: kill` через `POST /rules`.

**Фикс:**
```go
import "crypto/rand"

func generateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("cannot generate auth token: %w", err)
    }
    return hex.EncodeToString(b), nil
}
```
- Использовать `crypto/rand` вместо прямого открытия `/dev/urandom` (уже есть в stdlib).
- При ошибке — **fail-closed**: отказаться от запуска с понятным сообщением.
- При успешной генерации — вывести токен в лог **один раз** с пометкой
  "сохраните, повторно показан не будет", либо записать в `/run/ebpf-guard/token`
  (mode `0600`).

---

### H-2 · Подделка syslog-записей через неэкранированный `alert.Message`

**Файл:** `internal/exporter/syslog_cef.go:265`

**Проблема.**
`formatRFC5424` вставляет `alert.Message` непосредственно в RFC 5424-строку через
`fmt.Fprintln`. `alert.Message` формируется из данных, которые контролирует
атакующий: DNS-имена, пути к файлам, имена процессов (`comm`). Символ `\n` внутри
поля разрывает текущую syslog-запись и создаёт новую — полностью под контролем
атакующего. Функция `escapeSD` (строки 270–275) экранирует `\`, `"`, `]` по
RFC 5424, но не трогает `\n`, `\r` и другие управляющие символы.

**Сценарий атаки:**
1. Атакующий запускает процесс с именем, содержащим `\n<190>1 2026-01-01T00:00:00Z host ebpf-guard - - - CRITICAL: root shell opened`.
2. ebpf-guard записывает событие в syslog.
3. SIEM-система получает две записи: оригинальную и поддельную с произвольным содержимым.
4. Поддельная запись может подавить настоящий алерт или добавить ложные инциденты.

**Фикс:**
```go
// Очищать управляющие символы из всего поля сообщения перед записью.
func sanitizeLogField(s string) string {
    return strings.Map(func(r rune) rune {
        if r < 0x20 || r == 0x7f {
            return ' '
        }
        return r
    }, s)
}
```
Применить `sanitizeLogField` к `alert.Message`, `alert.Comm`, `alert.RuleName`
перед формированием RFC 5424 и CEF строк.

---

### H-3 · Таймаут WASM-плагина не работает — возможна блокировка пайплайна

**Файл:** `internal/wasm/engine.go:59–60`

**Проблема.**
Wazero runtime создаётся **без** `WithCloseOnContextDone(true)`:
```go
rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
    WithMemoryLimitPages(256))
```
По документации wazero, без этой опции runtime **игнорирует дедлайны контекста**.
Несмотря на то что каждый вызов плагина оборачивается в `context.WithTimeout`,
таймаут не срабатывает. WASM-плагин с бесконечным циклом или очень долгим
вычислением навсегда блокирует goroutine event-пайплайна → детекция останавливается
полностью.

**Сценарий атаки:**
1. Оператор устанавливает вредоносный `.wasm`-плагин (например, из непроверенного источника).
2. Плагин содержит `for(;;) {}` в функции `evaluate`.
3. Первый же вызов блокирует goroutine — новые события не обрабатываются.
4. Агент жив (healthcheck отвечает), но детекция мертва.

**Фикс — одна строка:**
```go
rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
    WithMemoryLimitPages(256).
    WithCloseOnContextDone(true))  // ← добавить
```

---

### H-4 · OTLP-экспортер игнорирует `tls_enabled` — алерты уходят в открытом виде

**Файл:** `internal/exporter/otlp.go:28,114–122,152–154`

**Проблема.**
Документированный дефолт эндпоинта — `http://otel-collector:4318`. Если оператор
устанавливает `tls_enabled: true`, но не меняет схему URL, схема не переписывается
и не проверяется. Алерты и карта `Headers` (bearer-токены, API-ключи) уходят по
HTTP в открытом тексте, несмотря на включённый TLS.

**Фикс:**
```go
// В конструкторе клиента:
if cfg.TLSEnabled && !strings.HasPrefix(cfg.Endpoint, "https://") {
    return nil, fmt.Errorf(
        "otlp: tls_enabled=true requires https:// endpoint, got %q", cfg.Endpoint,
    )
}
```
Дополнительно: обновить документацию и дефолт эндпоинта на `https://`.

---

### H-5 · Kafka SASL PLAIN отправляет пароль в открытом виде при отключённом TLS

**Файл:** `internal/exporter/kafka.go:111–116`

**Проблема.**
`sasl_enabled: true` совместим с `tls_enabled: false`. SASL PLAIN передаёт
`username:password` в base64 (фактически открытый текст) по незашифрованному
TCP-соединению. Любой, кто может перехватить трафик внутри кластера, получает
учётные данные Kafka.

**Фикс:**
```go
if cfg.SASLEnabled && cfg.SASLMechanism == "PLAIN" && !cfg.TLSEnabled {
    return nil, errors.New(
        "kafka: SASL PLAIN requires tls_enabled: true to avoid credential exposure",
    )
}
```

---

## 🟠 MEDIUM — Уязвимости безопасности

### M-1 · Инъекция в webhook JSON через неэкранированный `alert.Comm` / `RuleName`

**Файл:** `internal/exporter/webhook.go:80–81`

**Проблема.**
Дефолтный шаблон webhook рендерит `{{.Comm}}` и `{{.RuleName}}` без функции
`| json`, тогда как `{{.Message}}` корректно экранируется. `alert.Comm` —
сырые данные из BPF (`prctl(PR_SET_NAME)`), которые процесс может установить
произвольно. Имя вида `evil", "admin": true, "x": "` ломает JSON-структуру
исходящего запроса и позволяет инжектировать произвольные поля.

**Сценарий:** процесс выполняет `prctl(PR_SET_NAME, '", "kill": true, "y": "')`,
ebpf-guard отправляет сломанный JSON в webhook-получатель; если получатель
разбирает JSON нестрого — эффект зависит от его реализации.

**Фикс:**
```
"comm":      {{.Comm     | json}},
"rule_name": {{.RuleName | json}},
```
Применить `| json` ко всем полям, источником которых являются BPF-данные.

---

### M-2 · Инъекция в syslog Structured Data через `\n` в имени процесса

**Файл:** `internal/exporter/syslog_cef.go:270–275` (`escapeSD`)

**Проблема.**
`escapeSD` экранирует `\`, `"`, `]` по RFC 5424 §6.3.3, но пропускает `\n`/`\r`.
Имя процесса с переводом строки (`prctl(PR_SET_NAME, "foo\nbar")`) разрывает
SD-элемент и создаёт дополнительную syslog-запись. Проблема независима от H-2
(затрагивает поле SD, а не MSG).

**Фикс:**
```go
func escapeSD(s string) string {
    var b strings.Builder
    for _, r := range s {
        switch r {
        case '\\', '"', ']':
            b.WriteRune('\\')
            b.WriteRune(r)
        case '\n', '\r':
            b.WriteString(`\n`) // или просто пробел
        default:
            if r < 0x20 {
                continue // strip other control chars
            }
            b.WriteRune(r)
        }
    }
    return b.String()
}
```

---

### M-3 · Секреты уведомителей утекают в логи через `*url.Error`

**Файлы:**
- `internal/exporter/telegram.go:94–96` — токен бота в пути URL
- `internal/exporter/discord.go:83–86` — секрет webhook в пути URL
- `internal/exporter/teams.go:84–87` — секрет webhook в пути URL

**Проблема.**
При сетевой ошибке Go оборачивает её в `*url.Error`, который включает полный URL
запроса. Этот URL логируется на уровне WARN/ERROR. Telegram bot token, Discord
webhook secret, Teams webhook secret попадают в pod-логи и любую систему
агрегации логов.

**Фикс:**
```go
func redactURLError(err error) error {
    var urlErr *url.Error
    if errors.As(err, &urlErr) {
        urlErr.URL = "[redacted]"
    }
    return err
}
// Применить перед логированием ошибки отправки.
```

---

### M-4 · Паника хоста из WASM-плагина при нулевом количестве возвращаемых значений

**Файл:** `internal/wasm/plugin.go:128–132, 138–149`

**Проблема.**
`allocResults[0]` и `evalResults[0]` индексируются без предварительной проверки
`len(results) > 0`. `ValidatePlugin` проверяет наличие экспортируемых функций
`malloc` и `evaluate`, но не проверяет их сигнатуру (количество и типы
возвращаемых значений). Плагин, экспортирующий `evaluate` как void-функцию,
пройдёт валидацию и вызовет `panic: runtime error: index out of range`,
роняя весь агент.

**Фикс:**
```go
if len(allocResults) == 0 {
    return 0, fmt.Errorf("wasm plugin %q: malloc returned no results", p.name)
}
if len(evalResults) == 0 {
    return nil, fmt.Errorf("wasm plugin %q: evaluate returned no results", p.name)
}
```
Дополнительно: в `ValidatePlugin` проверять сигнатуру функций, а не только их наличие.

---

## 🟡 LOW — Уязвимости безопасности

### L-1 · Gossip-эндпоинты открыты при пустом `Secret`

**Файл:** `internal/gossip/http.go:120–122`

**Проблема.**
`authCheck` возвращает `true` (разрешить), когда `Secret == ""`. Если gossip
включён, но секрет не задан, любой узел кластера может отправлять произвольные
IOC-данные, снижать аномальные пороги или провоцировать amplification-алерты.

**Фикс:**
При `Secret == ""` и включённом gossip — либо отказываться от старта с ошибкой,
либо отключать HTTP-эндпоинты gossip (принимать только исходящие соединения).

---

### L-2 · Ошибка чтения CA-сертификата не фатальна — TLS-пиннинг обходится молча

**Файлы:** `internal/exporter/otlp.go:95–101`, `internal/exporter/kafka.go:91–97`

**Проблема.**
Если файл `ca_cert` указан, но недоступен (неверный путь, права доступа), ошибка
только логируется, а клиент создаётся с системными корневыми сертификатами.
Оператор думает, что пиннинг работает, но фактически любой CA может подписать
сертификат.

**Фикс:**
```go
caCert, err := os.ReadFile(cfg.CACert)
if err != nil {
    return nil, fmt.Errorf("cannot load ca_cert %q: %w", cfg.CACert, err)
}
```

---

### L-3 · CEF-заголовок не защищён от переноса строки

**Файл:** `internal/exporter/syslog_cef.go:331–335` (`escapeCEFHeader`)

**Проблема.**
`escapeCEFHeader` экранирует `|` и `\` (по спецификации ArcSight CEF), но не
`\n`/`\r`. Имена правил (`RuleName`) могут быть импортированы из внешних YAML
через Falco-мигратор — поле доступно для ввода оператора и потенциально из
непроверенных rule-файлов. Встроенный перевод строки разрывает CEF-запись.

Примечание: `escapeCEF` для расширений и экспорт через `/api/v1/alerts/export/cef`
(`api.go:613`) уже корректно экранируют переносы строк. Нужно унифицировать.

**Фикс:** добавить `\n` и `\r` в набор символов, экранируемых `escapeCEFHeader`.

---

### L-4 · Флаг TLS-верификации инвертирован в MISP/OpenCTI — нулевое значение отключает проверку

**Файлы:** `internal/exporter/misp.go:57`, `internal/exporter/opencti.go:27`

**Проблема.**
Поле `VerifyTLS bool` имеет нулевое значение `false`, что означает «не проверять».
Конфиги, загружаемые через Viper, безопасны (дефолт `true` в `config.go:1589,1597`).
Но любой код, создающий структуру напрямую (тесты, будущие интеграции), молча
отключает верификацию TLS и позволяет утечку API-ключей через MITM.

**Фикс:**
Переименовать в `InsecureSkipVerify bool` — нулевое значение теперь означает
«проверять», что соответствует соглашению `crypto/tls.Config`. Обновить все
вызовы.

---

### L-5 · Discord-уведомления допускают спуфинг через markdown в именах процессов

**Файл:** `internal/exporter/discord.go:130–164`

**Проблема.**
Поля `alert.Comm`, `alert.Message`, `alert.RuleName` вставляются в embed-поля
Discord без экранирования markdown. Процесс с именем вида
`[Нажмите для обновления](https://phishing.example)` отобразится как кликабельная
ссылка в уведомлении безопасности. JSON-структура не нарушается (проходит через
`json.Marshal`), риск — только косметический (masked links, выдача за другой
источник).

**Фикс:**
Экранировать Discord markdown-символы (`*`, `_`, `~`, `` ` ``, `[`, `]`, `>`) в
user-influenced полях.

---

## 🟣 Hardening — Усиление защиты

### HD-1 · Распространить SSRF-защиту на все уведомители

**Контекст.**
Защита `strict_ssrf` из коммита `af5c1b4` покрывает только Alertmanager-клиент.
Все остальные HTTP-клиенты (generic webhook, Slack, Teams, Discord, Telegram,
OTLP) не проверяют URL на приватные диапазоны.

В Kubernetes-среде атакующий, способный влиять на конфиг (или через инжекцию
правила с кастомным webhook-действием), может достучаться до `169.254.169.254`
(instance metadata AWS/GCP/Azure), внутренних сервисов или Secret Manager API.

**Задача.**
Вынести `validateWebhookURL(url string, strict bool)` в общий хелпер и применять
его ко всем HTTP-клиентам при инициализации, а не только к Alertmanager.

---

### HD-2 · Оператор не может получить автосгенерированный токен

**Контекст.**
`main.go:514–521` пишет `"admin token: [not shown for security]"` — при
автогенерации токена оператор не может его узнать без перезапуска агента с
явным `auth.token` в конфиге. Это делает CLI-команды (`ebpf-guard alerts`,
`ebpf-guard status`) нефункциональными после `helm install` без дополнительных
действий.

**Задача.**
Варианты (выбрать один):
1. Вывести токен один раз в лог при первом старте с пометкой «сохраните».
2. Записать токен в `/run/ebpf-guard/token` (mode `0600`) — аналогично k3s kubeconfig.
3. Сохранять токен в Kubernetes Secret при деплое через Helm (post-install hook).

---

### HD-3 · Swagger UI загружается с CDN unpkg.com — зависимость от третьей стороны

**Файл:** `internal/exporter/api.go:709–713`

**Контекст.**
Swagger UI подключается из `https://unpkg.com/swagger-ui-dist/`. Компрометация
CDN, BGP-хайджекинг или man-in-the-middle позволяют внедрить произвольный
JavaScript в документацию API. Если оператор открыл Swagger UI с bearer-токеном
в браузере — токен может быть похищен.

**Задача.**
Один из вариантов:
1. Встроить `swagger-ui-dist` в бинарник через `//go:embed`.
2. Добавить атрибуты SRI (`integrity=sha384-...`) для каждого CDN-ресурса.

---

### HD-4 · Проверять права доступа к файлу конфига при загрузке

**Контекст.**
Конфиг-файл может содержать пароли OpenSearch, webhook-URL, API-токены (несмотря
на env-var оверрайды, операторы часто оставляют секреты в YAML). Агент не
проверяет права доступа к файлу при старте.

**Задача.**
При загрузке конфига проверять `stat()` и предупреждать (или при `strict_config`
— завершаться), если файл доступен для чтения группой или всем:

```go
info, err := os.Stat(path)
if err == nil && info.Mode()&0044 != 0 {
    slog.Warn("config file is readable by group/world — consider chmod 0600",
        "path", path, "mode", info.Mode())
}
```

---

### HD-5 · Добавить CSP-заголовок и ограничить CORS на `/api/openapi.yaml`

**Файл:** `internal/exporter/api.go:731`

**Контекст.**
`Access-Control-Allow-Origin: *` на эндпоинте OpenAPI-спеки позволяет любому
origin читать полную спецификацию API. В сочетании с отсутствием
`Content-Security-Policy` на Swagger UI это открывает возможность CSRF-атак через
вредоносный сайт, если оператор авторизован в браузере.

**Задача.**
1. Заменить wildcard CORS на настраиваемый allowlist (`cors.allowed_origins` в конфиге).
2. Добавить CSP к Swagger UI-маршруту: `script-src 'self'`, `connect-src 'self'`.

---

## 🔵 Тесты и документация

### T-1 · Флакующий тест `TestManager_Watch_MultipleChanges`

**Файл:** `internal/config/config_test.go:217`

**Симптом.**
При `go test ./internal/config/` тест иногда падает:
```
expected: ":8080"
actual  : ":9090"
Test: TestManager_Watch_MultipleChanges
```
Одновременно в логе: `config: hot-reload rejected, keeping previous config — 'profiler.enabled' cannot parse value as 'bool'`.

**Причина.**
fsnotify отправляет событие IN_MODIFY в момент, когда тест записал файл лишь
частично. Hot-reload правильно отклоняет невалидный YAML и держит предыдущий
конфиг (это корректное поведение продакшен-кода). Но тест ожидает финальный
конфиг и не обрабатывает промежуточное состояние.

**Фикс.**
Записывать конфиг атомарно (write → rename) в тест-хелпере:
```go
tmp := configPath + ".tmp"
require.NoError(t, os.WriteFile(tmp, data, 0644))
require.NoError(t, os.Rename(tmp, configPath))
```
`os.Rename` атомарна на Linux — fsnotify увидит только одно событие на финальный
файл.

---

### T-2 · Benchmark regression test в CI

**Задача.**
Рассмотреть добавление benchmark-regression теста в CI (сравнение с baseline ±10%) для `BenchmarkRuleEval_EbpfGuard_Callback` и других ключевых бенчмарков.

---

## 🟢 Функциональность и дорожная карта

### F-1 · pidfd-based kill для полного устранения race condition при kill

**Контекст.**
Фикс PID-reuse из `af5c1b4` (перечитывать `/proc/<pid>/comm` перед SIGKILL) сужает
окно race до одного kernel round-trip, но не устраняет его. `pidfd_open(2)` +
`pidfd_send_signal(2)` (Linux 5.1+) дают атомарный handle на конкретный экземпляр
процесса — отправить SIGKILL не тому процессу становится технически невозможным
даже при мгновенном переиспользовании PID.

**Задача.**
В `internal/enforcer/kill.go`:
1. При старте определять версию ядра и поддержку `pidfd` (`unix.PidfdOpen`).
2. На ядрах ≥ 5.1: использовать `pidfd_open` → `pidfd_send_signal` как основной путь.
3. На старых ядрах: использовать текущий `/proc/comm` recheck как fallback.
4. Добавить метрику `enforcer_kill_pidfd_used_total` для observability.

---

### F-2 · Импорт правил из форматов Sigma и Elastic ECS

**Контекст.**
Sigma — промышленный стандарт переносимых правил детекции с 3000+ community-правил
под Linux, Windows и облачные среды. Elastic ECS покрывает ещё один крупный корпус.
Поддержка этих форматов расширит экосистему детекций ebpf-guard.

**Задача.**
1. **Sigma-конвертер** (`cmd/sigma2ebpfguard`):
   - Маппинг `detection.selection` полей → операторы ebpf-guard.
   - Маппинг `logsource` (process_creation, network_connection, file_event) → `event_type`.
   - Поддержка `condition: 1 of selection*` и `all of them`.
   - Режим `--validate`: отчёт о неконвертируемых правилах.
2. **ECS-конвертер** — маппинг ECS process/network/file полей.
3. Интеграция с существующим `internal/ruletest` для верификации конвертированных правил.

---

### F-3 · Коннекторы облачных аудит-логов (AWS CloudTrail, GCP, Azure)

**Контекст.**
ebpf-guard видит только kernel-level события. Атаки на control plane (IAM,
RBAC, service account, node-pool escapes) остаются невидимыми.

В Kubernetes наиболее опасные компрометации часто начинаются именно с cloud API
(кража service account credentials → privilege escalation через AWS IAM).

**Задача.**
Добавить опциональный компонент `cloud-audit-collector`:
- `--collector=cloudtrail` — poll/stream CloudTrail через SQS/S3.
- `--collector=gcp-audit` — stream GCP Audit Logs через Cloud Pub/Sub.
- `--collector=azure-monitor` — stream через Azure Event Hub.

Cloud-события проходят через тот же YAML + OPA пайплайн → cross-domain
корреляция (kernel + cloud control plane в одном алерте).

---

### F-4 · Настраиваемый `sample_rate` для правил под высокой нагрузкой

**Контекст.**
При высокой нагрузке все правила оцениваются на каждом событии с полной частотой.
Инфраструктура `ShouldSample` / `DeterministicSample` уже есть в `internal/correlator/`.

**Задача.**
Добавить поле `sample_rate` (float, 0.0–1.0, дефолт 1.0) в DSL правил:
```yaml
rules:
  - id: rule_high_volume
    event_type: syscall
    sample_rate: 0.10   # оценивать только 10% событий
    severity: info
```
Детерминированное семплирование (по hash PID+timestamp) для воспроизводимости.
Добавить метрику `rule_eval_sampled_total{rule_id, sample_rate}`.

---

### F-5 · Режим allowlist для сисколлов (аномалия по отсутствию в baseline)

**Контекст.**
ebpf-guard работает в deny-list режиме: правила описывают плохое поведение.
Дополнительный allowlist-режим использовал бы EWMA-профайлер для построения
per-workload baseline ожидаемых сисколлов и алертил бы при появлении
неожиданного — аналог seccomp-bpf, но runtime-обученный. Позволяет детектировать
novel-атаки без заранее написанного правила.

**Задача.**
Добавить опцию `allowlist_mode: true` в профайлер:
1. В период обучения — записывать каждый уникальный сискол на workload identity.
2. После обучения — эмитировать `severity: warning` при сисколе вне learned set.
3. Интегрировать с существующим `SequenceProfiler` — объединять два сигнала
   (EWMA anomaly score + unexpected syscall) в один взвешенный alert score.
4. Режим `audit` (только логировать, не алертить) для первичной настройки.

---

---

## Сводная таблица

| ID | Приоритет | Категория | Трудозатраты | Ключевой файл |
|----|-----------|-----------|-------------|---------------|
| H-1 | 🔴 Критично | Security | S (1 ч) | `cmd/ebpf-guard/main.go:1311` |
| H-2 | 🔴 Высокий | Security | S (2 ч) | `internal/exporter/syslog_cef.go:265` |
| H-3 | 🔴 Высокий | Security | XS (15 мин) | `internal/wasm/engine.go:59` |
| H-4 | 🔴 Высокий | Security | S (1 ч) | `internal/exporter/otlp.go:114` |
| H-5 | 🔴 Высокий | Security | S (1 ч) | `internal/exporter/kafka.go:111` |
| M-1 | 🟠 Средний | Security | S (1 ч) | `internal/exporter/webhook.go:80` |
| M-2 | 🟠 Средний | Security | S (1 ч) | `internal/exporter/syslog_cef.go:270` |
| M-3 | 🟠 Средний | Security | S (2 ч) | `telegram.go:94`, `discord.go:83` |
| M-4 | 🟠 Средний | Security | S (1 ч) | `internal/wasm/plugin.go:128` |
| L-1 | 🟡 Низкий | Security | S (1 ч) | `internal/gossip/http.go:120` |
| L-2 | 🟡 Низкий | Security | XS (30 мин) | `otlp.go:95`, `kafka.go:91` |
| L-3 | 🟡 Низкий | Security | XS (30 мин) | `syslog_cef.go:331` |
| L-4 | 🟡 Низкий | Security | S (1 ч) | `misp.go:57`, `opencti.go:27` |
| L-5 | 🟡 Низкий | Security | XS (30 мин) | `discord.go:130` |
| HD-1 | 🟣 Hardening | Security | M (4 ч) | `exporter/` |
| HD-2 | 🟣 Hardening | UX | S (2 ч) | `main.go:514` |
| HD-3 | 🟣 Hardening | Supply chain | M (4 ч) | `api.go:709` |
| HD-4 | 🟣 Hardening | Security | XS (30 мин) | `internal/config/` |
| HD-5 | 🟣 Hardening | Security | S (2 ч) | `api.go:731` |
| T-1 | 🔵 Тест | Quality | XS (30 мин) | `config/config_test.go:217` |
| T-2 | 🔵 Тест | Quality | XS (30 мин) | `bench/` |
| F-1 | 🟢 Feature | Correctness | M (1 д) | `internal/enforcer/kill.go` |
| F-2 | 🟢 Feature | Ecosystem | L (1–2 нед) | `internal/migration/` |
| F-3 | 🟢 Feature | Ecosystem | L (2–3 нед) | `internal/collector/` |
| F-4 | 🟢 Feature | Performance | M (2–3 д) | `internal/correlator/` |
| F-5 | 🟢 Feature | Detection | M (3–5 д) | `internal/profiler/` |

**Итого:** 5 HIGH · 4 MEDIUM · 5 LOW · 5 Hardening · 2 Тест/Docs · 5 Feature  
**Быстрые победы (< 1 ч каждая):** H-3, L-2, L-3, L-4, T-1, HD-4 — закрывают реальные уязвимости за один рабочий день.
