# ebpf-guard Security Testing Environment

Полностью настроенное окружение для тестирования ebpf-guard с использованием OWASP Juice Shop как цели для атак.

## 🎯 Цель

Создать комплексную среду для тестирования способности ebpf-guard детектировать различные типы атак:
- SQL Injection
- Brute Force / Credential Stuffing
- SSRF (Server-Side Request Forgery)
- LDAP Injection
- CSRF (Cross-Site Request Forgery)

## 🏗️ Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                         VPS Server                          │
│  IP: <VPS_IP>                                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            ebpf-guard (Host)                          │  │
│  │            Port: 19090                               │  │
│  │            - Мониторинг kernel событий                │  │
│  │            - Детекция атак                            │  │
│  │            - Prometheus metrics                       │  │
│  └───────────────────────────────────────────────────────┘  │
│                           ↑                                    │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Docker Containers                                   │  │
│  │                                                       │  │
│  │  ┌──────────────┐  ┌──────────────┐                  │  │
│  │  │ Juice Shop   │  │  Prometheus  │                  │  │
│  │  │ Port: 3000   │  │  Port: 9090  │                  │  │
│  │  │ Цель атак    │  │  Metrics     │                  │  │
│  │  └──────────────┘  └──────────────┘                  │  │
│  │                                                       │  │
│  │  ┌──────────────┐                                    │  │
│  │  │   Grafana    │                                    │  │
│  │  │  Port: 3001  │                                    │  │
│  │  │  Dashboard   │                                    │  │
│  │  └──────────────┘                                    │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Attack Scripts (/opt/security-testing/attacks)      │  │
│  │                                                       │  │
│  │  • sqlmap-attacks.sh                                 │  │
│  │  • bruteforce-attacks.sh                             │  │
│  │  • ssrf-attacks.sh                                   │  │
│  │  • ldap-csrf-attacks.sh                              │  │
│  │  • run-all-attacks.sh                                │  │
│  │  • analyze-alerts.py                                 │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Компоненты

### 1. ebpf-guard
- **Порт**: 19090
- **Конфиг**: /etc/ebpf-guard/config.yaml
- **API Endpoints**:
  - `http://<VPS_IP>:19090/health` - Health check
  - `http://<VPS_IP>:19090/api/v1/alerts` - Alerts API
  - `http://<VPS_IP>:19090/api/v1/status` - Status API
  - `http://<VPS_IP>:19090/metrics` - Prometheus metrics

### 2. Juice Shop (Цель атак)
- **Порт**: 3000
- **URL**: http://<VPS_IP>:3000
- **Описание**: OWASP Juice Shop - уязвимое веб-приложение для тестирования

### 3. Prometheus
- **Порт**: 9090
- **URL**: http://<VPS_IP>:9090
- **Конфиг**: /etc/prometheus/prometheus.yml

### 4. Grafana
- **Порт**: 3001
- **URL**: http://<VPS_IP>:3001
- **Login**: admin / admin123

## 🚀 Быстрый старт

### 1. Проверка состояния сервисов

```bash
ssh root@<VPS_IP>

# Проверка контейнеров
docker ps

# Проверка ebpf-guard
curl http://localhost:19090/health

# Проверка Juice Shop
curl -I http://localhost:3000
```

### 2. Запуск всех атак

```bash
ssh root@<VPS_IP>
cd /opt/security-testing/attacks

# Интерактивный режим
./run-all-attacks.sh --interactive

# Или полный запуск
./run-all-attacks.sh
```

### 3. Запуск отдельных типов атак

```bash
cd /opt/security-testing/attacks

# SQL Injection атаки
./sqlmap-attacks.sh

# Brute Force атаки
./bruteforce-attacks.sh

# SSRF атаки
./ssrf-attacks.sh

# LDAP/CSRF атаки
./ldap-csrf-attacks.sh
```

### 4. Анализ результатов

```bash
# Использование Python анализатора
python3 analyze-alerts.py --detailed

# Сравнение метрик
python3 analyze-alerts.py \
  --compare-baseline metrics-before.txt \
  --compare-final metrics-after.txt
```

## 📊 Мониторинг

### Prometheus Metrics

Основные метрики ebpf-guard:

- `ebpf_guard_alerts_total` - Общее количество алертов
- `ebpf_guard_events_total` - Общее количество событий
- `ebpf_guard_collector_up` - Статус коллекторов
- `ebpf_guard_profiler_anomalies_total` - Количество аномалий

### Grafana Dashboard

1. Откройте http://<VPS_IP>:3001
2. Login: admin / admin123
3. Импортируйте дашборд из `ebpf-guard-security-dashboard.json`
4. Или найдите "ebpf-guard Security Testing"

## 🔥 Типы атак

### 1. SQL Injection (sqlmap-attacks.sh)

- **Blind SQL Injection** - Login form
- **Error-based SQL Injection** - Search functionality
- **UNION-based SQL Injection** - Multiple endpoints
- **Time-based SQL Injection** - Timing attacks
- **Stacked Query SQL Injection** - Query chaining
- **Comprehensive Scan** - Full crawl and test

### 2. Brute Force (bruteforce-attacks.sh)

- **Credential Stuffing** - Common password pairs
- **Password Spraying** - One password, many users
- **Username Enumeration** - User discovery
- **API Token Brute Force** - Token guessing
- **Session Fixation** - Session manipulation
- **High-Frequency Login** - Rate limiting test
- **Distributed Pattern** - Multi-origin simulation

### 3. SSRF (ssrf-attacks.sh)

- **Localhost Scanning** - Internal port scanning
- **Cloud Metadata Access** - AWS/GCP/Azure metadata
- **File Protocol** - Local file access
- **DNS Rebinding** - DNS-based attacks
- **Internal Services** - Docker/K8s service discovery
- **Header-based SSRF** - X-Forwarded-Host attacks

### 4. LDAP/CSRF (ldap-csrf-attacks.sh)

- **LDAP Auth Bypass** - Injection attacks
- **LDAP Filter Injection** - Filter manipulation
- **LDAP Attribute Disclosure** - Data extraction
- **CSRF Token Enumeration** - Token discovery
- **CSRF Bypass** - Protection circumvention
- **Session Manipulation** - Session hijacking

## 📈 Результаты тестирования

### Пример результатов (Brute Force - 30 сек):

```
Бaseline: 20,458 alerts
После атаки: 20,667 alerts
Новых алертов: 209
```

### Топ детектируемых правил:

1. `container_escape_proc_write` - 1,062 алертов
2. `supply_chain_build_tool_rootwrite` - 910 алертов
3. `fim_library_replaced` - 909 алертов
4. `sigma_memory_proc_dump` - 906 алертов
5. `sigma_sensitive_file_chmod` - 839 алертов

### Распределение по严重程度:

- **Critical**: 10,329 алертов
- **Warning**: 10,268 алертов
- **Info**: 179 алертов

## 🛠️ Устранение проблем

### ebpf-guard не запущен

```bash
# Проверка статуса
ps aux | grep ebpf-guard

# Запуск
nohup /usr/local/bin/ebpf-guard --config /etc/ebpf-guard/config.yaml > /tmp/ebpf-guard.log 2>&1 &

# Проверка
curl http://localhost:19090/health
```

### Docker контейнеры не работают

```bash
# Проверка статуса
docker ps -a

# Рестарт
docker-compose up -d
```

### SQLMap не установлен

```bash
apt-get update && apt-get install -y sqlmap
```

## 📝 Следующие шаги

### План действий (Phase 2-4):

**Phase 2: Load Testing**
- Настройка Hey/Wrk для нагрузочного тестирования
- Проверка производительности ebpf-guard под нагрузкой

**Phase 3: Analysis**
- Детальный анализ результатов
- False positive анализ
- Оптимизация правил детектирования

**Phase 4: Dashboard Improvements**
- Кастомные alerts в Grafana
- Отчеты по безопасности
- Детальная аналитика

## 🔗 Полезные ссылки

- **ebpf-guard**: https://github.com/zugolO/ebpf-guard
- **OWASP Juice Shop**: https://owasp.org/www-project-juice-shop/
- **Prometheus**: http://<VPS_IP>:9090
- **Grafana**: http://<VPS_IP>:3001

## 📞 Контакты

Для вопросов и проблем:
- GitHub Issues: https://github.com/zugolO/ebpf-guard/issues
- Documentation: https://github.com/zugolO/ebpf-guard/docs

---

**Создано**: 2026-07-11
**Версия**: 1.0
**Статус**: ✅ Production Ready
