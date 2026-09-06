#!/bin/bash
# wave6.2.2-controls.sh — контроли волны 6.2.2 (долг прогона 6.2.1).
#
# ПОЧЕМУ ЭТОТ ФАЙЛ, А НЕ ПРАВКА wave6.2.1-controls.sh. Прогон 6.2.1 снят
# (архив server-logs/collect-6.2.1, 05.09.2026), его вердикты — история и
# переписыванию не подлежат. Волна 6.2.2 меряет ДРУГОЕ: пятнадцать находок
# №230…№244, из которых ШЕСТЬ — дефекты самого измерителя. Пока они не
# починены, прогон печатает ложный PASS, а не величину.
#
# ЧТО ИСПРАВЛЕНО ОТНОСИТЕЛЬНО 6.2.1 (каждая строка — цена, снятая по архиву):
#   №238  Список правил со срезом лимитера строился циклом по СТОРОВОМУ
#         подмножеству `_w621_new` (namespace непуст ИЛИ comm — нодовый актор).
#         Сетевые и daemon-правила туда не попадают никогда, поэтому прогон
#         6.2.1 напечатал «правила со срезом лимитера: нет» одновременно со
#         срезом +530. Здесь список строится ПО МЕТРИКЕ
#         (w622_ratelimited_by_rule, wave6.2.2-metrics-lib.sh) и о сторе
#         ничего не знает. Офлайн-сторож на collect-6.2.1 обязан дать
#         c2_periodic_beacon_pattern(+504) и sigma_passwd_shadow_read_daemon(+26).
#   №239  Разбивка величины строилась из того же `_w621_new` и покрыла 14 из
#         322 алертов (4.3%) — слепой вход для сужения. Здесь разбивка идёт по
#         метрике (w622_volume_by_rule), покрытие проверяется критерием
#         6.2.2.3 (≥95%); на архиве 6.2.1 та же функция даёт 100%.
#   №240  Момент старта агента пишется ТАКЖЕ эпохой, границы окна выносятся в
#         $W622_ART/window-epoch.txt — пайплайну есть чем звать journalctl
#         (`--since "@эпоха"`; ISO-8601 с суффиксом «T…Z» systemd.time(7) не
#         разбирает, и journal-agent-6.2.1.log приехал нулевого размера).
#   №241  (в пайплайне) копия лога — последним действием, после «ЗАВЕРШЁН».
#   №242  Порядок открытия окна: t0 фиксируется ПОСЛЕДНИМ действием
#         предоткрывающей последовательности, симметрично уже верному
#         закрытию, где t1 фиксируется первым. Список comm измерителя дополнен
#         `cat`/`tail` (на архиве 6.2.1 это 11 алертов вместо напечатанных 9).
#         И главное: доля измерителя перестала быть «поправкой к чтению» —
#         это критерий 6.2.2.5 с вердиктом.
#   №237  Заморозка базы дрейфа доказывается ПРИРАЩЕНИЕМ счётчика между двумя
#         срезами, а не наличием имени метрики в выдаче (Prometheus печатает
#         нулевые счётчики всегда). journal-грep ограничен окном. Плюс
#         позитивный подконтроль на искусственно заниженном max_signatures —
#         без него дельта 0 неотличима от «счётчик сломан».
#   №236  Цена старта пода получила порог: 45 алертов/под (36 измеренных × 1.25).
#   №235  Инцидентный слой получил вердикт: incident_confirmed_attack от
#         runc/flannel/comm измерителя — ноль ЗА ПРОГОН ЦЕЛИКОМ.
#   №244  Профиль и потолок ресурсов сняты пайплайном, а не рукой: 6.2.2.10 —
#         pprof в ОТДЕЛЬНОМ окне после окна объёма (внутри окна это действие
#         измерителя и нарушило бы 6.2.2.5), 6.2.2.11 — RSS/heap/goroutines/
#         латентность против лимита чарта.
#   №243  Живой сторож: снятие chmod с syscall-оси проверяется числом
#         monitored_syscalls в журнале, а не только офлайн-юнитом.
#
# ЧТО ПЕРЕНЕСЕНО РЕГРЕССИЕЙ И ПОЧЕМУ СОХРАНИЛО СТАРЫЕ НОМЕРА. Контроли
# 6.2.1.2, 6.2.1.2b, 6.2.1.3, 6.2.1.6, 6.2.1.8, 6.2.1.9 в таблице критериев
# 6.2.2 отсутствуют — они взяты прогоном 6.2.1 и здесь стоят регрессией.
# Их метки НЕ перенумерованы намеренно (память criteria-index-pins-replay-labels):
# перенумерация меток — ровно то, что роняет преflight на прошлых архивах.
# Новые критерии несут номера 6.2.2.*, старые — свои 6.2.1.*, и вердикт-файл
# читается однозначно.
#
# ЗАПУСК. Скрипт не самостоятелен: нужен живой агент с kubernetes.enabled:true
# и готовая нода. Провал контроля НЕ убивает чужой прогон (волна 6.0m,
# память die-only-for-unmeasurable-run); die() здесь только считает и пишет
# вердикт.
#   W622_API           — база HTTP API агента (http://<host>:19090)
#   W622_TOKEN         — bearer-токен (формат файла токена — admin=<...>)
#   W622_KUBECTL       — путь к kubectl
#   W622_NS            — namespace контролей (по умолчанию w622)
#   W622_WINDOW        — длина тихого окна объёма, с (по умолчанию 600)
#   W622_GATE          — гейт волны 6, алертов/ч (по умолчанию 100)
#   W622_GATE_FORMULA  — all | noinfo (решение по №232; по умолчанию all)
#   W622_CHURN_BUDGET  — порог цены старта пода (по умолчанию 45, №236)
#   W622_PROFILE_SECS  — длина окна pprof (по умолчанию 30, №244)
#   W622_SMOKE         — 1: смок-режим, все ветки исполняются на коротких
#                        временах; длинные ожидания укорочены, НИ ОДИН блок
#                        не пропускается (память smoke-only-does-not-cover-attack-window)
set -u

VPS_IP="${VPS_IP:-localhost}"
W622_API="${W622_API:-http://${VPS_IP}:19090}"
W622_TOKEN="${W622_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W622_KUBECTL="${W622_KUBECTL:-/usr/local/bin/kubectl}"
W622_NS="${W622_NS:-w622}"
W622_WINDOW="${W622_WINDOW:-600}"
W622_GATE="${W622_GATE:-100}"
W622_GATE_FORMULA="${W622_GATE_FORMULA:-all}"
W622_CHURN_BUDGET="${W622_CHURN_BUDGET:-45}"
W622_PROFILE_SECS="${W622_PROFILE_SECS:-30}"
W622_SETUP="${W622_SETUP:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
W622_SETTLE="${W622_SETTLE:-20}"
W622_POS_TIMEOUT="${W622_POS_TIMEOUT:-120}"
W622_CHURN="${W622_CHURN:-3}"
W622_SVC="${W622_SVC:-ebpf-guard-test.service}"
W622_VERDICTS="${W622_VERDICTS:-/root/wave6.2.2-controls-verdicts.txt}"
W622_ART="${W622_ART:-/root/wave6.2.2-artifacts}"
W622_REPO="${W622_REPO:-/opt/ebpf-guard}"
W622_GO="${W622_GO:-/usr/local/go/bin/go}"
W622_SMOKE="${W622_SMOKE:-0}"
W622_QUIET_LEAD="${W622_QUIET_LEAD:-70}"

WAVE622_FAILS=0
# Артефакты пишутся в КАТАЛОГ ЭТОГО ПРОГОНА и он очищается на старте
# (находка №228).
rm -rf "$W622_ART" 2>/dev/null || true
mkdir -p "$W622_ART" 2>/dev/null || true

die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE622_FAILS=$((WAVE622_FAILS + 1))
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '6\.2\.[12]\.[A-Za-z0-9]+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W622_VERDICTS" 2>/dev/null || true
    return 0
}
pass() { echo "OK: $*"; }

: > "$W622_VERDICTS" 2>/dev/null || true
echo "# wave6.2.2-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W622_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 6.2.2 (долг прогона 6.2.1) ==="
echo "режим: $([ "$W622_SMOKE" = "1" ] && echo 'СМОК (короткие времена, все ветки исполняются)' || echo 'полный')"
echo "формула гейта (№232): $W622_GATE_FORMULA (all = включая severity=info, noinfo = без него; обе величины печатаются в любом случае)"

# ─────────────────────────────────────────────────────────────────────────────
# ИЗМЕРИТЕЛЬНАЯ БИБЛИОТЕКА (№238/№239). Берётся source'ом, а не копией: у
# копии нет офлайн-сторожа, а у этого файла он есть и проходит на
# collect-6.2.1 (--self-test). Отсутствие библиотеки — не «работаем без
# разбивки», а неизмеримость критериев 6.2.2.2/6.2.2.3.
# ─────────────────────────────────────────────────────────────────────────────
W622_LIB="$W622_SETUP/wave6.2.2-metrics-lib.sh"
W622_LIB_OK=0
if [ -r "$W622_LIB" ]; then
    # shellcheck source=/dev/null
    . "$W622_LIB" && W622_LIB_OK=1
fi
[ "$W622_LIB_OK" -eq 1 ] || die "6.2.2.2 НЕИЗМЕРИМ: не подключилась $W622_LIB — список срезанных правил и разбивка величины строились бы снова по стору, то есть воспроизвели бы дефекты №238/№239"

# Правила, для которых нода — единственный вход.
W622_K8S_RULES="cis_5_1_3_secret_access k8s_sa_token_read k8s_sa_token_projected_read k8s_hostpath_kubelet_access"
W622_HOST_RULES="cis_5_1_3_secret_access k8s_hostpath_kubelet_access"
W622_NODE_ACTORS="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl flannel bridge loopback"
# Список comm ИЗМЕРИТЕЛЯ (№242, часть 1: добавлены cat и tail — на архиве
# 6.2.1 без них печаталось 9 при фактических 11 в сторе).
W622_INSTR_COMMS='["curl","jq","bash","head","sed","awk","date","tr","sort","systemctl","journalctl","cat","tail","stat","find","wc","cut","grep"]'
# Те же имена плоским списком — для 6.2.2.9 (инцидентный слой).
W622_INSTR_COMMS_FLAT="curl jq bash head sed awk date tr sort systemctl journalctl cat tail stat find wc cut grep"

_w622_curl() { curl -s --max-time 30 -H "Authorization: Bearer $W622_TOKEN" "$@"; }
_w622_alerts() { _w622_curl "$W622_API/api/v1/alerts?limit=200000"; }
_w622_metrics() { _w622_curl "$W622_API/metrics"; }
_w622_epoch() { date -u +%s; }

# Сумма метрики по срезу. Прямая дельта двух срезов, а не строка таблицы:
# строка индексирована срезом лимитера (память f6b-table-indexed-by-limiter-cut).
_w622_metric_sum() { # $1=metric $2=список rule_id (пусто = все) [$3=файл среза]
    local metric="$1" ids="${2:-}" src="${3:-}"
    { [ -n "$src" ] && cat "$src" || _w622_metrics; } | awk -v m="$metric" -v ids="$ids" '
        BEGIN { n = split(ids, a, " ") }
        $0 ~ "^"m"[{ ]" {
            if (n == 0) { s += $NF; next }
            for (i = 1; i <= n; i++) if (index($0, "rule_id=\"" a[i] "\"")) { s += $NF; next }
        }
        END { printf "%d", s+0 }'
}
# Скалярная метрика без лейблов (process_*, go_*): $NF может быть в
# экспоненциальной записи (1.37413104e+08), поэтому печатается через %.0f.
_w622_metric_raw() { # $1=metric $2=файл среза
    awk -v m="$1" '$1 == m { printf "%.0f", $2+0; found=1; exit } END { if (!found) printf "" }' "$2" 2>/dev/null
}

# ---------------------------------------------------------------------------
# ОБЪЁМ И РЕШЕНИЕ №232.
#
# Формула 6.2.1 (№227) — alerts_total + alerts_filtered_total по всем
# severity. Находка №230 показала, что 94% величины прошлого прогона это
# severity=info, которого нет в сторе; №232 спрашивает владельца, считать ли
# его. Решение зафиксировано ДО прогона и в прогоне не меняется (критерий
# 6.2.2.1), но ОБЕ величины печатаются всегда: разница двух — это цена
# решения №232 числом, а не прогнозом.
#
# Почему вердикт по умолчанию по «all»: filtered_total — это то, что срезано
# min_severity. Формула без info позволяет «починить» шумное правило
# понижением его severity: величина упадёт, а работа агента (regex,
# обогащение, дедуп, кольцевой буфер) останется та же. Гейт перестал бы быть
# гейтом. См. plan.md, №232.
# ---------------------------------------------------------------------------
_w622_volume_all() { # $1=файл среза
    awk '/^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/ { s += $NF } END { printf "%d", s+0 }' "$1"
}
_w622_volume_noinfo() { # $1=файл среза
    awk '(/^ebpf_guard_alerts_total[{ ]/ || /^ebpf_guard_alerts_filtered_total[{ ]/) && !/severity="info"/ { s += $NF } END { printf "%d", s+0 }' "$1"
}
_w622_ratelimited() { _w622_metric_sum ebpf_guard_alerts_ratelimited_by_rule_total "${1:-}" "${2:-}"; }
# Потери событий БЕЗ path_denylist (№222): denylist — законный фильтр, а не
# потеря видимости.
_w622_real_drops() { # [$1=файл среза]
    { [ -n "${1:-}" ] && cat "$1" || _w622_metrics; } | awk '
        /^ebpf_guard_events_dropped_total\{/ && !/reason="path_denylist"/ { s += $NF }
        /^ebpf_guard_event_queue_dropped_total/ { s += $NF }
        END { printf "%d", s+0 }'
}
# Журнальный счётчик потерь (№222, второй слой). №240: журнал читается ОТ
# СТАРТА АГЕНТА, а не за всю историю юнита — иначе величина принадлежит
# прошлым прогонам.
_w622_journal_since() {
    if [ -s /root/agent-start-6.2.2.epoch ]; then
        echo "@$(cat /root/agent-start-6.2.2.epoch)"
    else
        systemctl show "$W622_SVC" -p ActiveEnterTimestampMonotonic --value >/dev/null 2>&1
        local t; t=$(systemctl show "$W622_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
        local e; e=$(date -d "$t" +%s 2>/dev/null)
        [ -n "${e:-}" ] && echo "@$e" || echo "-1 hour"
    fi
}
_w622_journal_drops() {
    journalctl -u "$W622_SVC" --since "$(_w622_journal_since)" --no-pager 2>/dev/null \
        | grep -o '"bulk_dropped_since_start":[0-9]*' | tail -1 | cut -d: -f2
}

# Смок-режим укорачивает ОЖИДАНИЯ, но не выкидывает блоки.
if [ "$W622_SMOKE" = "1" ]; then
    W622_SETTLE=5
    W622_POS_TIMEOUT=30
    W622_QUIET_LEAD=10
fi

# ─────────────────────────────────────────────────────────────────────────────
# ПРЕFLIGHT. Провал здесь означает, что величины ниже нечем читать.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2 преflight ---"
command -v jq >/dev/null 2>&1 || die "6.2.2 преflight ПРОВАЛЕН: нет jq — все величины по стору неизмеримы"

if [ ! -x "$W622_KUBECTL" ]; then
    die "6.2.2 преflight ПРОВАЛЕН: kubectl не найден ($W622_KUBECTL) — ноду нечем подать на вход, любой ноль ниже приборный"
else
    _w622_ready=$("$W622_KUBECTL" get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{n++} END{print n+0}')
    if [ "${_w622_ready:-0}" -lt 1 ]; then
        die "6.2.2 преflight ПРОВАЛЕН: ни одна нода не Ready"
    else
        pass "6.2.2 преflight: нод Ready = $_w622_ready ($("$W622_KUBECTL" version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // "?"'))"
    fi
fi

_w622_cfg="${W622_CONFIG:-$W622_SETUP/config-test.yaml}"
_w622_k8s_block=$(awk '/^kubernetes:/{f=1;next} f && /^[a-zA-Z#]/{exit} f' "$_w622_cfg" 2>/dev/null)
_w622_drift_cfg=$(awk '/drift_baseline:/{f=1;next} f && /^[a-zA-Z]/{exit} f' "$_w622_cfg" 2>/dev/null)
echo "$_w622_k8s_block" | grep -qE '^\s*enabled:\s*true\s*$' \
    && pass "6.2.2 преflight: kubernetes.enabled: true в $_w622_cfg" \
    || die "6.2.2 преflight ПРОВАЛЕН: kubernetes.enabled НЕ true — энричер не конструируется, pod_name пуст по построению (находка №216)"

# pprof: без него критерий 6.2.2.10 нереализуем в принципе (находка №244:
# enable_pprof по умолчанию false, и config-test.yaml её никогда не включал —
# /debug/pprof/* 404-ил на живом стенде).
grep -qE '^\s*enable_pprof:\s*true\s*$' "$_w622_cfg" 2>/dev/null \
    && pass "6.2.2 преflight: enable_pprof: true — окно профиля 6.2.2.10 реализуемо" \
    || die "6.2.2.10 НЕИЗМЕРИМ: enable_pprof не true в $_w622_cfg — /debug/pprof/* ответит 404, профиль снять нечем (находка №244)"

_w622_src=$(journalctl -u "$W622_SVC" --since "$(_w622_journal_since)" --no-pager 2>/dev/null | grep -o '"msg":"runtime enricher active","source":"[a-z]*"' | tail -1 | grep -oE '"source":"[a-z]*"' | cut -d'"' -f4)
_w622_k8s_up=$(journalctl -u "$W622_SVC" --since "$(_w622_journal_since)" --no-pager 2>/dev/null | grep -c 'k8s enricher active')
echo "  источник runtime-обогащения: ${_w622_src:-НЕ НАПЕЧАТАН}; строк «k8s enricher active»: $_w622_k8s_up"
[ "${_w622_k8s_up:-0}" -ge 1 ] || die "6.2.2 преflight ПРОВАЛЕН: в журнале нет «k8s enricher active» — pod_name будет пуст по причине вне продукта"

# №240, часть 1: журнал вообще читается ОТ СТАРТА АГЕНТА. Прогон 6.2.1 привёз
# journal-agent-6.2.1.log нулевого размера и не заметил этого.
_w622_jsince=$(_w622_journal_since)
_w622_jlines=$(journalctl -u "$W622_SVC" --since "$_w622_jsince" --no-pager 2>/dev/null | wc -l)
echo "  журнал агента с $_w622_jsince: $_w622_jlines строк"
[ "${_w622_jlines:-0}" -ge 1 ] \
    && pass "6.2.2 преflight: journalctl --since «$_w622_jsince» даёт непустой журнал (№240: ISO-8601 «T…Z» systemd.time(7) НЕ разбирает, эпоха — разбирает)" \
    || die "6.2.2.4 ПРОВАЛЕН заранее: journalctl --since «$_w622_jsince» даёт ПУСТО — архив этого прогона будет нереплеиваемым, как collect-6.2.1 (№240)"

# №243, живой сторож. config-test.yaml не задаёт monitored_syscalls, значит
# используется DefaultMonitoredSyscalls() из sampling.go: 19 номеров после
# снятия chmod/fchmod/fchmodat (90/91/268), 22 до него. Число в журнале
# отличает ЗАДЕПЛОЕННУЮ правку от лежащей в дереве.
_w622_ms=$(journalctl -u "$W622_SVC" --since "$_w622_jsince" --no-pager 2>/dev/null \
    | grep -o '"monitored_syscalls":[0-9]*' | tail -1 | cut -d: -f2)
_w622_ms_want=$(awk '/^func DefaultMonitoredSyscalls/,/^}/' "$W622_REPO/internal/bpf/sampling.go" 2>/dev/null | grep -cE '^[[:space:]]+[0-9]+,')
echo "  №243: monitored_syscalls в журнале = ${_w622_ms:-НЕ НАПЕЧАТАН}; в дереве DefaultMonitoredSyscalls() = ${_w622_ms_want:-?}"
if [ -z "${_w622_ms:-}" ]; then
    die "6.2.1.9 (№243) НЕИЗМЕРИМ: строки kernel_filter с monitored_syscalls нет в журнале — задеплоена правка или нет, по этому прогону не установить"
elif [ "${_w622_ms_want:-0}" -gt 0 ] && [ "${_w622_ms:-0}" -ne "${_w622_ms_want:-0}" ]; then
    die "6.2.1.9 (№243) ПРОВАЛЕН: агент поднят на бинаре с ${_w622_ms} syscall'ами, а дерево описывает ${_w622_ms_want}. Правка №243 (снятие chmod с syscall-оси) НЕ задеплоена: chmod по-прежнему даёт второе, никем не читаемое событие, и цена ring buffer в 6.2.2.1 измеряется НЕ на том коде, что лежит в дереве"
else
    pass "6.2.1.9 (№243) ДОСТИГНУТО (половина «деплой»): monitored_syscalls=${_w622_ms} совпадает с деревом — chmod снят с syscall-оси на живом бинаре"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.6 РЕГРЕССИЯ: реестр немоты по среде (находка №225), ДО всякого замера.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.6 (регрессия): немота по среде ---"
_w622_unreach=$(journalctl -u "$W622_SVC" --since "$_w622_jsince" --no-pager 2>/dev/null | grep -o '"msg":"rules: syscall rules with no reachable nr in the kernel allowlist".*' | tail -1)
_w622_unreach_n=$(printf '%s' "$_w622_unreach" | grep -oE '"count":[0-9]+' | cut -d: -f2)
_w622_unreach_ids=$(printf '%s' "$_w622_unreach" | grep -oE '"rule_ids":\[[^]]*\]' | tr -d '"[]' | sed 's/rule_ids://')
_w622_kmod=$(journalctl -u "$W622_SVC" --since "$_w622_jsince" --no-pager 2>/dev/null | grep -c 'cgroup escape collector unavailable')
echo "  недостижимых syscall-правил: ${_w622_unreach_n:-0}"
echo "  поимённо: ${_w622_unreach_ids:-нет}"
echo "  kmod cgroup-escape коллектор недоступен: $([ "${_w622_kmod:-0}" -gt 0 ] && echo да || echo нет) (ядро $(uname -r))"
# №234/открытый вопрос 7: файловые правила, чей op не производит ни один хук
# сборки, теперь печатаются агентом при старте (UnreachableFileOpRules).
# Это немота ПО ПОСТРОЕНИЮ, и реплей обязан читать её так же, как syscall-ось.
_w622_unreach_f=$(journalctl -u "$W622_SVC" --since "$_w622_jsince" --no-pager 2>/dev/null | grep -o '"msg":"rules: file rules with an op no hook produces".*' | tail -1)
echo "  файловых правил с недостижимым op: ${_w622_unreach_f:-строки нет}"

_w622_registry="$W622_SETUP/attacks/silent-rules.txt"
_w622_reg_ids=$(grep -oE '^[A-Za-z0-9_]+ a$' "$_w622_registry" 2>/dev/null | awk '{print $1}' | sort -u)
_w622_reg_n=$(printf '%s\n' "$_w622_reg_ids" | grep -c .)
_w622_jrn_ids=$(printf '%s' "${_w622_unreach_ids:-}" | tr ',' '\n' | sed '/^$/d' | sort -u)
echo "  реестр (silent-rules.txt, категория а): ${_w622_reg_n} правил"
if [ -z "${_w622_unreach_n:-}" ]; then
    die "6.2.1.6 НЕИЗМЕРИМ: строки о недостижимых правилах нет в журнале — немоту по среде нечем отличить от регресса"
elif [ "$_w622_jrn_ids" != "$_w622_reg_ids" ]; then
    die "6.2.1.6 ПРОВАЛЕН: реестр (${_w622_reg_n} правил) разошёлся со стендом (${_w622_unreach_n} правил: ${_w622_unreach_ids:-нет}) — реплеи архивов этой волны читают расхождение как потерю/регресс"
elif [ "${_w622_kmod:-0}" -gt 0 ] && ! grep -q 'cgroup escape collector unavailable' "$_w622_registry" 2>/dev/null; then
    die "6.2.1.6 ПРОВАЛЕН: kmod cgroup-escape коллектор недоступен на этом ядре, но $_w622_registry не документирует этот факт"
else
    pass "6.2.1.6 ДОСТИГНУТО: реестр немоты по среде совпал со стендом (${_w622_unreach_n} правил + kmod)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.0 ПРИБОРНОСТЬ (первая половина: ось пода).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.0: приборность оси пода ---"
_w622_alerts > "$W622_ART/alerts-preflight.json"
_w622_pod_alerts=$(jq '[.[]|select(((.enrichment.pod_name // "") != "") and ((.enrichment.namespace // "") != ""))]|length' "$W622_ART/alerts-preflight.json" 2>/dev/null || echo 0)
_w622_ns_seen=$(jq -r '.[]|select((.enrichment.namespace // "")!="")|.enrichment.namespace' "$W622_ART/alerts-preflight.json" 2>/dev/null | sort -u | tr '\n' ' ')
echo "  алертов с непустыми namespace И pod_name: $_w622_pod_alerts; namespace'ы: ${_w622_ns_seen:-нет}"
W622_INSTRUMENTED=0
if [ "${_w622_pod_alerts:-0}" -lt 1 ]; then
    die "6.2.2.0 ПРОВАЛЕН: ни одного алерта с личностью пода. Дальше контроли оси пода НЕ ЧИТАЮТСЯ — их ноль был бы приборным"
else
    W622_INSTRUMENTED=1
    pass "6.2.2.0 ДОСТИГНУТО (половина «ось пода»): личность пода доезжает до алерта ($_w622_pod_alerts алертов)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.A ДЛИНА ПРОЛОГА.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.A: длина пролога до открытия окна ---"
_w622_lp=$(echo "$_w622_drift_cfg" | grep -oE 'learning_period:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w622_edp=$(echo "$_w622_drift_cfg" | grep -oE 'enforce_deadline_periods:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w622_need=$(( ${_w622_lp:-600} * ${_w622_edp:-2} ))
_w622_started=$(systemctl show "$W622_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
_w622_started_s=$(date -d "$_w622_started" +%s 2>/dev/null || echo 0)
_w622_prologue=$(( $(date +%s) - _w622_started_s ))
echo "  агент поднят: ${_w622_started:-?}; пролог: ${_w622_prologue}s; требуется > ${_w622_need}s"
echo "  на этот момент: профилей $(_w622_metric_sum ebpf_guard_drift_baseline_profiles ""), из них в learning $(_w622_metric_sum ebpf_guard_drift_baseline_learning_workloads "")"
if [ "$_w622_started_s" -eq 0 ]; then
    die "6.2.2.A НЕИЗМЕРИМ: время старта сервиса не прочитано"
elif [ "$_w622_prologue" -le "$_w622_need" ]; then
    die "6.2.2.A ПРОВАЛЕН: пролог ${_w622_prologue}s не длиннее ${_w622_need}s — окно ниже меряет ОБУЧЕНИЕ, а не линию"
else
    pass "6.2.2.A ДОСТИГНУТО: пролог ${_w622_prologue}s > ${_w622_need}s"
fi

# ─────────────────────────────────────────────────────────────────────────────
# ТИХОЕ ОКНО ОБЪЁМА. Вход НЕ подаётся.
#
# №242, часть 2: t0 фиксируется ПОСЛЕДНИМ действием предоткрывающей
# последовательности. Каждый curl/journalctl этой последовательности — сам
# источник алертов (чтение /etc/passwd через NSS, чтение /var/log/journal);
# в 6.2.1 они стояли ПОСЛЕ фиксации t0 и потому падали внутрь окна
# (curl:3 journalctl:3 в вердикте архива). Закрытие окна такого дефекта не
# имело изначально — там t1 берётся первым; здесь открытие сделано
# симметрично закрытию.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.1/6.2.2.2/6.2.2.3/6.2.2.5/6.2.2.11: тихое окно ${W622_WINDOW}s ---"
_w622_drift_print() {
    echo "  дрейф[$1]: $(awk '/^ebpf_guard_drift_baseline_(profiles|learning_workloads|stuck_learning_workloads|learning_overdue_workloads|saturated_profiles|evictions_total|frozen_workloads|signature_cap_reached_total) /{printf "%s=%s ", $1, $2}' "$2")"
}
echo "  тишина перед открытием окна: ${W622_QUIET_LEAD}s (шум собственных curl'ов преflight'а уходит за границу t0)"
sleep "$W622_QUIET_LEAD"
_w622_metrics > "$W622_ART/metrics-window-start.txt"
_w622_jdrops0=$(_w622_journal_drops)
_w622_drift_print "открытие" "$W622_ART/metrics-window-start.txt"
_w622_t0=$(_w622_epoch)
echo "  окно открыто $(date -u -d "@$_w622_t0" +%FT%TZ) — до закрытия НЕ ПОДАВАТЬ вход (память ebpf-guard-measurement-hygiene, п.2/п.5)"
sleep "$W622_WINDOW"
_w622_t1=$(_w622_epoch)
_w622_metrics > "$W622_ART/metrics-window-end.txt"
_w622_jdrops1=$(_w622_journal_drops)
_w622_drift_print "закрытие" "$W622_ART/metrics-window-end.txt"
_w622_alerts > "$W622_ART/alerts-window-end.json"
# №240/открытый вопрос 14: границы окна выносятся наружу файлом-мостом —
# пайплайну нечем иначе проверить, что журнал ПОКРЫВАЕТ окно (критерий
# 6.2.2.4), потому что эпохи считаются здесь и наружу не возвращаются.
printf 't0=%s\nt1=%s\n' "$_w622_t0" "$_w622_t1" > "$W622_ART/window-epoch.txt"

# ---- 6.2.2.0, вторая половина: потери событий за окно (№222) ----
_w622_dr0=$(_w622_real_drops "$W622_ART/metrics-window-start.txt")
_w622_dr1=$(_w622_real_drops "$W622_ART/metrics-window-end.txt")
_w622_dr=$(( _w622_dr1 - _w622_dr0 ))
_w622_jdr=$(( ${_w622_jdrops1:-0} - ${_w622_jdrops0:-0} ))
echo "  потери событий за окно: метрика (без path_denylist) = $_w622_dr; журнал bulk_dropped = $_w622_jdr"
if [ "$_w622_dr" -gt 0 ] || [ "$_w622_jdr" -gt 0 ]; then
    die "6.2.2.0 ПРОВАЛЕН (половина «потери»): за окно потеряно событий — метрика $_w622_dr, журнал $_w622_jdr. Величина 6.2.2.1 срезана ПОТЕРЕЙ, а не только лимитером (находка №222). Окно НЕИЗМЕРИМО"
elif [ "$_w622_jdr" -eq 0 ] && [ "$_w622_dr" -eq 0 ]; then
    pass "6.2.2.0 ДОСТИГНУТО (половина «потери»): за окно ни метрика, ни журнал не показали потерь"
fi
if { [ "$_w622_jdr" -gt 0 ] && [ "$_w622_dr" -eq 0 ]; } || { [ "$_w622_dr" -gt 0 ] && [ "$_w622_jdr" -eq 0 ]; }; then
    die "6.2.2.0 ПРОВАЛЕН (сверка прибора): журнал говорит $_w622_jdr потерь, метрика — $_w622_dr. Потеря видимости молчалива в метриках (второй слой находки №222)"
fi

# ---- 6.2.2.1: объём ПРЯМОЙ ДЕЛЬТОЙ ДВУХ МЕТРИК, обе формулы (№227/№232) ----
_w622_vol_all=$(( $(_w622_volume_all "$W622_ART/metrics-window-end.txt") - $(_w622_volume_all "$W622_ART/metrics-window-start.txt") ))
_w622_vol_ni=$(( $(_w622_volume_noinfo "$W622_ART/metrics-window-end.txt") - $(_w622_volume_noinfo "$W622_ART/metrics-window-start.txt") ))
_w622_rl0=$(_w622_ratelimited "" "$W622_ART/metrics-window-start.txt")
_w622_rl1=$(_w622_ratelimited "" "$W622_ART/metrics-window-end.txt")
_w622_rl=$(( _w622_rl1 - _w622_rl0 ))
_w622_hour() { awk -v n="$1" -v w="$W622_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}'; }
_w622_all_hour=$(_w622_hour "$_w622_vol_all")
_w622_ni_hour=$(_w622_hour "$_w622_vol_ni")
echo "  объём ВСЁ, формула (а):        $_w622_vol_all → $_w622_all_hour/ч"
echo "  объём БЕЗ info, формула (б):   $_w622_vol_ni → $_w622_ni_hour/ч"
echo "  цена решения №232 числом:      $(( _w622_vol_all - _w622_vol_ni )) алертов severity=info за окно"
if [ "$W622_GATE_FORMULA" = "noinfo" ]; then
    _w622_vol=$_w622_vol_ni; _w622_vol_hour=$_w622_ni_hour
else
    _w622_vol=$_w622_vol_all; _w622_vol_hour=$_w622_all_hour
fi
_w622_true_hour=$(_w622_hour "$(( _w622_vol + _w622_rl ))")
echo "  ← ВЕЛИЧИНА КРИТЕРИЯ (формула $W622_GATE_FORMULA): $_w622_vol_hour/ч при гейте ${W622_GATE}/ч"
echo "  срез лимитера за окно (alerts_ratelimited_by_rule_total): $_w622_rl"
echo "  нижняя оценка РЕАЛЬНОГО числа срабатываний: $(( _w622_vol + _w622_rl )) → $_w622_true_hour/ч"

# ---- 6.2.2.2: список срезанных правил ПО МЕТРИКЕ (№238) ----
echo "--- 6.2.2.2: правила со срезом лимитера за окно (по метрике, не по стору) ---"
_w622_rl_list=""
if [ "$W622_LIB_OK" -eq 1 ]; then
    _w622_rl_list=$(w622_ratelimited_by_rule "$W622_ART/metrics-window-start.txt" "$W622_ART/metrics-window-end.txt")
    printf '%s\n' "${_w622_rl_list:-  (ни одно правило не срезано)}" | sed 's/^/    /'
    printf '%s\n' "$_w622_rl_list" > "$W622_ART/ratelimited-by-rule.txt"
fi
_w622_rl_n=$(printf '%s' "$_w622_rl_list" | grep -c . )
if [ "$W622_LIB_OK" -ne 1 ]; then
    die "6.2.2.2 НЕИЗМЕРИМ: библиотека не подключилась (см. преflight)"
elif [ "$_w622_rl" -gt 0 ] && [ "${_w622_rl_n:-0}" -eq 0 ]; then
    die "6.2.2.2 ПРОВАЛЕН (дефект ИЗМЕРИТЕЛЯ, не продукта): сумма среза лимитера за окно = $_w622_rl, а поимённый список ПУСТ. Это ровно находка №238: «нет срезанных» при ненулевом срезе означает, что цикл не видел правил, а не что их нет"
elif [ "$_w622_rl" -eq 0 ] && [ "${_w622_rl_n:-0}" -eq 0 ]; then
    pass "6.2.2.2 ДОСТИГНУТО: срез лимитера за окно нулевой, и поимённый список пуст согласованно (сумма 0 = список пуст)"
else
    pass "6.2.2.2 ДОСТИГНУТО: $_w622_rl_n правил со срезом напечатаны поимённо при сумме среза $_w622_rl (6.2.1 печатала «нет» при срезе +530)"
fi

# ---- 6.2.2.3: разбивка величины покрывает её саму (№239) ----
echo "--- 6.2.2.3: разбивка величины по правилам (по метрике) ---"
if [ "$W622_LIB_OK" -eq 1 ]; then
    w622_volume_by_rule "$W622_ART/metrics-window-start.txt" "$W622_ART/metrics-window-end.txt" > "$W622_ART/volume-by-rule.txt"
    head -20 "$W622_ART/volume-by-rule.txt" | sed 's/^/    /'
    _w622_sum=$(awk '{s+=$2} END{printf "%d", s+0}' "$W622_ART/volume-by-rule.txt")
    echo "  прямая дельта объёма (формула all): $_w622_vol_all; сумма разбивки: $_w622_sum"
    if [ "$_w622_vol_all" -le 0 ]; then
        die "6.2.2.3 НЕИЗМЕРИМ: прямая дельта объёма за окно не положительна ($_w622_vol_all) — покрытие считать не от чего"
    else
        _w622_cov=$(awk -v s="$_w622_sum" -v v="$_w622_vol_all" 'BEGIN{printf "%.1f", 100.0*s/v}')
        echo "  покрытие разбивки: ${_w622_cov}% (требуется ≥ 95%; версия 6.2.1 давала 4.3%)"
        if awk -v s="$_w622_sum" -v v="$_w622_vol_all" 'BEGIN{exit !(s >= 0.95*v)}'; then
            pass "6.2.2.3 ДОСТИГНУТО: разбивка покрывает ${_w622_cov}% величины — это законный вход для сужения"
        else
            die "6.2.2.3 ПРОВАЛЕН: разбивка покрывает лишь ${_w622_cov}% величины ($_w622_sum из $_w622_vol_all). Сужение по такой разбивке — работа вслепую (находка №239), правки на её основании запрещены"
        fi
    fi
else
    die "6.2.2.3 НЕИЗМЕРИМ: библиотека не подключилась"
fi

# Сторовая разбивка по comm — СПРАВОЧНО. Ни у alerts_total, ни у
# alerts_filtered_total нет лейбла comm, метрикой эту ось не восстановить.
_w622_new=$(jq --argjson t0 "$_w622_t0" --argjson t1 "$_w622_t1" --arg actors "$W622_NODE_ACTORS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select(((.enrichment.namespace // "") != "") or ((.comm) as $c | ($actors|split(" "))|index($c))) ]
    ' "$W622_ART/alerts-window-end.json" 2>/dev/null)
echo "  (справочно, сторовый счёт нодовых алертов окна: $(echo "${_w622_new:-[]}" | jq 'length' 2>/dev/null) — вердикта не выносит, находки №227/№239)"
echo "  разбивка по comm (стор, справочно — метрикой эта ось не восстановима):"
echo "${_w622_new:-[]}" | jq -r 'group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' 2>/dev/null | head -15

# ---- 6.2.2.5: доля измерителя в окне = 0 (№242) ----
echo "--- 6.2.2.5: доля измерителя внутри окна (ВЕРДИКТ, а не поправка) ---"
_w622_instr=$(jq --argjson t0 "$_w622_t0" --argjson t1 "$_w622_t1" --argjson comms "$W622_INSTR_COMMS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.comm) as $c | ($comms|index($c))) ]
    | group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)' "$W622_ART/alerts-window-end.json" 2>/dev/null)
_w622_instr_n=$(echo "${_w622_instr:-[]}" | jq '[.[].n]|add // 0' 2>/dev/null)
# Вторая половина критерия: алерты НА ПУТИ артефактов контроля. Файл
# metrics-window-start.txt создаётся в каталоге, за которым следит
# drift_new_file_dir_sensitive; правка №242 переносит запись ДО t0, но
# остаточная гонка (задержка ring buffer) аналитически не закрывается —
# открытый вопрос 16 требует проверить это ЖИВЫМ прогоном, здесь и сейчас.
_w622_artpath=$(jq --argjson t0 "$_w622_t0" --argjson t1 "$_w622_t1" --arg art "$W622_ART" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.details["file.path"] // "") | startswith($art)) ] | length' "$W622_ART/alerts-window-end.json" 2>/dev/null)
echo "  алертов от comm измерителя внутри [t0,t1]: ${_w622_instr_n:-0} $(echo "${_w622_instr:-[]}" | jq -r 'map("\(.c):\(.n)")|join(" ")' 2>/dev/null)"
echo "  алертов на пути артефактов ($W622_ART) внутри [t0,t1]: ${_w622_artpath:-0}"
if [ "${_w622_instr_n:-0}" -eq 0 ] && [ "${_w622_artpath:-0}" -eq 0 ]; then
    pass "6.2.2.5 ДОСТИГНУТО: измеритель внутри окна не работал — ни одного его алерта, ни одного алерта на пути его артефактов (открытый вопрос 16 закрыт живым прогоном)"
else
    die "6.2.2.5 ПРОВАЛЕН: внутри окна ${_w622_instr_n:-0} алертов от comm измерителя и ${_w622_artpath:-0} на пути его артефактов. Это ЧАСТЬ измеренной величины 6.2.2.1, а не поправка к её чтению: контроль обязан не работать внутри окна вовсе (находка №242). Если ненулевая половина — путь артефактов, починка не в порядке операций, а в переносе снимков ВНЕ поддерева, за которым следит drift_new_file_dir_sensitive (открытый вопрос 16)"
fi

# ---- Вердикт 6.2.2.1. Порядок проверок: срез может только ЗАНИЗИТЬ, поэтому
#      превышение порога доказано и при срезе. «Неизмеримо» остаётся для
#      случая «порог не перешли, но прибор упёрт» (пункт Е). ----
if [ "$_w622_vol_hour" -gt "$W622_GATE" ]; then
    die "6.2.2.1 ПРОВАЛЕН (величина — НИЖНЯЯ оценка): цена ноды $_w622_vol_hour алертов/ч (формула $W622_GATE_FORMULA) при гейте волны 6 «не выше ${W622_GATE}/ч»; с учётом среза лимитера реальное число не менее $_w622_true_hour/ч. Разбивка 6.2.2.3 — вход для сужения, а не повод понизить порог"
elif [ "${_w622_rl_n:-0}" -gt 0 ]; then
    die "6.2.2.1 НЕИЗМЕРИМ ПО БУКВЕ: величина $_w622_vol_hour/ч порог не перешла, но $_w622_rl_n правил имеют срез лимитера за окно (список выше) — их вклад есть показание упёршегося прибора (10/60с), и «≤${W622_GATE}/ч» здесь показание, а не вердикт (пункт Е)"
else
    pass "6.2.2.1 ДОСТИГНУТО: цена ноды $_w622_vol_hour алертов/ч ≤ ${W622_GATE}/ч (формула $W622_GATE_FORMULA), ни одно правило не срезано лимитером за окно"
fi

# ---- 6.2.2.11: потолок ресурсов против лимита чарта (№244) ----
echo "--- 6.2.2.11: ресурсы агента на открытии и закрытии окна против лимита чарта ---"
_w622_values="$W622_REPO/deploy/helm/ebpf-guard/values.yaml"
# Берётся limits.memory ПЕРВОГО блока resources (сам агент), а не limits
# сайдкаров/тестовых подов ниже по файлу.
_w622_limit_h=$(awk '
    /^resources:/ { inres=1; next }
    inres && /^[A-Za-z#]/ { exit }                      # блок кончился — дальше чужие resources
    inres && /^[[:space:]]+limits:/ { inlim=1; next }
    inres && inlim && /^[[:space:]]+[a-z]+:[[:space:]]*$/ { exit }   # начался requests:
    inres && inlim && /memory:/ { print $2; exit }' "$_w622_values" 2>/dev/null)
_w622_limit_b=$(awk -v v="${_w622_limit_h:-}" 'BEGIN{
    if (v ~ /Mi$/) { sub(/Mi$/,"",v); printf "%d", v*1024*1024 }
    else if (v ~ /Gi$/) { sub(/Gi$/,"",v); printf "%d", v*1024*1024*1024 }
    else if (v ~ /M$/) { sub(/M$/,"",v); printf "%d", v*1000*1000 }
    else printf "0" }')
_w622_res_print() { # $1=метка $2=файл среза
    echo "  ресурсы[$1]: RSS=$(awk -v b="$(_w622_metric_raw process_resident_memory_bytes "$2")" 'BEGIN{printf "%.1f МиБ", b/1048576}')" \
         "heap=$(awk -v b="$(_w622_metric_raw go_memstats_heap_alloc_bytes "$2")" 'BEGIN{printf "%.1f МиБ", b/1048576}')" \
         "goroutines=$(_w622_metric_raw go_goroutines "$2")" \
         "cpu_total=$(_w622_metric_raw process_cpu_seconds_total "$2")s"
}
_w622_res_print "открытие" "$W622_ART/metrics-window-start.txt"
_w622_res_print "закрытие" "$W622_ART/metrics-window-end.txt"
_w622_rss1=$(_w622_metric_raw process_resident_memory_bytes "$W622_ART/metrics-window-end.txt")
_w622_rss0=$(_w622_metric_raw process_resident_memory_bytes "$W622_ART/metrics-window-start.txt")
_w622_lat_sum0=$(awk '$1=="ebpf_guard_correlation_latency_seconds_sum"{printf "%.6f", $2+0}' "$W622_ART/metrics-window-start.txt")
_w622_lat_cnt0=$(awk '$1=="ebpf_guard_correlation_latency_seconds_count"{printf "%.0f", $2+0}' "$W622_ART/metrics-window-start.txt")
_w622_lat_sum1=$(awk '$1=="ebpf_guard_correlation_latency_seconds_sum"{printf "%.6f", $2+0}' "$W622_ART/metrics-window-end.txt")
_w622_lat_cnt1=$(awk '$1=="ebpf_guard_correlation_latency_seconds_count"{printf "%.0f", $2+0}' "$W622_ART/metrics-window-end.txt")
echo "  латентность корреляции ЗА ОКНО: $(awk -v s0="${_w622_lat_sum0:-0}" -v s1="${_w622_lat_sum1:-0}" -v c0="${_w622_lat_cnt0:-0}" -v c1="${_w622_lat_cnt1:-0}" 'BEGIN{d=c1-c0; if(d>0) printf "%.1f мкс/событие (Δsum=%.3fs ÷ Δcount=%d)", (s1-s0)/d*1e6, s1-s0, d; else printf "НЕИЗМЕРИМА (Δcount=%d)", d}')"
echo "  распределение по бакетам (накопительно, закрытие окна):"
awk '/^ebpf_guard_correlation_latency_seconds_bucket/{gsub(/.*le="/,"");gsub(/"}/," ");printf "    le=%s\n", $0}' "$W622_ART/metrics-window-end.txt" | head -12
echo "  лимит чарта (deploy/helm/ebpf-guard/values.yaml, resources.limits.memory): ${_w622_limit_h:-НЕ ПРОЧИТАН}"
if [ -z "${_w622_rss1:-}" ] || [ "${_w622_limit_b:-0}" -le 0 ]; then
    die "6.2.2.11 НЕИЗМЕРИМ: RSS=${_w622_rss1:-нет} или лимит чарта=${_w622_limit_h:-нет} не прочитаны — «запас до лимита» считать не от чего"
else
    echo "  запас до лимита на закрытии: $(awk -v l="$_w622_limit_b" -v r="$_w622_rss1" 'BEGIN{printf "%.1f МиБ (%.1f%%)", (l-r)/1048576, 100.0*(l-r)/l}')"
    echo "  рост RSS за окно: $(awk -v a="${_w622_rss0:-0}" -v b="$_w622_rss1" 'BEGIN{printf "%+.1f МиБ", (b-a)/1048576}')"
    if [ "${_w622_rss1:-0}" -gt "${_w622_limit_b:-0}" ]; then
        die "6.2.2.11 ПРОВАЛЕН: RSS $(awk -v r="$_w622_rss1" 'BEGIN{printf "%.1f", r/1048576}') МиБ ВЫШЕ лимита чарта ${_w622_limit_h}. В DaemonSet это OOM-kill, а не «чуть больше»"
    else
        pass "6.2.2.11 ДОСТИГНУТО: RSS $(awk -v r="$_w622_rss1" 'BEGIN{printf "%.1f", r/1048576}') МиБ ниже лимита чарта ${_w622_limit_h}; порог не назначается (запрет 5.9.6), величина печатается"
    fi
fi

# ---- 6.2.2.7, пассивная половина: приращение счётчика заморозки (№237) ----
echo "--- 6.2.2.7 (наблюдение): потолки базы дрейфа за окно ---"
_w622_maxw=$(echo "$_w622_drift_cfg" | grep -oE 'max_workloads:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w622_maxsig=$(echo "$_w622_drift_cfg" | grep -oE 'max_signatures_per_workload:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w622_prof=$(_w622_metric_sum ebpf_guard_drift_baseline_profiles "" "$W622_ART/metrics-window-end.txt")
_w622_evict=$(_w622_metric_sum ebpf_guard_drift_baseline_evictions_total "" "$W622_ART/metrics-window-end.txt")
# №237, дефект 2: вердикт по РАЗНОСТИ ДВУХ СНИМКОВ, а не по наличию имени
# метрики в выдаче (Prometheus печатает нулевые счётчики всегда).
_w622_cap0=$(_w622_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "" "$W622_ART/metrics-window-start.txt")
_w622_cap1=$(_w622_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "" "$W622_ART/metrics-window-end.txt")
# №237, дефект 1: журнал ограничен ОКНОМ, а не всей историей юнита.
_w622_frozen_j=$(journalctl -u "$W622_SVC" --since "@$_w622_t0" --until "@$_w622_t1" --no-pager 2>/dev/null | grep -c 'workload signature cap reached')
echo "  профилей=$_w622_prof при max_workloads=${_w622_maxw:-?}; вытеснений=$_w622_evict"
echo "  max_signatures_per_workload=${_w622_maxsig:-?}; приращение signature_cap_reached_total ЗА ОКНО: $(( _w622_cap1 - _w622_cap0 )) (накопительно $_w622_cap1)"
echo "  строк «signature cap reached» в журнале ЗА ОКНО: $_w622_frozen_j"
echo "  6.2.2.7 (пассивная половина): наблюдение без порога — при max_signatures=${_w622_maxsig:-?} кап в тихом окне достигаться и не обязан. Вердикт выносит позитивный подконтроль в конце прогона"

# ---- 6.2.2.6, живая половина «фон молчит» ----
echo "--- 6.2.2.6 (живая половина 1/2): три правки условий на РЕАЛЬНОМ фоне ноды ---"
for _r in c2_periodic_beacon_pattern beacon_fixed_interval sigma_iptables_flush sigma_log_deletion; do
    _a0=$(_w622_metric_sum ebpf_guard_alerts_total "$_r" "$W622_ART/metrics-window-start.txt")
    _a1=$(_w622_metric_sum ebpf_guard_alerts_total "$_r" "$W622_ART/metrics-window-end.txt")
    _f0=$(_w622_metric_sum ebpf_guard_alerts_filtered_total "$_r" "$W622_ART/metrics-window-start.txt")
    _f1=$(_w622_metric_sum ebpf_guard_alerts_filtered_total "$_r" "$W622_ART/metrics-window-end.txt")
    _rl0=$(_w622_ratelimited "$_r" "$W622_ART/metrics-window-start.txt")
    _rl1=$(_w622_ratelimited "$_r" "$W622_ART/metrics-window-end.txt")
    echo "    $_r: за окно всего $(( (_a1 - _a0) + (_f1 - _f0) )) (экспортировано $(( _a1 - _a0 )), срезано min_severity $(( _f1 - _f0 )), срез лимитера $(( _rl1 - _rl0 )))"
done
echo "    (на окне 6.2.1 c2_periodic_beacon_pattern дал 602 — 71% всей величины прогона)"

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.10 ОКНО ПРОФИЛЯ (№244). ОТДЕЛЬНОЕ окно, сразу ПОСЛЕ окна объёма:
# `curl /debug/pprof/profile?seconds=30` — действие измерителя, и внутри окна
# объёма оно нарушило бы 6.2.2.5.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.10: окно профиля ${W622_PROFILE_SECS}s (ОТДЕЛЬНОЕ, после окна объёма) ---"
mkdir -p "$W622_ART/profile" 2>/dev/null
_w622_pcpu0=$(_w622_metric_raw process_cpu_seconds_total "$W622_ART/metrics-window-end.txt")
_w622_pt0=$(_w622_epoch)
_w622_curl "$W622_API/debug/pprof/profile?seconds=$W622_PROFILE_SECS" > "$W622_ART/profile/cpu.pprof" 2>/dev/null
_w622_curl "$W622_API/debug/pprof/heap" > "$W622_ART/profile/heap.pprof" 2>/dev/null
_w622_curl "$W622_API/debug/pprof/goroutine?debug=1" > "$W622_ART/profile/goroutine.txt" 2>/dev/null
_w622_metrics > "$W622_ART/profile/metrics-profile-end.txt"
_w622_pt1=$(_w622_epoch)
_w622_pcpu1=$(_w622_metric_raw process_cpu_seconds_total "$W622_ART/profile/metrics-profile-end.txt")
_w622_psize=$(wc -c < "$W622_ART/profile/cpu.pprof" 2>/dev/null | tr -d ' ')
echo "  профиль снят: cpu.pprof ${_w622_psize:-0} байт, heap.pprof $(wc -c < "$W622_ART/profile/heap.pprof" 2>/dev/null | tr -d ' ') байт"
echo "  дельта process_cpu_seconds_total за окно профиля: $(awk -v a="${_w622_pcpu0:-0}" -v b="${_w622_pcpu1:-0}" -v t="$(( _w622_pt1 - _w622_pt0 ))" 'BEGIN{if(t>0) printf "%.2f с за %d с = %.1f%% ядра", b-a, t, 100.0*(b-a)/t; else printf "НЕИЗМЕРИМА"}')"
if [ "${_w622_psize:-0}" -lt 1000 ]; then
    die "6.2.2.10 ПРОВАЛЕН: профиль не снят (cpu.pprof ${_w622_psize:-0} байт). «34% ядра» без разбора — не величина, а незнание (находка №244); отсутствие профиля в архиве есть провал критерия, а не оговорка"
else
    echo "  top-10 функций по CPU:"
    if [ -x "$W622_GO" ]; then
        "$W622_GO" tool pprof -top -nodecount=10 "$W622_REPO/build/ebpf-guard" "$W622_ART/profile/cpu.pprof" 2>/dev/null \
            | tee "$W622_ART/profile/top10.txt" | sed 's/^/    /'
    fi
    if [ -s "$W622_ART/profile/top10.txt" ]; then
        pass "6.2.2.10 ДОСТИГНУТО: профиль снят в отдельном окне и разобран top-10 (порог не назначается — запрет 5.9.6)"
    else
        die "6.2.2.10 ПРОВАЛЕН (половина «разбор»): профиль снят (${_w622_psize} байт), но top-10 не построен — go tool pprof недоступен ($W622_GO) или бинарь $W622_REPO/build/ebpf-guard не совпал с профилем. Профиль без разбора вердикта не даёт"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# ВХОД ПОДАЁТСЯ ЗДЕСЬ, ПОСЛЕ ОБОИХ ОКОН (память
# control-after-attacks-hits-filled-limiter).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.2 (регрессия): сторож слепоты лимитера (хостовое чтение токена пода) ---"
W622_HOSTCAT_PODDED=0
if [ "$W622_INSTRUMENTED" -eq 1 ]; then
    _w622_target=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w622_target" ] && _w622_target=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w622_target" ]; then
        die "6.2.1.2 НЕИЗМЕРИМ: под /var/lib/kubelet/pods нет ни одного файла — хостовую половину нечем подать, ноль был бы приборным"
    else
        _w622_hrl0=$(_w622_ratelimited "$W622_HOST_RULES")
        cp /bin/cat /usr/local/bin/w622hostcat 2>/dev/null
        _w622_tn=$(_w622_epoch)
        _w622_bytes=$(/usr/local/bin/w622hostcat "$_w622_target" 2>/dev/null | wc -c)
        _w622_hits=0; _w622_waited=0
        while [ "$_w622_waited" -lt "$W622_POS_TIMEOUT" ]; do
            sleep "$W622_SETTLE"; _w622_waited=$(( _w622_waited + W622_SETTLE ))
            _w622_hits=$(_w622_alerts | jq --argjson t "$_w622_tn" --arg ids "$W622_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w622hostcat") and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w622_hits:-0}" -gt 0 ] && break
        done
        _w622_hrl1=$(_w622_ratelimited "$W622_HOST_RULES")
        _w622_all=$(_w622_alerts | jq --argjson t "$_w622_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w622hostcat"))]|length' 2>/dev/null || echo 0)
        _w622_rules=$(_w622_alerts | jq -r --argjson t "$_w622_tn" '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w622hostcat"))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
        echo "  сторож результата: прочитано байт = $_w622_bytes (цель $_w622_target)"
        echo "  алертов от comm=w622hostcat: всего $_w622_all (правила: ${_w622_rules:-нет}); из них обязательных: $_w622_hits"
        echo "  срез лимитера обязательных правил за время контроля: $(( _w622_hrl1 - _w622_hrl0 ))"
        if [ "${_w622_bytes:-0}" -lt 1 ]; then
            die "6.2.1.2 НЕИЗМЕРИМ: хостовой читатель ничего не прочитал (байт=$_w622_bytes) — ноль приборный (память positive-control-needs-result-sentinel)"
        elif [ "${_w622_hits:-0}" -lt 1 ] && [ "$(( _w622_hrl1 - _w622_hrl0 ))" -gt 0 ]; then
            die "6.2.1.2 ПРОВАЛЕН (шум→слепота, регресс находки №221): хост прочитал токен ($_w622_bytes байт), обязательные правила не поднялись, И их лимитер срезал $(( _w622_hrl1 - _w622_hrl0 )) срабатываний"
        elif [ "${_w622_hits:-0}" -lt 1 ]; then
            die "6.2.1.2 ПРОВАЛЕН (детекта нет): хост прочитал токен пода ($_w622_bytes байт), обязательные правила не поднялись, лимитер их НЕ срезал"
        else
            pass "6.2.1.2 ДОСТИГНУТО: хостовое чтение токена пода подняло $_w622_hits обязательных алертов (${_w622_rules})"
        fi
        W622_HOSTCAT_PODDED=$(_w622_alerts | jq --argjson t "$_w622_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w622hostcat") and ((.enrichment.pod_name // "")!=""))]|length' 2>/dev/null || echo 0)
        rm -f /usr/local/bin/w622hostcat 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.3 (регрессия) НЕГАТИВНЫЙ КОНТРОЛЬ НА ПОЛНОМ ОБЪЁМЕ (находка №227).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.3 (регрессия): негативный контроль на полном объёме ---"
if [ "$W622_INSTRUMENTED" -eq 1 ]; then
    _w622_alerts > "$W622_ART/alerts-negative.json"
    echo "  comm, у которых ХОТЬ ОДИН алерт несёт pod_name (это обязаны быть только поды):"
    jq -r '[.[]|select((.enrichment.pod_name // "")!="")]|group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W622_ART/alerts-negative.json" 2>/dev/null | head -20
    _w622_bad=$(jq -r '[.[]|select(((.enrichment.pod_name // "")!="") and ((.enrichment.container_id // "")==""))]|length' "$W622_ART/alerts-negative.json" 2>/dev/null || echo 0)
    _w622_hostpodded=$(jq -r --arg h "k3s-server iptables ip6tables systemd sshd cron kubectl systemd-logind" \
        '[.[]|select(((.enrichment.pod_name // "")!="") and ((.comm) as $c|($h|split(" "))|index($c)))]|length' "$W622_ART/alerts-negative.json" 2>/dev/null || echo 0)
    echo "  алертов с pod_name БЕЗ container_id: $_w622_bad"
    echo "  алертов с pod_name у заведомо хостовых comm: $_w622_hostpodded"
    echo "  алертов с pod_name у контрольного хостового читателя: ${W622_HOSTCAT_PODDED:-0}"
    if [ "${_w622_hostpodded:-0}" -gt 0 ] || [ "${W622_HOSTCAT_PODDED:-0}" -gt 0 ] || [ "${_w622_bad:-0}" -gt 0 ]; then
        die "6.2.1.3 ПРОВАЛЕН: хостовые процессы получили ЧУЖУЮ личность пода (хостовые comm: $_w622_hostpodded, без container_id: $_w622_bad, контрольный читатель: ${W622_HOSTCAT_PODDED:-0})"
    else
        pass "6.2.1.3 ДОСТИГНУТО: ни один хостовой процесс не получил личность пода"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.2b (регрессия) ПОЗИТИВНЫЙ КОНТРОЛЬ ОСИ ПОДА.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.2b (регрессия): под читает свой SA-токен ---"
if [ "$W622_INSTRUMENTED" -eq 1 ]; then
    "$W622_KUBECTL" create namespace "$W622_NS" --dry-run=client -o yaml 2>/dev/null | "$W622_KUBECTL" apply -f - >/dev/null 2>&1
    "$W622_KUBECTL" -n "$W622_NS" delete pod w622-token-probe --ignore-not-found --wait=true >/dev/null 2>&1
    cat > "$W622_ART/w622-token-probe.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: w622-token-probe
  labels:
    app: w622-token-probe
spec:
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sh","-c"]
    args:
      - |
        i=0
        while [ $i -lt 30 ]; do
          read t < /run/secrets/kubernetes.io/serviceaccount/token
          echo "W622-SENTINEL opener_comm=$(cat /proc/$$/comm) token_head=$(echo "$t" | cut -c1-12) token_len=${#t}"
          i=$((i+1)); sleep 2
        done
    volumeMounts:
    - name: satoken
      mountPath: /run/secrets/kubernetes.io/serviceaccount
      readOnly: true
  volumes:
  - name: satoken
    projected:
      sources:
      - serviceAccountToken:
          path: token
YAML
    _w622_tp=$(_w622_epoch)
    "$W622_KUBECTL" -n "$W622_NS" apply -f "$W622_ART/w622-token-probe.yaml" >/dev/null 2>&1
    "$W622_KUBECTL" -n "$W622_NS" wait --for=condition=Ready pod/w622-token-probe --timeout=90s >/dev/null 2>&1
    _w622_pdelta=0; _w622_waited=0
    while [ "$_w622_waited" -lt "$W622_POS_TIMEOUT" ]; do
        sleep "$W622_SETTLE"; _w622_waited=$(( _w622_waited + W622_SETTLE ))
        _w622_pdelta=$(_w622_alerts | jq --arg ids "$W622_K8S_RULES" --argjson t "$_w622_tp" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w622-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]|length' 2>/dev/null || echo 0)
        [ "${_w622_pdelta:-0}" -gt 0 ] && break
    done
    _w622_sent=$("$W622_KUBECTL" -n "$W622_NS" logs w622-token-probe 2>/dev/null | grep -m1 'W622-SENTINEL')
    _w622_phit=$(_w622_alerts | jq -r --arg ids "$W622_K8S_RULES" --argjson t "$_w622_tp" \
        '.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w622-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    echo "  ожидание записи в стор: ${_w622_waited}s"
    echo "  сторож результата: ${_w622_sent:-НЕ НАПЕЧАТАН}"
    echo "  алертов с pod_name=w622-token-probe: $_w622_pdelta (правила: ${_w622_phit:-нет})"
    _w622_len=$(printf '%s' "${_w622_sent:-}" | grep -oE 'token_len=[0-9]+' | cut -d= -f2)
    if [ -z "${_w622_len:-}" ] || [ "${_w622_len:-0}" -lt 100 ]; then
        die "6.2.1.2b НЕИЗМЕРИМ: сторож результата не напечатал прочитанный токен (token_len=${_w622_len:-нет}) — ноль правил приборный"
    elif [ "$_w622_pdelta" -lt 1 ]; then
        die "6.2.1.2b ПРОВАЛЕН: под прочитал токен (token_len=$_w622_len), а правила ${W622_K8S_RULES} не поднялись с его именем"
    else
        pass "6.2.1.2b ДОСТИГНУТО: чтение SA-токена подом подтверждено сторожем (token_len=$_w622_len) и подняло $_w622_pdelta алертов С ИМЕНЕМ ПОДА (${_w622_phit})"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.8 ЦЕНА СТАРТА ПОДА — С ПОРОГОМ (№236).
# Порог 45/под = ceil(36 × 1.25): 36 измерено прогоном 6.2.1 (108 алертов на
# 3 оборота), 25% запаса на то, что величина снята ОДНИМ прогоном.
# Бюджет ОТДЕЛЬНЫЙ от 6.2.2.1: окна физически не пересекаются (churn идёт
# после тихого окна). Вопрос «как боевой часовой гейт учитывает непрерывный
# churn» этим порогом НЕ закрыт и остаётся открытым (пункт 10 plan.md).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.8: цена одного старта пода, порог ${W622_CHURN_BUDGET}/под ---"
if [ "$W622_INSTRUMENTED" -eq 1 ]; then
    _w622_tc=$(_w622_epoch)
    for i in $(seq 1 "$W622_CHURN"); do
        "$W622_KUBECTL" -n "$W622_NS" run "w622-churn-$i" --image=busybox:1.36 --restart=Never --command -- sleep 15 >/dev/null 2>&1
    done
    sleep 45
    for i in $(seq 1 "$W622_CHURN"); do "$W622_KUBECTL" -n "$W622_NS" delete pod "w622-churn-$i" --ignore-not-found --wait=false >/dev/null 2>&1; done
    sleep $(( W622_SETTLE * 3 ))
    _w622_alerts > "$W622_ART/alerts-churn-end.json"
    _w622_churn=$(jq --argjson t "$_w622_tc" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm|test("^(runc|containerd|conmon|crun|dockerd|pause)")))]' "$W622_ART/alerts-churn-end.json" 2>/dev/null)
    _w622_cn=$(echo "${_w622_churn:-[]}" | jq 'length' 2>/dev/null); _w622_cn=${_w622_cn:-0}
    _w622_per=$(awk -v n="$_w622_cn" -v p="$W622_CHURN" 'BEGIN{printf "%.1f", (p>0? n/p : 0)}')
    echo "  запущено и снято подов: $W622_CHURN; алертов от рантайм-comm: $_w622_cn → $_w622_per на под (порог ${W622_CHURN_BUDGET})"
    echo "${_w622_churn:-[]}" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -25
    if awk -v v="$_w622_per" -v b="$W622_CHURN_BUDGET" 'BEGIN{exit !(v > b)}'; then
        die "6.2.2.8 ПРОВАЛЕН: старт пода стоит $_w622_per алертов при бюджете ${W622_CHURN_BUDGET}/под (36 × 1.25, №236). Глушить по comm=runc нельзя — это ровно те правила, что обязаны ловить контейнерный побег; чинится сужением условий, а не исключением"
    else
        pass "6.2.2.8 ДОСТИГНУТО: старт пода стоит $_w622_per алертов ≤ ${W622_CHURN_BUDGET}/под"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.8 (регрессия) СЛОЙ 2: КЛЮЧ ИСКЛЮЧЕНИЯ, КОТОРЫЙ ПРОЦЕСС СЕБЕ НЕ НАЗНАЧАЕТ.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.8 (регрессия): образ процесса как ключ исключения ---"
if [ "$W622_INSTRUMENTED" -eq 1 ]; then
    W622_EXE_PREFIXES="/usr/ /bin/ /sbin/ /opt/ /var/lib/rancher/"
    _w622_exe_bad=""
    for _c in k3s-server containerd kubelet coredns; do
        _p=$(pgrep -x "$_c" 2>/dev/null | head -1)
        if [ -z "$_p" ]; then
            echo "  $_c: процесса нет на этой ноде (исключение для него на этом прогоне не проверяется)"
            continue
        fi
        _e=$(readlink "/proc/$_p/exe" 2>/dev/null)
        echo "  $_c: pid=$_p exe=${_e:-<не читается>}"
        [ "$_c" = "coredns" ] && continue
        _ok=0
        for _pre in $W622_EXE_PREFIXES; do
            case "${_e:-}" in "$_pre"*) _ok=1 ;; esac
        done
        [ "$_ok" -eq 1 ] || _w622_exe_bad="$_w622_exe_bad $_c(${_e:-<пусто>})"
    done
    echo "  обращений к /proc за образом (ebpf_guard_exe_path_lookups_total, накопительно): $(_w622_metric_sum ebpf_guard_exe_path_lookups_total "" 2>/dev/null)"
    if [ -n "$_w622_exe_bad" ]; then
        die "6.2.1.8 ПРОВАЛЕН (половина «покрытие»): образ демона(ов)$_w622_exe_bad не попадает ни под один префикс правил ($W622_EXE_PREFIXES) — исключения фона ноды для них НЕ ПРИМЕНЯЮТСЯ"
    else
        pass "6.2.1.8 ДОСТИГНУТО (половина «покрытие»): образы всех найденных хостовых демонов попадают под префиксы исключений"
    fi

    _w622_target8=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w622_target8" ] && _w622_target8=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w622_target8" ]; then
        die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): под /var/lib/kubelet/pods нет ни одного файла — подделке нечего читать"
    else
        # ИМЯ КОПИИ — РОВНО ИМЯ ДЕМОНА: comm ядро берёт из базового имени
        # образа в execve, `exec -a` подменяет только argv[0] (память
        # exec-a-argv0-spoof-kills-proc-args). Иначе исключение
        # node-host-daemon не применилось бы В ЛЮБОМ СЛУЧАЕ и контроль
        # проверял бы не слой 2.
        rm -rf /tmp/w622-bypass 2>/dev/null
        mkdir -p /tmp/w622-bypass 2>/dev/null
        cp /bin/cat /tmp/w622-bypass/k3s-server 2>/dev/null
        chmod 0755 /tmp/w622-bypass/k3s-server 2>/dev/null
        _w622_t8=$(_w622_epoch)
        ( exec -a k3s-server /tmp/w622-bypass/k3s-server "$_w622_target8" ) > /tmp/w622-bypass/out 2>/dev/null &
        _w622_p8=$!
        wait "$_w622_p8" 2>/dev/null
        _w622_b8=$(wc -c < /tmp/w622-bypass/out 2>/dev/null | tr -d ' ')
        _w622_h8=0; _w622_w8=0
        while [ "$_w622_w8" -lt "$W622_POS_TIMEOUT" ]; do
            sleep "$W622_SETTLE"; _w622_w8=$(( _w622_w8 + W622_SETTLE ))
            _w622_h8=$(_w622_alerts | jq --argjson t "$_w622_t8" --argjson p "${_w622_p8:-0}" --arg ids "$W622_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.pid == $p) and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w622_h8:-0}" -gt 0 ] && break
        done
        _w622_c8=$(_w622_alerts | jq -r --argjson p "${_w622_p8:-0}" '[.[]|select(.pid == $p)][0].comm // "нет алертов от этого pid"' 2>/dev/null)
        echo "  сторож результата подделки: прочитано байт = $_w622_b8 (цель $_w622_target8)"
        echo "  подделка: pid=$_w622_p8, образ /tmp/w622-bypass/k3s-server, comm в сторе=$_w622_c8"
        echo "  алертов от подделки (по её pid): $_w622_h8 из обязательных ($W622_HOST_RULES)"
        if [ "${_w622_b8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не прочитала ни байта — ноль правил приборный"
        elif [ "$_w622_c8" != "k3s-server" ] && [ "${_w622_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не носит имени демона — стор знает её как «$_w622_c8». При таком comm исключение не применилось бы в любом случае, и слой 2 контроль не проверял"
        elif [ "${_w622_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 ПРОВАЛЕН (половина «отказ обхода»): процесс, назвавшийся k3s-server и прочитавший токен пода ($_w622_b8 байт), НЕ поднял ни одного из $W622_HOST_RULES — исключение следует за именем, а не за образом"
        else
            pass "6.2.1.8 ДОСТИГНУТО (половина «отказ обхода»): подделка носила имя демона (comm=$_w622_c8), но не унаследовала его тишину — поднято $_w622_h8 обязательных правил"
        fi
        rm -rf /tmp/w622-bypass 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.9 (регрессия) СЛОЙ 3: СМЕНА ПРАВ НА ФАЙЛОВОЙ ОСИ + вторая половина
# №243 (chmod даёт ровно одно событие: syscall-ось его больше не производит).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.9 (регрессия): chmod с разрешённым путём + №243 ---"
if [ "$W622_INSTRUMENTED" -eq 1 ]; then
    _w622_hook_ok=$(_w622_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="ok"/ {s+=$NF} END{printf "%d", s+0}')
    _w622_hook_err=$(_w622_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="(error|missing)"/ {s+=$NF} END{printf "%d", s+0}')
    echo "  привязка chmod-хуков: ok=$_w622_hook_ok, error+missing=$_w622_hook_err"
    echo "  chmod без разрешённого пути (накопительно): $(_w622_metric_sum ebpf_guard_file_chmod_unresolved_total "" 2>/dev/null)"

    # №243, вторая половина: syscall-события за серию chmod. До правки каждый
    # chmod давал ВТОРОЕ событие на syscall-оси, которое никто не читает.
    _w622_sysc_m0=$(_w622_metrics > "$W622_ART/metrics-chmod-0.txt"; awk '/^ebpf_guard_events_total\{.*type="syscall"/{s+=$NF} END{printf "%d", s+0}' "$W622_ART/metrics-chmod-0.txt")
    _w622_t9=$(_w622_epoch)
    mkdir -p /tmp/w622-chmod 2>/dev/null
    : > /tmp/w622-chmod/payload 2>/dev/null
    chmod 0755 /tmp/w622-chmod/payload 2>/dev/null
    _w622_m1=$(stat -c '%a' /tmp/w622-chmod/payload 2>/dev/null)
    cp /bin/cat /usr/local/bin/w622-chmod-bin 2>/dev/null
    chmod 0755 /usr/local/bin/w622-chmod-bin 2>/dev/null
    _w622_m2=$(stat -c '%a' /usr/local/bin/w622-chmod-bin 2>/dev/null)
    # Серия из 50 chmod по одному пути: на syscall-оси это дало бы +50 событий.
    for _i in $(seq 1 50); do chmod 0644 /tmp/w622-chmod/payload 2>/dev/null; chmod 0755 /tmp/w622-chmod/payload 2>/dev/null; done
    echo "  сторож результата: права /tmp/w622-chmod/payload = ${_w622_m1:-НЕ ПРОЧИТАНЫ}, /usr/local/bin/w622-chmod-bin = ${_w622_m2:-НЕ ПРОЧИТАНЫ}"

    _w622_c9=0; _w622_w9=0
    while [ "$_w622_w9" -lt "$W622_POS_TIMEOUT" ]; do
        sleep "$W622_SETTLE"; _w622_w9=$(( _w622_w9 + W622_SETTLE ))
        _w622_c9=$(_w622_alerts | jq --argjson t "$_w622_t9" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))]|length' 2>/dev/null || echo 0)
        [ "${_w622_c9:-0}" -gt 1 ] && break
    done
    _w622_r9=$(_w622_alerts | jq -r --argjson t "$_w622_t9" \
        '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    _w622_metrics > "$W622_ART/metrics-chmod-1.txt"
    _w622_sysc_m1=$(awk '/^ebpf_guard_events_total\{.*type="syscall"/{s+=$NF} END{printf "%d", s+0}' "$W622_ART/metrics-chmod-1.txt")
    echo "  алертов о смене прав после подачи: $_w622_c9 (правила: ${_w622_r9:-нет})"
    echo "  №243, наблюдение: syscall-событий за серию из 100 chmod: $(( _w622_sysc_m1 - _w622_sysc_m0 )) (при chmod на syscall-оси было бы ≥ 100; фон ноды сюда тоже входит, поэтому это наблюдение, а вердикт №243 выносит monitored_syscalls в преflight'е)"

    if [ -z "${_w622_m1:-}" ] || [ -z "${_w622_m2:-}" ]; then
        die "6.2.1.9 НЕИЗМЕРИМ: сторож результата не прочитал права после chmod — подача не состоялась, ноль правил приборный"
    elif [ "$_w622_hook_ok" -eq 0 ]; then
        die "6.2.1.9 ПРОВАЛЕН (приборный ноль): ни один chmod-хук не привязан (ok=0, error+missing=$_w622_hook_err) — три правила о смене прав НЕ МОГУТ сработать"
    elif ! printf '%s' "$_w622_r9" | grep -q 'sigma_chmod_executable_tmp'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod +x в /tmp состоялся (права $_w622_m1), а sigma_chmod_executable_tmp не поднялся — тихая смерть правила"
    elif ! printf '%s' "$_w622_r9" | grep -q 'evasion_chmod_sensitive'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod системного бинаря состоялся (права $_w622_m2), а evasion_chmod_sensitive не поднялся"
    else
        pass "6.2.1.9 ДОСТИГНУТО: смена прав видна с разрешённым путём, и каждое из двух мест подняло СВОЁ правило (${_w622_r9})"
    fi
    rm -rf /tmp/w622-chmod /usr/local/bin/w622-chmod-bin 2>/dev/null
else
    echo "  ПРОПУЩЕН: 6.2.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.6 ПРАВИЛО СОВПАДАЕТ НЕ ШИРЕ СВОЕГО ИМЕНИ (№231, №234 + sigma_iptables_flush).
#
# Критерий требует ОБЕ половины по каждому из трёх правил. Половины разнесены
# по способу проверки честно, а не по удобству:
#   * ЮНИТ — обязательная часть критерия («юнит, а не прогон»): он покрывает
#     и те половины, которые на живом стенде подать нельзя без вреда
#     (настоящий `iptables -F` на ноде k3s снёс бы её сеть — это не контроль,
#     а авария);
#   * ЖИВАЯ ЧАСТЬ — то, что подать можно: молчание фона (напечатано выше по
#     окну), инъекция периодического бикона, чтение и запись /var/log,
#     подделка строки iptables без самого flush.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.6 (половина 2/2): юнит + инъекции ---"
_w622_unit_out="$W622_ART/unit-6.2.2.6.txt"
if [ -x "$W622_GO" ] && [ -d "$W622_REPO/internal/correlator" ]; then
    ( cd "$W622_REPO" && "$W622_GO" test -count=1 -run 'Wave6_2_2|Wave6_2_1' ./internal/correlator/... ) > "$_w622_unit_out" 2>&1
    _w622_unit_rc=$?
    tail -5 "$_w622_unit_out" | sed 's/^/    /'
    if [ "$_w622_unit_rc" -eq 0 ]; then
        pass "6.2.2.6 ДОСТИГНУТО (половина «юнит»): обе половины трёх правок условий зелены (см. $_w622_unit_out)"
    else
        die "6.2.2.6 ПРОВАЛЕН (половина «юнит»): go test -run 'Wave6_2_2|Wave6_2_1' ./internal/correlator/... вернул $_w622_unit_rc — правки условий не держат ни фон, ни свой сценарий (см. $_w622_unit_out)"
    fi
else
    die "6.2.2.6 НЕИЗМЕРИМ (половина «юнит»): нет $W622_GO или дерева $W622_REPO/internal/correlator — юнит-половину критерия нечем взять"
fi

# Инъекция 1: периодический бикон. Одна и та же тройка (pid, daddr, dport),
# ≥3 соединения с ровным кадансом внутри 5 минут — ровно то, чего требует
# новое условие (conn_periodic_count_5m gt 2, conn_periodic_cv_5m lt 0.35).
# comm НЕ должен быть в списке исключений правила (curl/wget/... там есть),
# поэтому берётся копия оболочки с собственным именем.
# Алерт правила — severity=info, в стор он НЕ ПОПАДАЕТ (ровно причина, по
# которой сужение №220 по стору его не видело): читается ПО МЕТРИКЕ.
echo "  инъекция «периодический бикон» (одна тройка pid+addr+port, ровный каданс):"
_w622_beacon_before=$(( $(_w622_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w622_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w622_ratelimited "c2_periodic_beacon_pattern beacon_fixed_interval") ))
cp /bin/bash /usr/local/bin/w622beacon 2>/dev/null
# setsid уводит нагрузку из дерева самого контроля: исключение наблюдателя
# (5.9a) режет в ЯДРЕ и ослепило бы контроль (память
# observer-exclusion-blinds-controls) — ноль тогда был бы приборным.
setsid /usr/local/bin/w622beacon -c 'for i in 1 2 3 4 5; do exec 9<>/dev/tcp/127.0.0.1/19090 2>/dev/null; exec 9>&-; sleep 6; done' >/dev/null 2>&1
sleep "$W622_SETTLE"
_w622_beacon_after=$(( $(_w622_metric_sum ebpf_guard_alerts_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w622_metric_sum ebpf_guard_alerts_filtered_total "c2_periodic_beacon_pattern beacon_fixed_interval") + $(_w622_ratelimited "c2_periodic_beacon_pattern beacon_fixed_interval") ))
rm -f /usr/local/bin/w622beacon 2>/dev/null
echo "    срабатываний бикон-правил за инъекцию (по метрике, включая info): $(( _w622_beacon_after - _w622_beacon_before ))"
if [ "$(( _w622_beacon_after - _w622_beacon_before ))" -lt 1 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», инъекция бикона): пять соединений на один адрес:порт с кадансом 6с не подняли ни c2_periodic_beacon_pattern, ни beacon_fixed_interval. Порог периодичности (count>2, cv<0.35, окно 5 мин) выбран инженерной оценкой и живым трафиком до сих пор не проверялся (открытый вопрос 2) — этот ноль и есть его проверка"
else
    pass "6.2.2.6 ДОСТИГНУТО (половина «своё правило поднимается»): инъекция периодического бикона поднята правилом $(( _w622_beacon_after - _w622_beacon_before )) раз — порог периодичности подтверждён живым трафиком (открытый вопрос 2)"
fi

# Инъекция 2: sigma_log_deletion — обе половины (№234). Чтение /var/log
# молчит, запись поднимает.
echo "  инъекция «чтение против записи /var/log» (№234):"
_w622_ld_t=$(_w622_epoch)
journalctl -u "$W622_SVC" --since "-1 min" --no-pager >/dev/null 2>&1
sleep "$W622_SETTLE"
_w622_ld_read=$(_w622_alerts | jq --argjson t "$_w622_ld_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_log_deletion") and (.comm=="journalctl"))]|length' 2>/dev/null || echo 0)
_w622_lw_t=$(_w622_epoch)
setsid /bin/sh -c 'echo w622-log-probe >> /var/log/w622-probe.log' >/dev/null 2>&1
sleep "$W622_SETTLE"
_w622_ld_write=$(_w622_alerts | jq --argjson t "$_w622_lw_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_log_deletion"))]|length' 2>/dev/null || echo 0)
rm -f /var/log/w622-probe.log 2>/dev/null
echo "    journalctl читает /var/log/journal → алертов sigma_log_deletion: $_w622_ld_read (обязан быть 0)"
echo "    запись в /var/log/w622-probe.log   → алертов sigma_log_deletion: $_w622_ld_write (обязан быть ≥ 1)"
if [ "${_w622_ld_read:-0}" -gt 0 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «фон молчит», №234): journalctl, ЧИТАЮЩИЙ /var/log/journal, поднял sigma_log_deletion $_w622_ld_read раз — правило по-прежнему совпадает шире своего имени"
elif [ "${_w622_ld_write:-0}" -lt 1 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «своё правило поднимается», №234): запись в /var/log не подняла sigma_log_deletion — сужение до op=write превратилось в немоту"
else
    pass "6.2.2.6 ДОСТИГНУТО (обе половины №234): чтение молчит ($_w622_ld_read), запись поднимает ($_w622_ld_write)"
fi

# Инъекция 3: sigma_iptables_flush — только НЕГАТИВНАЯ половина живьём.
# Позитивная (настоящий `iptables -F`) на ноде k3s снесла бы её сеть; она
# закрыта юнитом выше и подаваться на живой ноде НЕ ДОЛЖНА.
echo "  инъекция «строка iptables без flush» (№234-сосед, sigma_iptables_flush):"
_w622_ipt_t=$(_w622_epoch)
setsid /bin/sh -c 'grep iptables /etc/hosts; tar -F /tmp/w622-nope.txt' >/dev/null 2>&1
sleep "$W622_SETTLE"
_w622_ipt=$(_w622_alerts | jq --argjson t "$_w622_ipt_t" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id=="sigma_iptables_flush"))]|length' 2>/dev/null || echo 0)
echo "    подделка «grep iptables …; tar -F …» → алертов sigma_iptables_flush: $_w622_ipt (обязан быть 0)"
echo "    позитивная половина (настоящий iptables -F) живьём НЕ подаётся: на ноде k3s это авария, а не контроль — она закрыта юнитом выше"
if [ "${_w622_ipt:-0}" -gt 0 ]; then
    die "6.2.2.6 ПРОВАЛЕН (половина «фон молчит», sigma_iptables_flush): строка, где iptables и -F принадлежат РАЗНЫМ командам, подняла правило $_w622_ipt раз — класс [^;|&] границу команды не удержал"
else
    pass "6.2.2.6 ДОСТИГНУТО (половина «фон молчит», sigma_iptables_flush): подделка через границу команды правило не подняла"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.9 ИНЦИДЕНТНЫЙ СЛОЙ ЗА ПРОГОН ЦЕЛИКОМ (№235).
# Не «величина без порога», как в 6.2.1.5: теперь вердикт. Штатная работа
# ноды (старт пода, настройка сети) и работа измерителя не имеют права
# называться подтверждённой атакой.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.9: инцидентный слой не называет атакой штатную работу ноды ---"
_w622_alerts > "$W622_ART/alerts-incidents.json"
_w622_inc_all=$(jq '[.[]|select(.rule_id=="incident_confirmed_attack")]|length' "$W622_ART/alerts-incidents.json" 2>/dev/null || echo 0)
echo "  incident_confirmed_attack за прогон: $_w622_inc_all"
echo "  по корневому comm:"
jq -r '[.[]|select(.rule_id=="incident_confirmed_attack")]|group_by(.details.root_comm // .comm)|map({c:(.[0].details.root_comm // .[0].comm),n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W622_ART/alerts-incidents.json" 2>/dev/null | head -15
_w622_inc_bad=$(jq --arg instr "$W622_INSTR_COMMS_FLAT" '
    [ .[] | select(.rule_id=="incident_confirmed_attack")
      | select(((.details.root_comm // .comm) as $c
                | ($c=="runc:[2:INIT]" or $c=="runc:[1:CHILD]" or $c=="runc:[0:PARENT]" or $c=="flannel"
                   or (($instr|split(" "))|index($c)) != null))) ] | length' "$W622_ART/alerts-incidents.json" 2>/dev/null || echo 0)
_w622_inc_names=$(jq -r --arg instr "$W622_INSTR_COMMS_FLAT" '
    [ .[] | select(.rule_id=="incident_confirmed_attack")
      | select(((.details.root_comm // .comm) as $c
                | ($c=="runc:[2:INIT]" or $c=="runc:[1:CHILD]" or $c=="runc:[0:PARENT]" or $c=="flannel"
                   or (($instr|split(" "))|index($c)) != null)))
      | (.details.root_comm // .comm) ] | unique | join(" ")' "$W622_ART/alerts-incidents.json" 2>/dev/null)
echo "  из них от runc/flannel/comm измерителя: $_w622_inc_bad (${_w622_inc_names:-нет})"
if [ "${_w622_inc_bad:-0}" -gt 0 ]; then
    die "6.2.2.9 ПРОВАЛЕН: инцидентный слой назвал подтверждённой атакой штатную работу ноды или работу самого измерителя — $_w622_inc_bad инцидентов от ${_w622_inc_names}. Порог слою назначается ПОСЛЕ того, как ложь убрана, а не вместо этого (находка №235)"
else
    pass "6.2.2.9 ДОСТИГНУТО: ни один incident_confirmed_attack за прогон не имеет корнем runc/flannel/comm измерителя (всего инцидентов-атак за прогон: $_w622_inc_all)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2.7 ПОЗИТИВНЫЙ ПОДКОНТРОЛЬ ЗАМОРОЗКИ (№237, открытый вопрос 11).
#
# ПОЧЕМУ САМЫМ ПОСЛЕДНИМ. Подконтроль ВРЕМЕННО понижает
# max_signatures_per_workload и перезапускает агент: это обнуляет счётчики
# метрик и базу дрейфа. Любой контроль, стоящий после него, мерил бы уже
# другой агент. Конфиг восстанавливается и агент перезапускается обратно
# ВСЕГДА — в том числе если подконтроль провалится (trap).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2.7 (вердикт): заморозка доказывается приращением счётчика ---"
_w622_cfg_bak="$W622_ART/config-test.yaml.orig"
_w622_restore_cfg() {
    if [ -f "$_w622_cfg_bak" ]; then
        cp "$_w622_cfg_bak" "$_w622_cfg" 2>/dev/null
        systemctl restart "$W622_SVC" 2>/dev/null
        echo "  конфиг стенда восстановлен из $_w622_cfg_bak, агент перезапущен"
    fi
    rm -rf /root/w622-sig 2>/dev/null
    rm -f /usr/local/bin/w622sig 2>/dev/null
}
trap '_w622_restore_cfg' EXIT

if ! grep -qE '^\s*max_signatures_per_workload:' "$_w622_cfg" 2>/dev/null; then
    die "6.2.2.7 НЕИЗМЕРИМ: в $_w622_cfg нет ключа max_signatures_per_workload — понизить его нечем, и дельта 0 останется неотличима от «счётчик сломан» (находка №237)"
else
    cp "$_w622_cfg" "$_w622_cfg_bak" 2>/dev/null
    sed -i 's/^\(\s*\)max_signatures_per_workload:.*/\1max_signatures_per_workload: 3/' "$_w622_cfg"
    echo "  max_signatures_per_workload временно понижен до 3 (было ${_w622_maxsig:-?}), рестарт агента"
    systemctl restart "$W622_SVC" 2>/dev/null
    sleep "$W622_SETTLE"
    _w622_capA=$(_w622_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "")
    # Нагрузка: один comm (=один WorkloadKey) открывает ДЕСЯТКИ РАЗНЫХ путей
    # под /root/ — каждый путь есть отдельная сигнатура drift_new_file_dir_sensitive
    # (normalizeDriftPath сохраняет путь целиком, схлопывая лишь числовые
    # сегменты). setsid — по той же причине, что у инъекции бикона.
    mkdir -p /root/w622-sig 2>/dev/null
    for _i in $(seq 1 40); do echo "s$_i" > "/root/w622-sig/f$_i" 2>/dev/null; done
    cp /bin/cat /usr/local/bin/w622sig 2>/dev/null
    _w622_sig_read=0
    for _i in $(seq 1 40); do
        _w622_sig_read=$(( _w622_sig_read + $(setsid /usr/local/bin/w622sig "/root/w622-sig/f$_i" 2>/dev/null | wc -c) ))
    done
    sleep "$W622_SETTLE"
    _w622_capB=$(_w622_metric_sum ebpf_guard_drift_baseline_signature_cap_reached_total "")
    _w622_capD=$(( _w622_capB - _w622_capA ))
    _w622_frozen_now=$(_w622_metric_sum ebpf_guard_drift_baseline_frozen_workloads "")
    echo "  сторож результата: прочитано байт нагрузкой = $_w622_sig_read (40 разных путей под /root/, один comm=w622sig)"
    echo "  приращение signature_cap_reached_total на подконтроле: $_w622_capD (было $_w622_capA, стало $_w622_capB); замороженных нагрузок сейчас: $_w622_frozen_now"
    if [ "${_w622_sig_read:-0}" -lt 1 ]; then
        die "6.2.2.7 НЕИЗМЕРИМ: нагрузка не прочитала ни байта — ноль приращения приборный, а не вердикт (память positive-control-needs-result-sentinel)"
    elif [ "$_w622_capD" -gt 0 ]; then
        pass "6.2.2.7 ДОСТИГНУТО: при max_signatures_per_workload=3 счётчик заморозки вырос на $_w622_capD — приращение ДОКАЗАНО, а не выведено из наличия имени метрики в выдаче (находка №237)"
    else
        die "6.2.2.7 ПРОВАЛЕН: нагрузка завела 40 различных сигнатур на ОДНУ нагрузку при потолке 3, а signature_cap_reached_total не вырос ни разу. Два возможных объяснения, и оба — находка: счётчик не движется, либо дерево нагрузки срезано в ядре исключением наблюдателя 5.9a (память observer-exclusion-blinds-controls) — тогда ноль приборный и контроль требует носителя вне дерева измерителя"
    fi
fi
_w622_restore_cfg
trap - EXIT

echo "--- уборка ---"
"$W622_KUBECTL" -n "$W622_NS" delete pod --all --ignore-not-found --wait=false >/dev/null 2>&1
rm -f /usr/local/bin/w622hostcat /usr/local/bin/w622sig /usr/local/bin/w622beacon 2>/dev/null
rm -rf /root/w622-sig /tmp/w622-bypass /tmp/w622-chmod 2>/dev/null

echo
echo "=== ИТОГ КОНТРОЛЕЙ ВОЛНЫ 6.2.2: проваленных $WAVE622_FAILS ==="
echo "артефакты: $W622_ART"
[ "$WAVE622_FAILS" -gt 0 ] && echo "вердикты: $W622_VERDICTS"
exit 0
