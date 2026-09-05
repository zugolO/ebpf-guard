#!/bin/bash
# wave6.2.1-controls.sh — контроли волны 6.2.1 (долг базового прогона 6.2).
#
# ПОЧЕМУ ЭТОТ ФАЙЛ, А НЕ ПРАВКА wave6.2-controls.sh. Базовый прогон 6.2
# (архив server-logs/collect-6.2, 04.09.2026) снят и разобран; его вердикты —
# история и переписыванию не подлежат. Волна 6.2.1 меряет ДРУГОЕ: она
# проверяет, что девять находок №220…№228 починены, и три из них — дефекты
# самого измерителя, из-за которых прошлый прогон напечатал приборные нули.
#
# ЧТО ИСПРАВЛЕНО ПО СРАВНЕНИЮ С 6.2 (каждая строка — цена, снятая по архиву):
#   №226  Сравнение времени. `date -u +%FT%TZ` усекает до секунды, а jq
#         сравнивает СТРОКАМИ: "…T03:14:02.392685873Z" > "…T03:14:02Z" ложно,
#         потому что '.' (0x2E) < 'Z' (0x5A). Прошлый прогон потерял алерт
#         негативного контроля (напечатал «0 из 0» при фактическом 1) и семь
#         из десяти алертов позитивного. Здесь сравнение идёт через
#         fromdateiso8601 — числами, а не строками.
#   №227  Вердикт объёма берётся ПРЯМОЙ ДЕЛЬТОЙ двух метрик, как требует
#         критерий, а не сторовым счётом: прошлый прогон напечатал дельту
#         (2329 → 13 974/ч) и судил по другому числу (1738 → 10 428/ч),
#         потеряв alerts_filtered_total целиком.
#   №227  Негативная половина считается по ВСЕМ хостовым comm, а не по одному
#         контрольному: ноль на единице неотличим от приборного, ноль на
#         пяти тысячах — вердикт.
#   №222  Дельта потерь событий стала УСЛОВИЕМ ИЗМЕРИМОСТИ окна, и метрика
#         сверяется с журналом: «метрика молчит» и «метрика не успела» —
#         разные вещи, и прошлый прогон их не различил.
#   №221  Появился позитивный контроль, который СЕГОДНЯ ДАЁТ НОЛЬ: хостовое
#         чтение SA-токена пода обязано подниматься. Рядом печатается срез
#         лимитера этих правил — ноль при выбранном лимитере есть «детект
#         съеден шумом», а не «детекта нет», и это разные починки.
#   №223  Печатаются ОБА потолка базы дрейфа. max_workloads (1000) не
#         выбирается и близко, а упирается max_signatures (256) — молча.
#   №224  Инцидентный слой измеряется числом: гейт считает алерты и 1091
#         инцидент прошлого прогона не видит вовсе.
#   №225  Немота по среде (11 недостижимых syscall-правил, неподнявшийся
#         kmod-коллектор) печатается ДО прогона, чтобы реплей не считал её
#         потерей.
#
# ЗАПУСК. Скрипт не самостоятелен: нужен живой агент с kubernetes.enabled:true
# и готовая нода. Провал контроля НЕ убивает чужой прогон (волна 6.0m,
# память die-only-for-unmeasurable-run); die() здесь только считает и пишет
# вердикт.
#   W621_API      — база HTTP API агента (http://<host>:19090)
#   W621_TOKEN    — bearer-токен (формат файла токена — admin=<...>)
#   W621_KUBECTL  — путь к kubectl
#   W621_NS       — namespace контролей (по умолчанию w621)
#   W621_WINDOW   — длина тихого окна объёма, с (по умолчанию 600)
#   W621_GATE     — гейт волны 6, алертов/ч (по умолчанию 100)
set -u

VPS_IP="${VPS_IP:-localhost}"
W621_API="${W621_API:-http://${VPS_IP}:19090}"
W621_TOKEN="${W621_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W621_KUBECTL="${W621_KUBECTL:-/usr/local/bin/kubectl}"
W621_NS="${W621_NS:-w621}"
W621_WINDOW="${W621_WINDOW:-600}"
W621_GATE="${W621_GATE:-100}"
W621_SETUP="${W621_SETUP:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
W621_SETTLE="${W621_SETTLE:-20}"
W621_POS_TIMEOUT="${W621_POS_TIMEOUT:-120}"
W621_CHURN="${W621_CHURN:-3}"
W621_SVC="${W621_SVC:-ebpf-guard-test.service}"
W621_VERDICTS="${W621_VERDICTS:-/root/wave6.2.1-controls-verdicts.txt}"
W621_ART="${W621_ART:-/root/wave6.2.1-artifacts}"

WAVE621_FAILS=0
# Артефакты пишутся в КАТАЛОГ ЭТОГО ПРОГОНА и он очищается на старте
# (находка №228: в сборке 6.2 лежал alerts-window-start.json от репетиции
# сутками раньше — скрипт его не писал, а читающий получал мусор).
rm -rf "$W621_ART" 2>/dev/null || true
mkdir -p "$W621_ART" 2>/dev/null || true

die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE621_FAILS=$((WAVE621_FAILS + 1))
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '6\.2\.1\.[A-Z0-9]+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W621_VERDICTS" 2>/dev/null || true
    return 0
}
pass() { echo "OK: $*"; }

: > "$W621_VERDICTS" 2>/dev/null || true
echo "# wave6.2.1-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W621_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 6.2.1 (долг прогона 6.2) ==="

# Правила, для которых нода — единственный вход (те же, что в 6.2).
W621_K8S_RULES="cis_5_1_3_secret_access k8s_sa_token_read k8s_sa_token_projected_read k8s_hostpath_kubelet_access"
# Правила, которые ОБЯЗАНЫ подниматься на хостовом чтении токена пода: их
# условия совпадают с путём /var/lib/kubelet/pods/<uid>/…/token по букве.
W621_HOST_RULES="cis_5_1_3_secret_access k8s_hostpath_kubelet_access"
# Акторы ноды: их фон и есть «цена ноды». Сверяется с idle-actors.txt.
W621_NODE_ACTORS="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl flannel bridge loopback"

_w621_curl() { curl -s --max-time 30 -H "Authorization: Bearer $W621_TOKEN" "$@"; }
_w621_alerts() { _w621_curl "$W621_API/api/v1/alerts?limit=200000"; }
_w621_metrics() { _w621_curl "$W621_API/metrics"; }

# Сумма метрики. Прямая дельта двух срезов, а не строка таблицы: строка
# индексирована срезом лимитера (память f6b-table-indexed-by-limiter-cut).
_w621_metric_sum() { # $1=metric $2=список rule_id (пусто = все) [$3=файл среза]
    local metric="$1" ids="${2:-}" src="${3:-}"
    { [ -n "$src" ] && cat "$src" || _w621_metrics; } | awk -v m="$metric" -v ids="$ids" '
        BEGIN { n = split(ids, a, " ") }
        $0 ~ "^"m"[{ ]" {
            if (n == 0) { s += $NF; next }
            for (i = 1; i <= n; i++) if (index($0, "rule_id=\"" a[i] "\"")) { s += $NF; next }
        }
        END { printf "%d", s+0 }'
}
# Объём = экспортированные + срезанные min_severity. Ровно то, что предписано
# критерием; сторовый счёт сюда не подмешивается (№227).
_w621_volume() { echo "$(( $(_w621_metric_sum ebpf_guard_alerts_total "${1:-}" "${2:-}") + $(_w621_metric_sum ebpf_guard_alerts_filtered_total "${1:-}" "${2:-}") ))"; }
_w621_ratelimited() { _w621_metric_sum ebpf_guard_alerts_ratelimited_by_rule_total "${1:-}" "${2:-}"; }
# Потери событий БЕЗ path_denylist: denylist — законный фильтр, а не потеря
# видимости, и его +617 за окно прошлого прогона не должны маскировать ноль
# настоящих дропов (№222).
_w621_real_drops() { # [$1=файл среза]
    { [ -n "${1:-}" ] && cat "$1" || _w621_metrics; } | awk '
        /^ebpf_guard_events_dropped_total\{/ && !/reason="path_denylist"/ { s += $NF }
        /^ebpf_guard_event_queue_dropped_total/ { s += $NF }
        END { printf "%d", s+0 }'
}
# Журнальный счётчик потерь: сверяется с метрикой (№222, второй слой).
_w621_journal_drops() {
    journalctl -u "$W621_SVC" --no-pager 2>/dev/null \
        | grep -o '"bulk_dropped_since_start":[0-9]*' | tail -1 | cut -d: -f2
}
# Отсечка по времени — ЧИСЛОМ, а не строкой (№226).
# Отсечка по времени — ЧИСЛОМ, а не строкой (находка №226). Две тонкости, обе
# стоили величин на прогоне 6.2:
#   1) jq fromdateiso8601 НЕ принимает дробные секунды: "…T03:14:02.392Z"
#      даёт ошибку, и `// 0` превратил бы КАЖДЫЙ алерт в 0. Дробь срезается.
#   2) срез усекает вниз, поэтому нижняя граница берётся ВКЛЮЧИТЕЛЬНО (>=):
#      иначе алерт своей же секунды выпадает снова — ровно тот дефект, из-за
#      которого 6.2.2 напечатал «0 из 0» при фактическом 1. Цена включения —
#      до 1 с чужого фона на границе окна в 600 с; цена исключения — потеря
#      собственного алерта контроля.
_w621_epoch() { date -u +%s; }

# ─────────────────────────────────────────────────────────────────────────────
# ПРЕFLIGHT. Провал здесь означает, что величины ниже нечем читать.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1 преflight ---"
command -v jq >/dev/null 2>&1 || die "6.2.1 преflight ПРОВАЛЕН: нет jq — все величины по стору неизмеримы"

if [ ! -x "$W621_KUBECTL" ]; then
    die "6.2.1 преflight ПРОВАЛЕН: kubectl не найден ($W621_KUBECTL) — ноду нечем подать на вход, любой ноль ниже приборный"
else
    _w621_ready=$("$W621_KUBECTL" get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{n++} END{print n+0}')
    if [ "${_w621_ready:-0}" -lt 1 ]; then
        die "6.2.1 преflight ПРОВАЛЕН: ни одна нода не Ready"
    else
        pass "6.2.1 преflight: нод Ready = $_w621_ready ($("$W621_KUBECTL" version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // "?"'))"
    fi
fi

_w621_cfg="${W621_CONFIG:-$W621_SETUP/config-test.yaml}"
# Блок читается целиком, а не окном grep -A6 (находка №216: комментарий внутри
# блока вырос, и сторож печатал «НЕ true» при true).
_w621_k8s_block=$(awk '/^kubernetes:/{f=1;next} f && /^[a-zA-Z#]/{exit} f' "$_w621_cfg" 2>/dev/null)
_w621_drift_cfg=$(awk '/drift_baseline:/{f=1;next} f && /^[a-zA-Z]/{exit} f' "$_w621_cfg" 2>/dev/null)
echo "$_w621_k8s_block" | grep -qE '^\s*enabled:\s*true\s*$' \
    && pass "6.2.1 преflight: kubernetes.enabled: true в $_w621_cfg" \
    || die "6.2.1 преflight ПРОВАЛЕН: kubernetes.enabled НЕ true — энричер не конструируется (cmd/ebpf-guard/main.go:1835), pod_name пуст по построению (находка №216)"

_w621_src=$(journalctl -u "$W621_SVC" --no-pager 2>/dev/null | grep -o '"msg":"runtime enricher active","source":"[a-z]*"' | tail -1 | grep -oE '"source":"[a-z]*"' | cut -d'"' -f4)
_w621_k8s_up=$(journalctl -u "$W621_SVC" --no-pager 2>/dev/null | grep -c 'k8s enricher active')
echo "  источник runtime-обогащения: ${_w621_src:-НЕ НАПЕЧАТАН}; строк «k8s enricher active»: $_w621_k8s_up"
[ "${_w621_k8s_up:-0}" -ge 1 ] || die "6.2.1 преflight ПРОВАЛЕН: в журнале нет «k8s enricher active» — pod_name будет пуст по причине вне продукта"

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.6 РЕЕСТР НЕМОТЫ ПО СРЕДЕ (находка №225), ДО всякого замера.
# 11 syscall-правил недостижимы в allowlist ядра 5.15, kmod-коллектор не
# поднимается (cgroup_attach_task LSM hook not supported). Их отсутствие в
# реплеях — не регресс; это должно быть НАПЕЧАТАНО, а не выясняться заново.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.6: немота по среде (реестр до прогона) ---"
_w621_unreach=$(journalctl -u "$W621_SVC" --no-pager 2>/dev/null | grep -o '"msg":"rules: syscall rules with no reachable nr in the kernel allowlist".*' | tail -1)
_w621_unreach_n=$(printf '%s' "$_w621_unreach" | grep -oE '"count":[0-9]+' | cut -d: -f2)
_w621_unreach_ids=$(printf '%s' "$_w621_unreach" | grep -oE '"rule_ids":\[[^]]*\]' | tr -d '"[]' | sed 's/rule_ids://')
_w621_kmod=$(journalctl -u "$W621_SVC" --no-pager 2>/dev/null | grep -c 'cgroup escape collector unavailable')
echo "  недостижимых syscall-правил: ${_w621_unreach_n:-0}"
echo "  поимённо: ${_w621_unreach_ids:-нет}"
echo "  kmod cgroup-escape коллектор недоступен: $([ "${_w621_kmod:-0}" -gt 0 ] && echo да || echo нет) (ядро $(uname -r))"

# Сверка с реестром (silent-rules.txt, категория «а»), а не просто печать
# журнала: без сверки «печатает их числом» превращается в число, которое
# никто не проверяет против записанного, и реестр может отстать от стенда
# незамеченным (собственно суть находки №225).
_w621_registry="$W621_SETUP/attacks/silent-rules.txt"
_w621_reg_ids=$(grep -oE '^[A-Za-z0-9_]+ a$' "$_w621_registry" 2>/dev/null | awk '{print $1}' | sort -u)
_w621_reg_n=$(printf '%s\n' "$_w621_reg_ids" | grep -c .)
_w621_jrn_ids=$(printf '%s' "${_w621_unreach_ids:-}" | tr ',' '\n' | sed '/^$/d' | sort -u)
echo "  реестр (silent-rules.txt, категория а): ${_w621_reg_n} правил"
if [ -z "${_w621_unreach_n:-}" ]; then
    die "6.2.1.6 НЕИЗМЕРИМ: строки о недостижимых правилах нет в журнале — немоту по среде нечем отличить от регресса, и реплей этого прогона будет читать её потерей"
elif [ "$_w621_jrn_ids" != "$_w621_reg_ids" ]; then
    die "6.2.1.6 ПРОВАЛЕН: реестр (${_w621_reg_n} правил) разошёлся со стендом (${_w621_unreach_n} правил: ${_w621_unreach_ids:-нет}) — реестр отстал от стенда, реплеи архивов этой волны читают расхождение как потерю/регресс, пока plan.md и silent-rules.txt не приведены к списку стенда"
elif [ "${_w621_kmod:-0}" -gt 0 ] && ! grep -q 'cgroup escape collector unavailable' "$_w621_registry" 2>/dev/null; then
    die "6.2.1.6 ПРОВАЛЕН: kmod cgroup-escape коллектор недоступен на этом ядре, но $_w621_registry не документирует этот факт — немота по среде не зарегистрирована"
else
    pass "6.2.1.6 ДОСТИГНУТО: реестр немоты по среде совпал со стендом (${_w621_unreach_n} правил + kmod), сверка пройдена"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.0 ПРИБОРНОСТЬ + СТОРОЖ ПОТЕРЬ (находка №222).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.0: приборность оси пода ---"
_w621_alerts > "$W621_ART/alerts-preflight.json"
_w621_pod_alerts=$(jq '[.[]|select(((.enrichment.pod_name // "") != "") and ((.enrichment.namespace // "") != ""))]|length' "$W621_ART/alerts-preflight.json" 2>/dev/null || echo 0)
_w621_ns_seen=$(jq -r '.[]|select((.enrichment.namespace // "")!="")|.enrichment.namespace' "$W621_ART/alerts-preflight.json" 2>/dev/null | sort -u | tr '\n' ' ')
echo "  алертов с непустыми namespace И pod_name: $_w621_pod_alerts; namespace'ы: ${_w621_ns_seen:-нет}"
W621_INSTRUMENTED=0
if [ "${_w621_pod_alerts:-0}" -lt 1 ]; then
    die "6.2.1.0 ПРОВАЛЕН: ни одного алерта с личностью пода. Дальше 6.2.1.2/6.2.1.3 НЕ ЧИТАЮТСЯ — их ноль был бы приборным"
else
    W621_INSTRUMENTED=1
    pass "6.2.1.0 ДОСТИГНУТО (половина «ось пода»): личность пода доезжает до алерта ($_w621_pod_alerts алертов)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.A ДЛИНА ПРОЛОГА (пункт А, без изменений относительно 6.2).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.A: длина пролога до открытия окна ---"
_w621_lp=$(echo "$_w621_drift_cfg" | grep -oE 'learning_period:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w621_edp=$(echo "$_w621_drift_cfg" | grep -oE 'enforce_deadline_periods:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w621_need=$(( ${_w621_lp:-600} * ${_w621_edp:-2} ))
_w621_started=$(systemctl show "$W621_SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
_w621_started_s=$(date -d "$_w621_started" +%s 2>/dev/null || echo 0)
_w621_prologue=$(( $(date +%s) - _w621_started_s ))
echo "  агент поднят: ${_w621_started:-?}; пролог: ${_w621_prologue}s; требуется > ${_w621_need}s"
echo "  на этот момент: профилей $(_w621_metric_sum ebpf_guard_drift_baseline_profiles ""), из них в learning $(_w621_metric_sum ebpf_guard_drift_baseline_learning_workloads "")"
if [ "$_w621_started_s" -eq 0 ]; then
    die "6.2.1.A НЕИЗМЕРИМ: время старта сервиса не прочитано"
elif [ "$_w621_prologue" -le "$_w621_need" ]; then
    die "6.2.1.A ПРОВАЛЕН: пролог ${_w621_prologue}s не длиннее ${_w621_need}s — окно ниже меряет ОБУЧЕНИЕ, а не линию"
else
    pass "6.2.1.A ДОСТИГНУТО: пролог ${_w621_prologue}s > ${_w621_need}s"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.1 ЦЕНА НОДЫ + 6.2.1.4 ПОТОЛКИ ДРЕЙФА. Вход НЕ подаётся (окно тихое).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.1/6.2.1.4: тихое окно ${W621_WINDOW}s ---"
_w621_drift_print() {
    echo "  дрейф[$1]: $(cat "$2" | awk '/^ebpf_guard_drift_baseline_(profiles|learning_workloads|stuck_learning_workloads|learning_overdue_workloads|saturated_profiles|evictions_total|frozen_workloads|signature_cap_reached_total) /{printf "%s=%s ", $1, $2}')"
}
# ТИШИНА ПЕРЕД ОТКРЫТИЕМ (04.09.2026, разбор архива 6.2 перед прогоном).
# Инструмент сам попадает в измеряемый объём: в окне 6.2 лежат ДЕСЯТЬ алертов
# sensitive_file_read от comm=curl, девять из них — ровно в секунду открытия
# окна (03:03:17), то есть это curl'ы преflight'а этого же скрипта, читающие
# /etc/passwd через NSS на каждом запуске. Десять — это ещё и потолок лимитера
# (10/60 с), так что настоящее число было больше. При гейте 100/ч эти 10
# алертов за окно = 60/ч, то есть больше половины бюджета критерия тратит
# измеритель. Пауза длиннее окна лимитера уводит преflight-шум ЗА границу t0;
# доля инструмента внутри окна печатается ниже отдельной строкой, чтобы
# остаток был виден, а не подразумевался.
W621_QUIET_LEAD="${W621_QUIET_LEAD:-70}"
echo "  тишина перед открытием окна: ${W621_QUIET_LEAD}s (шум собственных curl'ов преflight'а уходит за границу t0)"
sleep "$W621_QUIET_LEAD"
_w621_t0=$(_w621_epoch)
_w621_metrics > "$W621_ART/metrics-window-start.txt"
_w621_jdrops0=$(_w621_journal_drops)
_w621_drift_print "открытие" "$W621_ART/metrics-window-start.txt"
echo "  окно открыто $(date -u -d "@$_w621_t0" +%FT%TZ) — до закрытия НЕ ПОДАВАТЬ вход (память ebpf-guard-measurement-hygiene, п.2/п.5)"
sleep "$W621_WINDOW"
_w621_t1=$(_w621_epoch)
_w621_metrics > "$W621_ART/metrics-window-end.txt"
_w621_jdrops1=$(_w621_journal_drops)
_w621_drift_print "закрытие" "$W621_ART/metrics-window-end.txt"
_w621_alerts > "$W621_ART/alerts-window-end.json"

# ---- 6.2.1.0, вторая половина: потери событий за окно (№222) ----
_w621_dr0=$(_w621_real_drops "$W621_ART/metrics-window-start.txt")
_w621_dr1=$(_w621_real_drops "$W621_ART/metrics-window-end.txt")
_w621_dr=$(( _w621_dr1 - _w621_dr0 ))
_w621_jdr=$(( ${_w621_jdrops1:-0} - ${_w621_jdrops0:-0} ))
echo "  потери событий за окно: метрика (без path_denylist) = $_w621_dr; журнал bulk_dropped = $_w621_jdr"
if [ "$_w621_dr" -gt 0 ] || [ "$_w621_jdr" -gt 0 ]; then
    die "6.2.1.0 ПРОВАЛЕН (половина «потери»): за окно потеряно событий — метрика $_w621_dr, журнал $_w621_jdr. Величина 6.2.1.1 ниже срезана ПОТЕРЕЙ, а не только лимитером, и любой ноль контроля в эти секунды может быть потерей, а не вердиктом (находка №222). Окно НЕИЗМЕРИМО"
elif [ "$_w621_jdr" -eq 0 ] && [ "$_w621_dr" -eq 0 ]; then
    pass "6.2.1.0 ДОСТИГНУТО (половина «потери»): за окно ни метрика, ни журнал не показали потерь"
fi
# Сверка прибора с журналом: расхождение знаков означает, что потеря
# видимости молчалива В МЕТРИКАХ — находка класса №223, а не шум.
if { [ "$_w621_jdr" -gt 0 ] && [ "$_w621_dr" -eq 0 ]; } || { [ "$_w621_dr" -gt 0 ] && [ "$_w621_jdr" -eq 0 ]; }; then
    die "6.2.1.0 ПРОВАЛЕН (сверка прибора): журнал говорит $_w621_jdr потерь, метрика — $_w621_dr. Счётчик потерь не движется вместе с журналом: потеря видимости молчалива в метриках (второй слой находки №222)"
fi

# ---- 6.2.1.1: объём ПРЯМОЙ ДЕЛЬТОЙ ДВУХ МЕТРИК (№227) ----
_w621_vol0=$(_w621_volume "" "$W621_ART/metrics-window-start.txt")
_w621_vol1=$(_w621_volume "" "$W621_ART/metrics-window-end.txt")
_w621_rl0=$(_w621_ratelimited "" "$W621_ART/metrics-window-start.txt")
_w621_rl1=$(_w621_ratelimited "" "$W621_ART/metrics-window-end.txt")
_w621_vol=$(( _w621_vol1 - _w621_vol0 ))
_w621_rl=$(( _w621_rl1 - _w621_rl0 ))
_w621_vol_hour=$(awk -v n="$_w621_vol" -v w="$W621_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}')
_w621_true_hour=$(awk -v n="$(( _w621_vol + _w621_rl ))" -v w="$W621_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}')
echo "  ПРЯМАЯ ДЕЛЬТА объёма (alerts_total + alerts_filtered_total): $_w621_vol → $_w621_vol_hour/ч   ← величина критерия"
echo "  срез лимитера за окно (alerts_ratelimited_by_rule_total): $_w621_rl"
echo "  нижняя оценка РЕАЛЬНОГО числа срабатываний: $(( _w621_vol + _w621_rl )) → $_w621_true_hour/ч"

# Поимённый разбор — вход для сужения. Сторовый счёт печатается СПРАВОЧНО и
# вердикта не выносит (№227): он отстаёт от метрики и не знает filtered.
_w621_new=$(jq --argjson t0 "$_w621_t0" --argjson t1 "$_w621_t1" --arg actors "$W621_NODE_ACTORS" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select(((.enrichment.namespace // "") != "") or ((.comm) as $c | ($actors|split(" "))|index($c))) ]
    ' "$W621_ART/alerts-window-end.json" 2>/dev/null)
echo "  (справочно, сторовый счёт нодовых алертов окна: $(echo "${_w621_new:-[]}" | jq 'length' 2>/dev/null) — вердикт по нему НЕ выносится, находка №227)"
echo "  разбивка по правилам:"
echo "${_w621_new:-[]}" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -30
echo "  разбивка по comm:"
echo "${_w621_new:-[]}" | jq -r 'group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' 2>/dev/null | head -15

# Доля ИЗМЕРИТЕЛЯ внутри окна. Считается по стору (метрика не знает comm) и
# вердикта не выносит — это поправка к чтению величины, а не сама величина:
# ноль здесь означает, что тишина перед открытием сработала, ненулевое —
# сколько из напечатанного объёма произвёл сам замер (curl/jq/bash скрипта).
_w621_instr=$(jq --argjson t0 "$_w621_t0" --argjson t1 "$_w621_t1" '
    [ .[] | select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t0) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) <= $t1))
      | select((.comm) as $c | (["curl","jq","bash","head","sed","awk","date","tr","sort","systemctl","journalctl"]|index($c))) ]
    | group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)' "$W621_ART/alerts-window-end.json" 2>/dev/null)
_w621_instr_n=$(echo "${_w621_instr:-[]}" | jq '[.[].n]|add // 0' 2>/dev/null)
echo "  доля ИЗМЕРИТЕЛЯ в окне (стор, поправка к чтению — не вердикт): ${_w621_instr_n:-0} алертов $(echo "${_w621_instr:-[]}" | jq -r 'map("\(.c):\(.n)")|join(" ")' 2>/dev/null)"

# Правила со срезом лимитера ЗА ОКНО — по разности двух снимков одной метрики.
_w621_rl_window() { # $1=rule_id
    awk -v r="$1" '
        FILENAME==ARGV[1] && index($0, "rule_id=\"" r "\"") && /^ebpf_guard_alerts_ratelimited_by_rule_total/ { a=$NF }
        FILENAME==ARGV[2] && index($0, "rule_id=\"" r "\"") && /^ebpf_guard_alerts_ratelimited_by_rule_total/ { b=$NF }
        END { printf "%d", (b+0)-(a+0) }' "$W621_ART/metrics-window-start.txt" "$W621_ART/metrics-window-end.txt"
}
_w621_capped=""
for _r in $(echo "${_w621_new:-[]}" | jq -r '.[].rule_id' 2>/dev/null | sort -u); do
    _d=$(_w621_rl_window "$_r")
    [ "${_d:-0}" -gt 0 ] && _w621_capped="$_w621_capped $_r(+$_d)"
done
echo "  правила со СРЕЗОМ лимитера ЗА ОКНО:${_w621_capped:- нет}"

# ПОРЯДОК ПРОВЕРОК. Срез может только ЗАНИЗИТЬ измеренное, поэтому превышение
# порога доказано и при срезе — снятие среза величину только увеличит.
# «Неизмеримо» остаётся для случая «порог не перешли, но прибор упёрт»: там
# ноль незнания настоящий (пункт Е «Переноса в 6.1…6.4»).
if [ "$_w621_vol_hour" -gt "$W621_GATE" ]; then
    die "6.2.1.1 ПРОВАЛЕН (величина — НИЖНЯЯ оценка): цена ноды $_w621_vol_hour алертов/ч прямой дельтой при гейте волны 6 «не выше ${W621_GATE}/ч»; с учётом среза лимитера реальное число срабатываний не менее $_w621_true_hour/ч. Правила со срезом:${_w621_capped:- нет}. Разбивка выше — вход для сужения, а не повод понизить порог"
elif [ -n "$_w621_capped" ]; then
    die "6.2.1.1 НЕИЗМЕРИМ ПО БУКВЕ: величина $_w621_vol_hour/ч порог не перешла, но у правил${_w621_capped} есть срез лимитера за окно — их вклад есть показание упёршегося прибора (10/60с), и «≤${W621_GATE}/ч» здесь показание, а не вердикт (пункт Е)"
else
    pass "6.2.1.1 ДОСТИГНУТО: цена ноды $_w621_vol_hour алертов/ч ≤ ${W621_GATE}/ч, ни одно правило не срезано лимитером за окно"
fi

# ---- 6.2.1.4: потолки базы дрейфа, ОБА (№223) ----
echo "--- 6.2.1.4: потолки базы дрейфа ---"
_w621_maxw=$(echo "$_w621_drift_cfg" | grep -oE 'max_workloads:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
# config-test.yaml ключ — max_signatures_per_workload, а не max_signatures:
# первая версия этого grep искала буквально "max_signatures:" и не находила
# ничего (пустой "?" в печати ниже при фактическом значении 256) — сама
# находка того же класса, что №223: сторож печатал незнание там, где было
# известное значение.
_w621_maxsig=$(echo "$_w621_drift_cfg" | grep -oE 'max_signatures_per_workload:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w621_prof=$(_w621_metric_sum ebpf_guard_drift_baseline_profiles "" "$W621_ART/metrics-window-end.txt")
_w621_evict=$(_w621_metric_sum ebpf_guard_drift_baseline_evictions_total "" "$W621_ART/metrics-window-end.txt")
_w621_frozen_j=$(journalctl -u "$W621_SVC" --no-pager 2>/dev/null | grep -c 'workload signature cap reached')
_w621_frozen_m=$(_w621_metrics | grep -cE '^ebpf_guard_drift_baseline_(frozen_workloads|signature_cap_reached_total)')
echo "  профилей=$_w621_prof при max_workloads=${_w621_maxw:-?}; вытеснений=$_w621_evict"
echo "  max_signatures=${_w621_maxsig:-?}; строк «signature cap reached» в журнале: $_w621_frozen_j; метрика заморозки в выдаче: $([ "${_w621_frozen_m:-0}" -gt 0 ] && echo есть || echo НЕТ)"
if [ "${_w621_frozen_j:-0}" -gt 0 ] && [ "${_w621_frozen_m:-0}" -eq 0 ]; then
    die "6.2.1.4 ПРОВАЛЕН: база дрейфа замораживалась по max_signatures (${_w621_frozen_j} раз в журнале), а метрики заморозки в выдаче НЕТ — заморозка молчалива, и сторож вытеснения смотрит на потолок max_workloads=${_w621_maxw:-?}, который при профилях=$_w621_prof не выбран и близко (находка №223)"
elif [ "${_w621_frozen_m:-0}" -eq 0 ]; then
    die "6.2.1.4 ПРОВАЛЕН: метрики заморозки по max_signatures нет в выдаче. Пока её нет, «база полна» и «база не встречала нагрузку» неотличимы, а ноль _evictions_total ничего не доказывает (находка №223)"
else
    pass "6.2.1.4 ДОСТИГНУТО: оба потолка печатаются числом, заморозка имеет счётчик; порог не назначается (запрет 5.9.6)"
fi

# ---- 6.2.1.5: инцидентный слой (№224) ----
echo "--- 6.2.1.5: величина инцидентного слоя (без порога) ---"
_w621_inc0=$(_w621_metric_sum ebpf_guard_incidents_total "" "$W621_ART/metrics-window-start.txt")
_w621_inc1=$(_w621_metric_sum ebpf_guard_incidents_total "" "$W621_ART/metrics-window-end.txt")
_w621_inc=$(( _w621_inc1 - _w621_inc0 ))
echo "  инцидентов за окно: $_w621_inc → $(awk -v n="$_w621_inc" -v w="$W621_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}')/ч"
echo "  по вердиктам (накопительно): $(grep -E '^ebpf_guard_incidents_total\{' "$W621_ART/metrics-window-end.txt" | sed 's/ebpf_guard_incidents_total//' | tr '\n' ' ')"
journalctl -u "$W621_SVC" --since "@$_w621_t0" --until "@$_w621_t1" --no-pager 2>/dev/null \
    | grep -o '{"time".*incident promoted.*}' > "$W621_ART/incidents-window.jsonl" || true
echo "  по root_comm:"
jq -rs 'group_by(.root_comm)|map({c:.[0].root_comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W621_ART/incidents-window.jsonl" 2>/dev/null | head -10
echo "  правила-доминанты (scoring_rule_ids):"
jq -rs '[.[].scoring_rule_ids//[]]|flatten|group_by(.)|map({r:.[0],n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' "$W621_ART/incidents-window.jsonl" 2>/dev/null | head -10
echo "  6.2.1.5: величина без порога (находка №224) — гейт считает алерты и этот слой не видит; порог назначает следующая волна"

# ─────────────────────────────────────────────────────────────────────────────
# ВХОД ПОДАЁТСЯ ЗДЕСЬ, ПОСЛЕ ОКНА. Иначе лимитер, выбранный контролем,
# показывает себя вместо фона (память control-after-attacks-hits-filled-limiter).
#
# 6.2.1.2 СТОРОЖ СЛЕПОТЫ ЛИМИТЕРА (находка №221) — контроль, который на
# прогоне 6.2 дал НОЛЬ. Хостовое чтение /var/lib/kubelet/pods/<uid>/…/token
# по букве правил обязано поднять cis_5_1_3_secret_access (префикс
# /var/lib/kubelet/pods/) и k8s_hostpath_kubelet_access (префикс
# /var/lib/kubelet/). На прогоне 6.2 не поднялось ни одно, а у второго
# лимитер был выбран фоном k3s-server (98 за окно при потолке 100, срез +41).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.2: сторож слепоты лимитера (хостовое чтение токена пода) ---"
if [ "$W621_INSTRUMENTED" -eq 1 ]; then
    _w621_target=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w621_target" ] && _w621_target=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w621_target" ]; then
        die "6.2.1.2 НЕИЗМЕРИМ: под /var/lib/kubelet/pods нет ни одного файла — хостовую половину нечем подать, ноль был бы приборным"
    else
        # Срез лимитера ДО чтения: ноль правила при выбранном лимитере — это
        # «детект съеден шумом», а не «детекта нет». Разные починки.
        _w621_hrl0=$(_w621_ratelimited "$W621_HOST_RULES")
        cp /bin/cat /usr/local/bin/w621hostcat 2>/dev/null
        _w621_tn=$(_w621_epoch)
        _w621_bytes=$(/usr/local/bin/w621hostcat "$_w621_target" 2>/dev/null | wc -c)
        _w621_hits=0; _w621_waited=0
        while [ "$_w621_waited" -lt "$W621_POS_TIMEOUT" ]; do
            sleep "$W621_SETTLE"; _w621_waited=$(( _w621_waited + W621_SETTLE ))
            _w621_hits=$(_w621_alerts | jq --argjson t "$_w621_tn" --arg ids "$W621_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w621hostcat") and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w621_hits:-0}" -gt 0 ] && break
        done
        _w621_hrl1=$(_w621_ratelimited "$W621_HOST_RULES")
        _w621_all=$(_w621_alerts | jq --argjson t "$_w621_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w621hostcat"))]|length' 2>/dev/null || echo 0)
        _w621_rules=$(_w621_alerts | jq -r --argjson t "$_w621_tn" '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w621hostcat"))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
        echo "  сторож результата: прочитано байт = $_w621_bytes (цель $_w621_target)"
        echo "  алертов от comm=w621hostcat: всего $_w621_all (правила: ${_w621_rules:-нет}); из них обязательных ($W621_HOST_RULES): $_w621_hits"
        echo "  срез лимитера обязательных правил за время контроля: $(( _w621_hrl1 - _w621_hrl0 ))"
        if [ "${_w621_bytes:-0}" -lt 1 ]; then
            die "6.2.1.2 НЕИЗМЕРИМ: хостовой читатель ничего не прочитал (байт=$_w621_bytes) — ноль приборный (память positive-control-needs-result-sentinel)"
        elif [ "${_w621_hits:-0}" -lt 1 ] && [ "$(( _w621_hrl1 - _w621_hrl0 ))" -gt 0 ]; then
            die "6.2.1.2 ПРОВАЛЕН (шум→слепота, находка №221 НЕ починена): хост прочитал токен пода ($_w621_bytes байт), обязательные правила ($W621_HOST_RULES) не поднялись, И их лимитер срезал $(( _w621_hrl1 - _w621_hrl0 )) срабатываний за то же время. Детект съеден собственным шумом ноды — чинится сужением 6.2.1.1, а не правилом"
        elif [ "${_w621_hits:-0}" -lt 1 ]; then
            die "6.2.1.2 ПРОВАЛЕН (детекта нет): хост прочитал токен пода ($_w621_bytes байт), обязательные правила ($W621_HOST_RULES) не поднялись, при этом лимитер их НЕ срезал. Это не шум — это условие правила не совпадает с путём, хотя по букве обязано"
        else
            pass "6.2.1.2 ДОСТИГНУТО: хостовое чтение токена пода подняло $_w621_hits обязательных алертов (${_w621_rules}) — находка №221 закрыта"
        fi
        # 6.2.1.3 считается на этих же данных: см. ниже.
        W621_HOSTCAT_PODDED=$(_w621_alerts | jq --argjson t "$_w621_tn" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="w621hostcat") and ((.enrichment.pod_name // "")!=""))]|length' 2>/dev/null || echo 0)
        rm -f /usr/local/bin/w621hostcat 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.1.0 не взят"
    W621_HOSTCAT_PODDED=0
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.3 НЕГАТИВНЫЙ КОНТРОЛЬ НА ПОЛНОМ ОБЪЁМЕ (находка №227).
# Прогон 6.2 считал эту величину по ОДНОМУ контрольному comm и получил
# «0 из 0» — ноль на единице неотличим от приборного. Здесь она считается по
# ВСЕМ comm разом: печатается таблица «comm → есть ли pod_name», и вердикт
# выносится по хостовой половине целиком.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.3: негативный контроль на полном объёме ---"
if [ "$W621_INSTRUMENTED" -eq 1 ]; then
    _w621_alerts > "$W621_ART/alerts-negative.json"
    echo "  comm, у которых ХОТЬ ОДИН алерт несёт pod_name (это обязаны быть только поды):"
    jq -r '[.[]|select((.enrichment.pod_name // "")!="")]|group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W621_ART/alerts-negative.json" 2>/dev/null | head -20
    echo "  comm БЕЗ pod_name (хостовая половина, top-10):"
    jq -r '[.[]|select((.enrichment.pod_name // "")=="")]|group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' "$W621_ART/alerts-negative.json" 2>/dev/null | head -10
    # Хостовые акторы — те, что заведомо не в подах. Сверка по cgroup даётся
    # полем container_id: у процесса вне пода оно пусто ИЛИ это голый cgroup-ID
    # хоста, и pod_name при этом обязан быть пуст в любом случае.
    _w621_bad=$(jq -r '[.[]|select(((.enrichment.pod_name // "")!="") and ((.enrichment.container_id // "")==""))]|length' "$W621_ART/alerts-negative.json" 2>/dev/null || echo 0)
    _w621_hostpodded=$(jq -r --arg h "k3s-server iptables ip6tables systemd sshd cron kubectl systemd-logind" \
        '[.[]|select(((.enrichment.pod_name // "")!="") and ((.comm) as $c|($h|split(" "))|index($c)))]|length' "$W621_ART/alerts-negative.json" 2>/dev/null || echo 0)
    echo "  алертов с pod_name БЕЗ container_id: $_w621_bad"
    echo "  алертов с pod_name у заведомо хостовых comm: $_w621_hostpodded"
    echo "  алертов с pod_name у контрольного хостового читателя: ${W621_HOSTCAT_PODDED:-0}"
    if [ "${_w621_hostpodded:-0}" -gt 0 ] || [ "${W621_HOSTCAT_PODDED:-0}" -gt 0 ] || [ "${_w621_bad:-0}" -gt 0 ]; then
        die "6.2.1.3 ПРОВАЛЕН: хостовые процессы получили ЧУЖУЮ личность пода (хостовые comm: $_w621_hostpodded, без container_id: $_w621_bad, контрольный читатель: ${W621_HOSTCAT_PODDED:-0}). Всякая величина 6.2.1, разрезанная по pod_name, недействительна"
    else
        pass "6.2.1.3 ДОСТИГНУТО: ни один хостовой процесс не получил личность пода; величина взята на полном объёме стора, а не на одном контрольном comm"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.1.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.2b ПОЗИТИВНЫЙ КОНТРОЛЬ ОСИ ПОДА (перенесён из 6.2.1 волны 6.2 без
# изменения смысла — с починенной отсечкой по времени и без спешки).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.2b: позитивный контроль оси пода (под читает свой SA-токен) ---"
if [ "$W621_INSTRUMENTED" -eq 1 ]; then
    "$W621_KUBECTL" create namespace "$W621_NS" --dry-run=client -o yaml 2>/dev/null | "$W621_KUBECTL" apply -f - >/dev/null 2>&1
    "$W621_KUBECTL" -n "$W621_NS" delete pod w621-token-probe --ignore-not-found --wait=true >/dev/null 2>&1
    cat > "$W621_ART/w621-token-probe.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: w621-token-probe
  labels:
    app: w621-token-probe
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
          echo "W621-SENTINEL opener_comm=$(cat /proc/$$/comm) token_head=$(echo "$t" | cut -c1-12) token_len=${#t}"
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
    _w621_tp=$(_w621_epoch)
    "$W621_KUBECTL" -n "$W621_NS" apply -f "$W621_ART/w621-token-probe.yaml" >/dev/null 2>&1
    "$W621_KUBECTL" -n "$W621_NS" wait --for=condition=Ready pod/w621-token-probe --timeout=90s >/dev/null 2>&1
    _w621_pdelta=0; _w621_waited=0
    while [ "$_w621_waited" -lt "$W621_POS_TIMEOUT" ]; do
        sleep "$W621_SETTLE"; _w621_waited=$(( _w621_waited + W621_SETTLE ))
        _w621_pdelta=$(_w621_alerts | jq --arg ids "$W621_K8S_RULES" --argjson t "$_w621_tp" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w621-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]|length' 2>/dev/null || echo 0)
        [ "${_w621_pdelta:-0}" -gt 0 ] && break
    done
    _w621_sent=$("$W621_KUBECTL" -n "$W621_NS" logs w621-token-probe 2>/dev/null | grep -m1 'W621-SENTINEL')
    _w621_phit=$(_w621_alerts | jq -r --arg ids "$W621_K8S_RULES" --argjson t "$_w621_tp" \
        '.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w621-token-probe") and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    echo "  ожидание записи в стор: ${_w621_waited}s"
    echo "  сторож результата: ${_w621_sent:-НЕ НАПЕЧАТАН}"
    echo "  алертов с pod_name=w621-token-probe: $_w621_pdelta (правила: ${_w621_phit:-нет})"
    _w621_len=$(printf '%s' "${_w621_sent:-}" | grep -oE 'token_len=[0-9]+' | cut -d= -f2)
    if [ -z "${_w621_len:-}" ] || [ "${_w621_len:-0}" -lt 100 ]; then
        die "6.2.1.2b НЕИЗМЕРИМ: сторож результата не напечатал прочитанный токен (token_len=${_w621_len:-нет}) — ноль правил приборный"
    elif [ "$_w621_pdelta" -lt 1 ]; then
        die "6.2.1.2b ПРОВАЛЕН: под прочитал токен (token_len=$_w621_len), а правила ${W621_K8S_RULES} не поднялись с его именем"
    else
        pass "6.2.1.2b ДОСТИГНУТО: чтение SA-токена подом подтверждено сторожем (token_len=$_w621_len) и подняло $_w621_pdelta алертов С ИМЕНЕМ ПОДА (${_w621_phit})"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.1.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.7 ОБОРОТ ПОДОВ (наследник 6.2.6). Величина без порога, но снимок
# берётся ПОСЛЕ полного оседания, а не через фиксированные 20 с: прошлый
# прогон снял 111 алертов при 143 за ту же минуту.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.7: цена одного старта пода (без порога) ---"
if [ "$W621_INSTRUMENTED" -eq 1 ]; then
    _w621_tc=$(_w621_epoch)
    for i in $(seq 1 "$W621_CHURN"); do
        "$W621_KUBECTL" -n "$W621_NS" run "w621-churn-$i" --image=busybox:1.36 --restart=Never --command -- sleep 15 >/dev/null 2>&1
    done
    sleep 45
    for i in $(seq 1 "$W621_CHURN"); do "$W621_KUBECTL" -n "$W621_NS" delete pod "w621-churn-$i" --ignore-not-found --wait=false >/dev/null 2>&1; done
    sleep $(( W621_SETTLE * 3 ))
    _w621_alerts > "$W621_ART/alerts-churn-end.json"
    _w621_churn=$(jq --argjson t "$_w621_tc" '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm|test("^(runc|containerd|conmon|crun|dockerd|pause)")))]' "$W621_ART/alerts-churn-end.json" 2>/dev/null)
    _w621_cn=$(echo "${_w621_churn:-[]}" | jq 'length' 2>/dev/null); _w621_cn=${_w621_cn:-0}
    echo "  запущено и снято подов: $W621_CHURN; алертов от рантайм-comm: $_w621_cn → $(awk -v n="$_w621_cn" -v p="$W621_CHURN" 'BEGIN{printf "%.1f", (p>0? n/p : 0)}') на под"
    echo "${_w621_churn:-[]}" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -25
    echo "  6.2.1.7: величина без порога — вход для сужения, а не вердикт"
else
    echo "  ПРОПУЩЕН: 6.2.1.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.8 СЛОЙ 2: КЛЮЧ ИСКЛЮЧЕНИЯ, КОТОРЫЙ ПРОЦЕСС СЕБЕ НЕ НАЗНАЧАЕТ.
#
# Исключения фона ноды опираются на три вещи: comm (процесс назначает себе
# сам — prctl(PR_SET_NAME), exec -a), пустую идентичность из cgroup (означает
# «не в контейнере», у ВСЕХ хостовых процессов одинакова) и образ
# /proc/<pid>/exe (ставит ядро в execve). Первая подделывается тривиально,
# вторая не различает хостовые процессы между собой, поэтому за отказ обхода
# отвечает третья.
#
# Контроль делает две разные вещи и не путает их:
#   (а) ПЕЧАТАЕТ фактические exe демонов — это доказательная база для
#       следующего ужесточения (сегодня в правилах стоит префикс каталога,
#       потому что точный путь зависит от способа установки k3s и вписывать
#       догадку в правило значит рискнуть тем, что исключение молча перестанет
#       применяться);
#   (б) ПРОВЕРЯЕТ отказ: подделка с тем же comm в том же хостовом контексте
#       обязана поднять те же правила, что обычный посторонний процесс.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.8: слой 2, образ процесса как ключ исключения ---"
if [ "$W621_INSTRUMENTED" -eq 1 ]; then
    W621_EXE_PREFIXES="/usr/ /bin/ /sbin/ /opt/ /var/lib/rancher/"
    _w621_exe_bad=""
    for _c in k3s-server containerd kubelet coredns; do
        _p=$(pgrep -x "$_c" 2>/dev/null | head -1)
        if [ -z "$_p" ]; then
            echo "  $_c: процесса нет на этой ноде (исключение для него на этом прогоне не проверяется)"
            continue
        fi
        _e=$(readlink "/proc/$_p/exe" 2>/dev/null)
        echo "  $_c: pid=$_p exe=${_e:-<не читается>}"
        # coredns живёт в поде: его исключение стоит на namespace из cgroup, а
        # не на образе, и путь внутри контейнера с хостовыми префиксами
        # сравнивать бессмысленно. Печатаем справочно, в проверку не берём.
        [ "$_c" = "coredns" ] && continue
        _ok=0
        for _pre in $W621_EXE_PREFIXES; do
            case "${_e:-}" in "$_pre"*) _ok=1 ;; esac
        done
        [ "$_ok" -eq 1 ] || _w621_exe_bad="$_w621_exe_bad $_c(${_e:-<пусто>})"
    done
    _w621_exe_res=$(_w621_metric_sum ebpf_guard_exe_path_lookups_total "" 2>/dev/null)
    echo "  обращений к /proc за образом (ebpf_guard_exe_path_lookups_total, накопительно): ${_w621_exe_res:-серии нет}"
    if [ -n "$_w621_exe_bad" ]; then
        die "6.2.1.8 ПРОВАЛЕН (половина «покрытие»): образ демона(ов)$_w621_exe_bad не попадает ни под один префикс правил ($W621_EXE_PREFIXES). Исключения фона ноды для них НЕ ПРИМЕНЯЮТСЯ — отказ открытый, в сторону шума, поэтому детект не потерян, но величина 6.2.1.1 выше измеряла НЕ сужённый фон, и сравнивать её с расчётом по архиву нельзя. Правки: внести фактический префикс в исключения (список выше — доказательная база)"
    else
        pass "6.2.1.8 ДОСТИГНУТО (половина «покрытие»): образы всех найденных хостовых демонов попадают под префиксы исключений"
    fi

    # (б) Отказ обхода. cp + exec -a — ровно то, чем обходится исключение по
    # comm: имя то же, хостовой контекст тот же, образ другой.
    _w621_target8=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    [ -z "$_w621_target8" ] && _w621_target8=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    if [ -z "$_w621_target8" ]; then
        die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): под /var/lib/kubelet/pods нет ни одного файла — подделке нечего читать, ноль был бы приборным"
    else
        cp /bin/cat /tmp/w621-k3s-server 2>/dev/null
        chmod 0755 /tmp/w621-k3s-server 2>/dev/null
        _w621_t8=$(_w621_epoch)
        # Сторож результата: без него ноль правил неотличим от «подделка не
        # запустилась» (память positive-control-needs-result-sentinel).
        _w621_b8=$( (exec -a k3s-server /tmp/w621-k3s-server "$_w621_target8") 2>/dev/null | wc -c )
        _w621_h8=0; _w621_w8=0
        while [ "$_w621_w8" -lt "$W621_POS_TIMEOUT" ]; do
            sleep "$W621_SETTLE"; _w621_w8=$(( _w621_w8 + W621_SETTLE ))
            _w621_h8=$(_w621_alerts | jq --argjson t "$_w621_t8" --arg ids "$W621_HOST_RULES" \
                '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.comm=="k3s-server") and (.rule_id as $r|($ids|split(" "))|index($r)))]|length' 2>/dev/null || echo 0)
            [ "${_w621_h8:-0}" -gt 0 ] && break
        done
        echo "  сторож результата подделки: прочитано байт = $_w621_b8 (цель $_w621_target8)"
        echo "  алертов от подделки (comm=k3s-server, образ /tmp/w621-k3s-server): $_w621_h8 из обязательных ($W621_HOST_RULES)"
        if [ "${_w621_b8:-0}" -lt 1 ]; then
            die "6.2.1.8 НЕИЗМЕРИМ (половина «отказ обхода»): подделка не прочитала ни байта — ноль правил приборный, а не вердикт"
        elif [ "${_w621_h8:-0}" -lt 1 ]; then
            die "6.2.1.8 ПРОВАЛЕН (половина «отказ обхода»): процесс, назвавшийся k3s-server и прочитавший токен пода ($_w621_b8 байт), НЕ поднял ни одного из $W621_HOST_RULES. Исключение фона ноды следует за именем, а не за образом — это готовый обход всей защиты ноды, а не тюнинг шума"
        else
            pass "6.2.1.8 ДОСТИГНУТО (половина «отказ обхода»): подделка имени демона не унаследовала его тишину — поднято $_w621_h8 правил"
        fi
        rm -f /tmp/w621-k3s-server 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.1.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1.9 СЛОЙ 3: СМЕНА ПРАВ НА ФАЙЛОВОЙ ОСИ.
#
# Три правила о chmod переехали с syscall-оси (где путь не разрешался и все
# три несли одно условие «случился chmod» — 144 алерта из 1787 в окне 6.2) на
# файловую, с разрешением пути в bpf/fileaccess.bpf.c. Если хуки не
# привязались или объект собран без них, правила молчат — и тогда падение
# объёма в 6.2.1.1 приборное, а не настоящее. Этот контроль отличает одно от
# другого, и это его единственная работа.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1.9: слой 3, chmod с разрешённым путём ---"
if [ "$W621_INSTRUMENTED" -eq 1 ]; then
    _w621_hook_ok=$(_w621_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="ok"/ {s+=$NF} END{printf "%d", s+0}')
    _w621_hook_err=$(_w621_metrics | awk '/^ebpf_guard_file_hook_attach_total\{.*result="(error|missing)"/ {s+=$NF} END{printf "%d", s+0}')
    _w621_unres=$(_w621_metric_sum ebpf_guard_file_chmod_unresolved_total "" 2>/dev/null)
    echo "  привязка chmod-хуков: ok=$_w621_hook_ok, error+missing=$_w621_hook_err"
    echo "  chmod без разрешённого пути (ebpf_guard_file_chmod_unresolved_total, накопительно): ${_w621_unres:-серии нет}"

    _w621_t9=$(_w621_epoch)
    # Две подачи, по одной на два разных правила: если обе поднимут одно и то
    # же правило, значит адресность не появилась и слой 3 не состоялся.
    mkdir -p /tmp/w621-chmod 2>/dev/null
    : > /tmp/w621-chmod/payload 2>/dev/null
    chmod 0755 /tmp/w621-chmod/payload 2>/dev/null
    _w621_m1=$(stat -c '%a' /tmp/w621-chmod/payload 2>/dev/null)
    cp /bin/cat /usr/local/bin/w621-chmod-bin 2>/dev/null
    chmod 0755 /usr/local/bin/w621-chmod-bin 2>/dev/null
    _w621_m2=$(stat -c '%a' /usr/local/bin/w621-chmod-bin 2>/dev/null)
    echo "  сторож результата: права /tmp/w621-chmod/payload = ${_w621_m1:-НЕ ПРОЧИТАНЫ}, /usr/local/bin/w621-chmod-bin = ${_w621_m2:-НЕ ПРОЧИТАНЫ}"

    _w621_c9=0; _w621_w9=0
    while [ "$_w621_w9" -lt "$W621_POS_TIMEOUT" ]; do
        sleep "$W621_SETTLE"; _w621_w9=$(( _w621_w9 + W621_SETTLE ))
        _w621_c9=$(_w621_alerts | jq --argjson t "$_w621_t9" \
            '[.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))]|length' 2>/dev/null || echo 0)
        [ "${_w621_c9:-0}" -gt 1 ] && break
    done
    _w621_r9=$(_w621_alerts | jq -r --argjson t "$_w621_t9" \
        '.[]|select(((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t) and (.rule_id|test("chmod")))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    echo "  алертов о смене прав после подачи: $_w621_c9 (правила: ${_w621_r9:-нет})"

    if [ -z "${_w621_m1:-}" ] || [ -z "${_w621_m2:-}" ]; then
        die "6.2.1.9 НЕИЗМЕРИМ: сторож результата не прочитал права после chmod — подача не состоялась, ноль правил приборный"
    elif [ "$_w621_hook_ok" -eq 0 ]; then
        die "6.2.1.9 ПРОВАЛЕН (приборный ноль): ни один chmod-хук не привязан (ok=0, error+missing=$_w621_hook_err). Три правила о смене прав НЕ МОГУТ сработать, значит их вклад в объём 6.2.1.1 равен нулю по причине отсутствия прибора, а не сужения. Проверить: собран ли объект через make generate ПОСЛЕ правки bpf/fileaccess.bpf.c"
    elif ! printf '%s' "$_w621_r9" | grep -q 'sigma_chmod_executable_tmp'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod +x в /tmp состоялся (права $_w621_m1), а sigma_chmod_executable_tmp не поднялся. Правило переехало на файловую ось и там немо — это тихая смерть правила, ровно тот дефект, который волна ловит у других"
    elif ! printf '%s' "$_w621_r9" | grep -q 'evasion_chmod_sensitive'; then
        die "6.2.1.9 ПРОВАЛЕН: chmod системного бинаря состоялся (права $_w621_m2), а evasion_chmod_sensitive не поднялся"
    else
        pass "6.2.1.9 ДОСТИГНУТО: смена прав видна с разрешённым путём, и каждое из двух мест подняло СВОЁ правило (${_w621_r9})"
    fi
    rm -rf /tmp/w621-chmod /usr/local/bin/w621-chmod-bin 2>/dev/null
else
    echo "  ПРОПУЩЕН: 6.2.1.0 не взят"
fi

echo "--- уборка ---"
"$W621_KUBECTL" -n "$W621_NS" delete pod --all --ignore-not-found --wait=false >/dev/null 2>&1
rm -f /usr/local/bin/w621hostcat 2>/dev/null

echo
echo "=== ИТОГ КОНТРОЛЕЙ ВОЛНЫ 6.2.1: проваленных $WAVE621_FAILS ==="
echo "артефакты: $W621_ART"
[ "$WAVE621_FAILS" -gt 0 ] && echo "вердикты: $W621_VERDICTS"
exit 0
