#!/bin/bash
# wave6.2-controls.sh — контроли волны 6.2 (k8s-нода).
#
# ПОЧЕМУ ЭТОТ ФАЙЛ СУЩЕСТВУЕТ. Волна 6.2 поднимает на стенде k3s и включает
# kubernetes.enabled. Это меняет три вещи разом, и каждая делает предыдущие
# величины несопоставимыми:
#   1) появляется вход для правил cis-k8s/k8s-* — они впервые перестают быть
#      немыми, и это НУЖНО доказать, а не предположить;
#   2) ключ базовой линии дрейфа {Comm, Namespace, AppLabel}
#      (internal/profiler/workload.go:77-87) получает два непустых поля у
#      каждого обогащённого события — вся выученная база одномоментно уходит
#      в learning (пункт А «Переноса в 6.1…6.4»);
#   3) нода приносит свой фон: k3s-server, containerd, runc:[N:INIT], kubelet,
#      coredns — то есть новый шум ровно там, где гейт волны 6 требует «не
#      выше 100/час».
#
# ПОРЯДОК ЧТЕНИЯ ВЕРДИКТОВ. 6.2.0 — сторож приборности. Не взят — 6.2.1/6.2.2
# НЕ ЧИТАЮТСЯ ВООБЩЕ: ни ноль, ни единица там ничего не измеряют.
#
# ЗАПУСК. Скрипт не самостоятелен: нужен живой агент с kubernetes.enabled:true
# и готовая нода. Провал контроля НЕ убивает чужой прогон (волна 6.0m,
# память die-only-for-unmeasurable-run).
#   W62_API      — база HTTP API агента (http://<host>:19090)
#   W62_TOKEN    — bearer-токен (формат файла токена — admin=<...>, не голый)
#   W62_KUBECTL  — путь к kubectl (по умолчанию /usr/local/bin/kubectl)
#   W62_NS       — namespace контролей (по умолчанию w62)
#   W62_WINDOW   — длина тихого окна объёма, с (по умолчанию 600)
set -u

VPS_IP="${VPS_IP:-localhost}"
W62_API="${W62_API:-http://${VPS_IP}:19090}"
W62_TOKEN="${W62_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W62_KUBECTL="${W62_KUBECTL:-/usr/local/bin/kubectl}"
W62_NS="${W62_NS:-w62}"
W62_WINDOW="${W62_WINDOW:-600}"
W62_SETUP="${W62_SETUP:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
W62_SETTLE="${W62_SETTLE:-20}"
W62_VERDICTS="${W62_VERDICTS:-/root/wave6.2-controls-verdicts.txt}"
W62_ART="${W62_ART:-/root/wave6.2-artifacts}"

WAVE62_FAILS=0
mkdir -p "$W62_ART" 2>/dev/null || true

die() {
    echo "=== КОНТРОЛЬ ПРОВАЛЕН (прогон НЕ прерывается — волна 6.0m): $* ==="
    WAVE62_FAILS=$((WAVE62_FAILS + 1))
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)+' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W62_VERDICTS" 2>/dev/null || true
    return 0
}
pass() { echo "OK: $*"; }

: > "$W62_VERDICTS" 2>/dev/null || true
echo "# wave6.2-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W62_VERDICTS"
echo "=== КОНТРОЛИ ВОЛНЫ 6.2 (k8s-нода) ==="

# Правила, для которых нода — ЕДИНСТВЕННЫЙ вход. До 6.2 они немы на стенде
# по отсутствию входа, а не по условию (различие находки №2).
W62_K8S_RULES="cis_5_1_3_secret_access k8s_sa_token_read k8s_sa_token_projected_read k8s_hostpath_kubelet_access"
# Акторы ноды: их фон и есть «цена ноды» критерия 6.2.3. Список сверяется с
# idle-actors.txt — расхождение означает, что реестр отстал от стенда.
W62_NODE_ACTORS="k3s-server kubelet containerd containerd-shim containerd-shim-runc-v2 runc runc:[1:CHILD] runc:[2:INIT] coredns local-path-prov kube-proxy pause iptables ip6tables kubectl"

_w62_curl() { curl -s --max-time 20 -H "Authorization: Bearer $W62_TOKEN" "$@"; }
_w62_alerts() { _w62_curl "$W62_API/api/v1/alerts?limit=200000"; }
_w62_metrics() { _w62_curl "$W62_API/metrics"; }

# Сумма метрики по списку правил. Считается ПРЯМОЙ дельтой двух срезов, а не
# строкой таблицы: строка таблицы индексирована срезом лимитера (память
# f6b-table-indexed-by-limiter-cut), и её отсутствие не равно нулю.
_w62_metric_sum() { # $1=metric $2=список rule_id (пусто = все)
    local metric="$1" ids="${2:-}"
    _w62_metrics | awk -v m="$metric" -v ids="$ids" '
        BEGIN { n = split(ids, a, " ") }
        $0 ~ "^"m"[{ ]" {
            if (n == 0) { s += $NF; next }
            for (i = 1; i <= n; i++) if (index($0, "rule_id=\"" a[i] "\"")) { s += $NF; next }
        }
        END { printf "%d", s+0 }'
}
_w62_volume() { # объём = экспортированные + срезанные min_severity
    echo "$(( $(_w62_metric_sum ebpf_guard_alerts_total "${1:-}") + $(_w62_metric_sum ebpf_guard_alerts_filtered_total "${1:-}") ))"
}
_w62_ratelimited() { _w62_metric_sum ebpf_guard_alerts_ratelimited_by_rule_total "${1:-}"; }

# ─────────────────────────────────────────────────────────────────────────────
# ПРЕFLIGHT. Провал здесь означает, что величины ниже нечем читать.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2 преflight ---"

if ! command -v jq >/dev/null 2>&1; then
    die "6.2 преflight ПРОВАЛЕН: нет jq — все величины по стору неизмеримы"
fi
if [ ! -x "$W62_KUBECTL" ]; then
    die "6.2 преflight ПРОВАЛЕН: kubectl не найден ($W62_KUBECTL) — ноду нечем подать на вход, любой ноль ниже будет приборным"
else
    _w62_node_ready=$("$W62_KUBECTL" get nodes --no-headers 2>/dev/null | awk '$2=="Ready"{n++} END{print n+0}')
    if [ "${_w62_node_ready:-0}" -lt 1 ]; then
        die "6.2 преflight ПРОВАЛЕН: ни одна нода не Ready — волна меряет не то, что называется"
    else
        pass "6.2 преflight: нод Ready = $_w62_node_ready ($("$W62_KUBECTL" version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // "?"'))"
    fi
fi

_w62_cfg="${W62_CONFIG:-$W62_SETUP/config-test.yaml}"
# Блок читается ЦЕЛИКОМ (от 'kubernetes:' до следующего ключа верхнего
# уровня), а не окном фиксированной длины: комментарий внутри блока вырос до
# двух десятков строк, и grep -A6 не доставал до enabled — сторож печатал
# «НЕ true» при true. Приборный провал сторожа приборности стоит дороже
# обычного: он объявляет неизмеримым исправный прогон.
_w62_k8s_block=$(awk '/^kubernetes:/{f=1;next} f && /^[a-zA-Z#]/{exit} f' "$_w62_cfg" 2>/dev/null)
# Окна обучения дрейфа — вход критерия 6.2.A ниже.
_w62_drift_cfg=$(awk '/drift_baseline:/{f=1;next} f && /^[a-zA-Z]/{exit} f' "$_w62_cfg" 2>/dev/null)
if ! echo "$_w62_k8s_block" | grep -qE '^\s*enabled:\s*true\s*$'; then
    die "6.2 преflight ПРОВАЛЕН: в $_w62_cfg kubernetes.enabled НЕ true — k8s-энричер не конструируется вовсе (cmd/ebpf-guard/main.go:1835), namespace/pod_name пусты на каждом событии по построению. Ровно эта находка (№216) стоила прогона волне 6.1"
else
    pass "6.2 преflight: kubernetes.enabled: true в $_w62_cfg"
fi

# Источник обогащения — обязательная печатаемая величина, а не деталь: без неё
# «пусто» и «не тот сокет» неразличимы. На этом стенде auto выбирает docker,
# а поды k3s живут в своём containerd — у подов container_name/image пусты
# ЗАКОННО, а container.id уцелеет деградацией 6.1 до голого cgroup-ID.
_w62_src=$(journalctl -u ebpf-guard-test.service --no-pager 2>/dev/null | grep -o '"msg":"runtime enricher active","source":"[a-z]*"' | tail -1 | grep -oE '"source":"[a-z]*"' | cut -d'"' -f4)
_w62_k8s_up=$(journalctl -u ebpf-guard-test.service --no-pager 2>/dev/null | grep -c 'k8s enricher active')
echo "  источник runtime-обогащения: ${_w62_src:-НЕ НАПЕЧАТАН}; строк «k8s enricher active» в журнале: $_w62_k8s_up"
if [ "${_w62_k8s_up:-0}" -lt 1 ]; then
    die "6.2 преflight ПРОВАЛЕН: в журнале агента нет «k8s enricher active» — энричер не поднялся (нет kubeconfig? нет прав?), и pod_name будет пуст по причине, не имеющей отношения к продукту"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.0 ПРИБОРНОСТЬ. Метаданные пода доезжают до алерта.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.0: приборность оси пода ---"
_w62_pod_alerts=$(_w62_alerts | jq '[.[]|select(((.enrichment.pod_name // "") != "") and ((.enrichment.namespace // "") != ""))]|length' 2>/dev/null || echo 0)
_w62_ns_seen=$(_w62_alerts | jq -r '.[]|select((.enrichment.namespace // "")!="")|.enrichment.namespace' 2>/dev/null | sort -u | tr '\n' ' ')
echo "  алертов с непустыми namespace И pod_name: $_w62_pod_alerts; namespace'ы: ${_w62_ns_seen:-нет}"
W62_INSTRUMENTED=0
if [ "${_w62_pod_alerts:-0}" -lt 1 ]; then
    die "6.2.0 ПРОВАЛЕН: ни одного алерта с личностью пода. Дальше 6.2.1/6.2.2 НЕ ЧИТАЮТСЯ — их ноль был бы приборным"
else
    W62_INSTRUMENTED=1
    pass "6.2.0 ДОСТИГНУТО: личность пода доезжает до алерта ($_w62_pod_alerts алертов)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.1 ПОЗИТИВНЫЙ КОНТРОЛЬ СО СТОРОЖЕМ РЕЗУЛЬТАТА.
# Под читает свой serviceaccount-токен → правила класса «доступ к секрету»
# обязаны подняться С ИМЕНЕМ ПОДА.
#
# Сторож результата (память positive-control-needs-result-sentinel): под
# печатает ДЛИНУ и первые байты реально прочитанного токена и comm ТОГО
# процесса, который открывал файл. Без сторожа ноль правила неотличим от
# «под не запустился / токен не смонтирован» — приборный ноль.
# Открывает файл САМ shell (`read t < ...`), а не короткоживущий cat: PID
# должен быть жив в момент, когда энричер резолвит его cgroup.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.1: позитивный контроль (под читает SA-токен) ---"
if [ "$W62_INSTRUMENTED" -eq 1 ]; then
    "$W62_KUBECTL" create namespace "$W62_NS" --dry-run=client -o yaml 2>/dev/null | "$W62_KUBECTL" apply -f - >/dev/null 2>&1
    "$W62_KUBECTL" -n "$W62_NS" delete pod w62-token-probe --ignore-not-found --wait=true >/dev/null 2>&1
    cat > "$W62_ART/w62-token-probe.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: w62-token-probe
  labels:
    app: w62-token-probe
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
          echo "W62-SENTINEL opener_comm=$(cat /proc/$$/comm) token_head=$(echo "$t" | cut -c1-12) token_len=${#t}"
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
    # Отсечка по ВРЕМЕНИ, а не разность двух счётчиков: под с этим именем мог
    # существовать раньше (репетиция, предыдущий прогон), и его старые алерты
    # входят в обе стороны разности одинаково — а вот засчитывать их нельзя.
    _w62_t_pos=$(date -u +%FT%TZ)
    "$W62_KUBECTL" -n "$W62_NS" apply -f "$W62_ART/w62-token-probe.yaml" >/dev/null 2>&1
    "$W62_KUBECTL" -n "$W62_NS" wait --for=condition=Ready pod/w62-token-probe --timeout=90s >/dev/null 2>&1
    # Алерт доезжает до стора ПАЧКОЙ, а не сразу: репетиция 19:05 показала
    # ноль при уже поднятых правилах — снимок через фиксированные 20 с застал
    # запись, которой ещё нет. Ждать событие, а не время.
    _w62_delta=0
    _w62_waited=0
    while [ "$_w62_waited" -lt "${W62_POS_TIMEOUT:-120}" ]; do
        sleep "$W62_SETTLE"
        _w62_waited=$(( _w62_waited + W62_SETTLE ))
        _w62_delta=$(_w62_alerts | jq --arg ids "$W62_K8S_RULES" --arg t "$_w62_t_pos" '[.[]|select((.rule_id as $r | ($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w62-token-probe") and (.timestamp > $t))]|length' 2>/dev/null || echo 0)
        [ "${_w62_delta:-0}" -gt 0 ] && break
    done
    echo "  ожидание записи в стор: ${_w62_waited}s"
    _w62_sentinel=$("$W62_KUBECTL" -n "$W62_NS" logs w62-token-probe 2>/dev/null | grep -m1 'W62-SENTINEL')
    _w62_rules_hit=$(_w62_alerts | jq -r --arg ids "$W62_K8S_RULES" --arg t "$_w62_t_pos" '.[]|select((.rule_id as $r | ($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")=="w62-token-probe") and (.timestamp > $t))|.rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
    echo "  сторож результата: ${_w62_sentinel:-НЕ НАПЕЧАТАН}"
    echo "  дельта алертов с pod_name=w62-token-probe: $_w62_delta (правила: ${_w62_rules_hit:-нет})"
    _w62_len=$(printf '%s' "${_w62_sentinel:-}" | grep -oE 'token_len=[0-9]+' | cut -d= -f2)
    if [ -z "${_w62_len:-}" ] || [ "${_w62_len:-0}" -lt 100 ]; then
        die "6.2.1 НЕИЗМЕРИМ: сторож результата не напечатал прочитанный токен (token_len=${_w62_len:-нет}). Под не стартовал или токен не смонтирован — ноль правил здесь ПРИБОРНЫЙ, а не вердикт о продукте"
    elif [ "$_w62_delta" -lt 1 ]; then
        die "6.2.1 ПРОВАЛЕН: под прочитал токен (token_len=$_w62_len), а правила ${W62_K8S_RULES} не поднялись с его именем — вход есть, детекта нет"
    else
        pass "6.2.1 ДОСТИГНУТО: чтение SA-токена подом подтверждено сторожем (token_len=$_w62_len) и подняло $_w62_delta алертов С ИМЕНЕМ ПОДА (${_w62_rules_hit})"
    fi
else
    echo "  ПРОПУЩЕН: 6.2.0 не взят, ноль здесь был бы приборным"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.2 НЕГАТИВНЫЙ КОНТРОЛЬ. Хостовой процесс не получает чужую личность пода.
#
# Две половины, и обе обязательны. Считать «все алерты правила» здесь нельзя
# (урок 6.1.2): любой ПОД, читающий секрет в то же окно, дал бы +N и вынес
# вердикт, ПРЯМО ОБРАТНЫЙ действительности. Меряется только своя пара
# (comm читателя × наличие pod_name).
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.2: негативный контроль (хостовой читатель) ---"
if [ "$W62_INSTRUMENTED" -eq 1 ]; then
    _w62_host_target=$(find /var/lib/kubelet/pods -maxdepth 6 -type f -name token 2>/dev/null | head -1)
    if [ -z "$_w62_host_target" ]; then
        _w62_host_target=$(find /var/lib/kubelet/pods -maxdepth 4 -type f 2>/dev/null | head -1)
    fi
    if [ -z "$_w62_host_target" ]; then
        die "6.2.2 НЕИЗМЕРИМ: под /var/lib/kubelet/pods нет ни одного файла — хостовую половину нечем подать, ноль будет приборным"
    else
        # Отдельный comm, чтобы считать ТОЛЬКО своё чтение. Копия, а не
        # symlink: comm берётся из имени исполняемого файла.
        cp /bin/cat /usr/local/bin/w62hostcat 2>/dev/null
        _w62_t_neg=$(date -u +%FT%TZ)
        _w62_host_bytes=$(/usr/local/bin/w62hostcat "$_w62_host_target" 2>/dev/null | wc -c)
        _w62_host_all=0
        _w62_waited=0
        while [ "$_w62_waited" -lt "${W62_POS_TIMEOUT:-120}" ]; do
            sleep "$W62_SETTLE"
            _w62_waited=$(( _w62_waited + W62_SETTLE ))
            _w62_host_all=$(_w62_alerts | jq --arg t "$_w62_t_neg" '[.[]|select(.comm=="w62hostcat" and (.timestamp > $t))]|length' 2>/dev/null || echo 0)
            [ "${_w62_host_all:-0}" -gt 0 ] && break
        done
        _w62_host_podded=$(_w62_alerts | jq --arg t "$_w62_t_neg" '[.[]|select(.comm=="w62hostcat" and (.timestamp > $t) and ((.enrichment.pod_name // "")!=""))]|length' 2>/dev/null || echo 0)
        echo "  сторож результата: прочитано байт с хоста = $_w62_host_bytes (цель $_w62_host_target)"
        echo "  алертов от comm=w62hostcat: всего $_w62_host_all, из них с непустым pod_name: $_w62_host_podded"
        if [ "${_w62_host_bytes:-0}" -lt 1 ]; then
            die "6.2.2 НЕИЗМЕРИМ: хостовой читатель ничего не прочитал (байт=$_w62_host_bytes) — ноль ниже приборный"
        elif [ "$_w62_host_podded" -gt 0 ]; then
            die "6.2.2 ПРОВАЛЕН: $_w62_host_podded алертов хостового процесса получили ЧУЖУЮ личность пода — энричер приписывает хосту под, и всякая величина 6.2, разрезанная по pod_name, недействительна"
        elif [ "$_w62_host_all" -lt 1 ]; then
            echo "  ЗАМЕЧАНИЕ (не провал): чтение с хоста не подняло ни одного правила — негативная половина взята, но позитивной опоры у неё на этом входе нет"
            pass "6.2.2 ДОСТИГНУТО: хостовой процесс не получил личность пода (0 из $_w62_host_all)"
        else
            pass "6.2.2 ДОСТИГНУТО: $_w62_host_all алертов хостового читателя, ВСЕ с пустым pod_name"
        fi
        rm -f /usr/local/bin/w62hostcat 2>/dev/null
    fi
else
    echo "  ПРОПУЩЕН: 6.2.0 не взят"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.3 ЦЕНА НОДЫ + 6.2.4 НАБЛЮДЕНИЯ ДРЕЙФА.
# Объём читается ВМЕСТЕ со срезом лимитера (пункт Е): правило, упёршееся в
# 10 алертов/60 с, показывает величину ЛИМИТЕРА, а не реальности.
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# 6.2.A ДЛИНА ПРОЛОГА (пункт А «Переноса в 6.1…6.4»), проверяется ЧИСЛОМ.
# Подъём ноды меняет ключ {Comm, Namespace, AppLabel} у каждого обогащённого
# события разом — вся выученная база уходит в learning. Пока не прошло
# learning_period × enforce_deadline_periods от старта агента, окно ниже
# меряет ОБУЧЕНИЕ, а не базовую линию, и величины дрейфа с него не значат
# того, что написано в их именах. Волна 6.0a уже платила за это укорочением
# окон; здесь величина печатается, а не обещается.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.A: длина пролога до открытия окна ---"
_w62_lp=$(echo "$_w62_drift_cfg" | grep -oE 'learning_period:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w62_edp=$(echo "$_w62_drift_cfg" | grep -oE 'enforce_deadline_periods:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1)
_w62_need=$(( ${_w62_lp:-600} * ${_w62_edp:-2} ))
_w62_started=$(systemctl show ebpf-guard-test.service -p ActiveEnterTimestamp --value 2>/dev/null)
_w62_started_s=$(date -d "$_w62_started" +%s 2>/dev/null || echo 0)
_w62_prologue=$(( $(date +%s) - _w62_started_s ))
echo "  агент поднят: ${_w62_started:-?}; пролог до открытия окна: ${_w62_prologue}s; требуется > learning_period($_w62_lp) × enforce_deadline_periods($_w62_edp) = ${_w62_need}s"
_w62_learning_now=$(_w62_metric_sum ebpf_guard_drift_baseline_learning_workloads "")
_w62_prof_now=$(_w62_metric_sum ebpf_guard_drift_baseline_profiles "")
echo "  на этот момент: профилей $_w62_prof_now, из них в learning $_w62_learning_now"
if [ "$_w62_started_s" -eq 0 ]; then
    die "6.2.A НЕИЗМЕРИМ: время старта сервиса не прочитано — длину пролога нечем доказать, и величины дрейфа окна ниже нечем защитить от «это было обучение»"
elif [ "$_w62_prologue" -le "$_w62_need" ]; then
    die "6.2.A ПРОВАЛЕН: пролог ${_w62_prologue}s не длиннее ${_w62_need}s — окно ниже меряет ОБУЧЕНИЕ, а не базовую линию (пункт А). Величины дрейфа этого прогона не засчитываются"
else
    pass "6.2.A ДОСТИГНУТО: пролог ${_w62_prologue}s > ${_w62_need}s, обучение закрыто до открытия окна"
fi

echo "--- 6.2.3/6.2.4: тихое окно ${W62_WINDOW}s ---"
_w62_drift_print() { # $1 = метка среза
    local m; m=$(_w62_metrics)
    echo "  дрейф[$1]: $(echo "$m" | awk '/^ebpf_guard_drift_baseline_(profiles|learning_workloads|stuck_learning_workloads|learning_overdue_workloads|saturated_profiles|evictions_total) /{printf "%s=%s ", $1, $2}')"
}
_w62_t0=$(date -u +%FT%TZ)
_w62_vol0=$(_w62_volume "")
_w62_rl0=$(_w62_ratelimited "")
# Полный срез метрик на обоих концах окна. Репетиция 19:05 показала, зачем:
# накопительный счётчик среза лимитера ненулевой почти у всех правил с самого
# старта агента, и сторож объявлял неизмеримым ВСЁ подряд. Величина, которая
# нужна пункту Е, — срез ЗА ОКНО (память control-after-attacks-hits-filled-limiter:
# ноль контроля может быть срезом, а не вердиктом; читать надо срез окна).
_w62_metrics > "$W62_ART/metrics-window-start.txt"
_w62_drift_print "открытие"
echo "  окно открыто $_w62_t0 — до закрытия НЕ ПОДАВАТЬ вход (память ebpf-guard-measurement-hygiene, п.2/п.5)"
sleep "$W62_WINDOW"
_w62_t1=$(date -u +%FT%TZ)
_w62_vol1=$(_w62_volume "")
_w62_rl1=$(_w62_ratelimited "")
_w62_metrics > "$W62_ART/metrics-window-end.txt"
_w62_drift_print "закрытие"
_w62_alerts > "$W62_ART/alerts-window-end.json"

# Срез лимитера по правилу ЗА ОКНО: разность двух снимков одной метрики.
_w62_rl_window() { # $1=rule_id
    awk -v r="$1" '
        FILENAME==ARGV[1] && index($0, "rule_id=\"" r "\"") && /^ebpf_guard_alerts_ratelimited_by_rule_total/ { a=$NF }
        FILENAME==ARGV[2] && index($0, "rule_id=\"" r "\"") && /^ebpf_guard_alerts_ratelimited_by_rule_total/ { b=$NF }
        END { printf "%d", (b+0)-(a+0) }' "$W62_ART/metrics-window-start.txt" "$W62_ART/metrics-window-end.txt"
}

# «Новый шум» — алерты окна, принесённые нодой: непустой namespace ЛИБО comm
# из списка акторов ноды. Остальное — старый фон стенда, к цене ноды не
# относится и в гейт волны 6 не входит.
_w62_new=$(jq --arg t0 "$_w62_t0" --arg t1 "$_w62_t1" --arg actors "$W62_NODE_ACTORS" '
    [ .[] | select(.timestamp > $t0 and .timestamp <= $t1)
      | select(((.enrichment.namespace // "") != "") or ((.comm) as $c | ($actors|split(" "))|index($c))) ]
    ' "$W62_ART/alerts-window-end.json" 2>/dev/null)
_w62_new_n=$(echo "$_w62_new" | jq 'length' 2>/dev/null || echo 0)
_w62_new_hour=$(awk -v n="${_w62_new_n:-0}" -v w="$W62_WINDOW" 'BEGIN{printf "%.0f", n*3600.0/w}')
echo "  окно $_w62_t0 … $_w62_t1"
echo "  ПРЯМАЯ дельта объёма (все правила, alerts_total+filtered): $(( _w62_vol1 - _w62_vol0 ))"
echo "  ПРЯМАЯ дельта среза лимитера (все правила): $(( _w62_rl1 - _w62_rl0 ))"
echo "  новых алертов ноды за окно: ${_w62_new_n:-0} → $_w62_new_hour/ч"
echo "  разбивка по правилам (правило: алертов):"
echo "$_w62_new" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -25
echo "  разбивка по comm:"
echo "$_w62_new" | jq -r 'group_by(.comm)|map({c:.[0].comm,n:length})|sort_by(-.n)[]|"    \(.c): \(.n)"' 2>/dev/null | head -15
# Правила, упёршиеся в лимитер за окно — их величина выше есть показание
# прибора. Называются поимённо, как требует пункт Е.
_w62_capped=""
for _r in $(echo "$_w62_new" | jq -r '.[].rule_id' 2>/dev/null | sort -u); do
    _d=$(_w62_rl_window "$_r")
    if [ "${_d:-0}" -gt 0 ]; then _w62_capped="$_w62_capped $_r(+$_d)"; fi
done
echo "  правила со СРЕЗОМ лимитера ЗА ОКНО:${_w62_capped:- нет}"
# ПОРЯДОК ПРОВЕРОК ВАЖЕН. Срез лимитера может только ЗАНИЗИТЬ измеренный
# объём — правило, упёршееся в 10/60с, не печатает то, что сверх. Значит,
# измеренная величина есть НИЖНЯЯ ОЦЕНКА, и превышение порога ею одной уже
# доказано: снятие среза может величину только увеличить. Поэтому «выше 100/ч»
# судится ПЕРВЫМ и при срезе тоже; «неизмеримо» остаётся только для случая,
# когда величина порог не перешла, а прибор упёрт — там ноль незнания
# настоящий (пункт Е «Переноса в 6.1…6.4»).
if [ "$_w62_new_hour" -gt 100 ] && [ -n "$_w62_capped" ]; then
    die "6.2.3 ПРОВАЛЕН (величина — НИЖНЯЯ оценка): цена ноды не менее $_w62_new_hour алертов/ч при гейте волны 6 «не выше 100/ч». У правил${_w62_capped} есть срез лимитера за окно, то есть реальный объём ВЫШЕ измеренного, а не ниже — вердикт от этого только твёрже. Разбивка по правилам выше — вход для сужения"
elif [ -n "$_w62_capped" ]; then
    die "6.2.3 НЕИЗМЕРИМ ПО БУКВЕ: величина $_w62_new_hour/ч порог не перешла, но у правил${_w62_capped} есть срез лимитера за окно — их вклад есть показание упёршегося прибора (10/60с = 600/ч потолок), и «≤100/ч» здесь не вердикт, а показание (пункт Е)"
elif [ "$_w62_new_hour" -gt 100 ]; then
    die "6.2.3 ПРОВАЛЕН: цена ноды $_w62_new_hour алертов/ч при гейте волны 6 «не выше 100/ч нового шума». Разбивка по правилам напечатана выше — это вход для сужения, а не повод понизить порог"
else
    pass "6.2.3 ДОСТИГНУТО: цена ноды $_w62_new_hour алертов/ч ≤ 100/ч, ни одно считаемое правило не срезано лимитером"
fi
echo "  6.2.4: наблюдения дрейфа напечатаны на обоих срезах ВЫШЕ, порог не назначается (правильный ответ на ноде неизвестен, запрет 5.9.6)"

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.5 СТОРОЖ ВЫТЕСНЕНИЯ LRU (живая половина).
# Политику доказывает юнит-тест TestDriftBaselineEvictionSparesActiveWorkload
# (internal/profiler/driftbaseline_test.go): при достигнутом капе вытесняется
# МОЛЧАЩАЯ нагрузка, активная переживает вдесятеро больший поток чужих, и
# каждое вытеснение напечатано счётчиком. Живьём кап (1000) не достигается —
# здесь проверяется ровно то, что достижимо: прибор существует и растёт
# согласованно с числом профилей.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.5: сторож вытеснения (живая половина) ---"
_w62_prof=$(_w62_metric_sum ebpf_guard_drift_baseline_profiles "")
_w62_evict=$(_w62_metric_sum ebpf_guard_drift_baseline_evictions_total "")
_w62_maxw=$(grep -A3 'max_workloads' "$_w62_cfg" 2>/dev/null | grep -oE 'max_workloads:\s*[0-9]+' | grep -oE '[0-9]+' | head -1)
echo "  профилей=$_w62_prof, вытеснений=$_w62_evict, max_workloads=${_w62_maxw:-?}"
if ! _w62_metrics | grep -q '^ebpf_guard_drift_baseline_evictions_total'; then
    die "6.2.5 ПРОВАЛЕН: метрики ebpf_guard_drift_baseline_evictions_total нет в выдаче — вытеснение линии стало бы молчаливым, а молчаливая потеря линии неотличима от «нагрузка не встречалась»"
elif [ "${_w62_maxw:-0}" -gt 0 ] && [ "${_w62_prof:-0}" -ge "${_w62_maxw:-0}" ] && [ "${_w62_evict:-0}" -eq 0 ]; then
    die "6.2.5 ПРОВАЛЕН: профилей $_w62_prof при капе $_w62_maxw, а вытеснений 0 — кап не бюджет, а пожелание"
else
    pass "6.2.5 ДОСТИГНУТО (живая половина): прибор вытеснения существует и печатается; политику держит юнит TestDriftBaselineEvictionSparesActiveWorkload"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6.2.6 ОБОРОТ ПОДОВ: runc:[N:INIT] вне оси 6.1 (долг волны 6.1).
# Волна 6.1 исключила runtime-comm из ПЯТИ Q9-правил, но старт контейнера
# по-прежнему поднимает container-escape/rootkit/cis — это ДРУГОЙ, до-6.1
# источник. На докер-стенде он был разовым; на ноде оборот подов делает его
# постоянным. Величина без порога + поимённый разбор.
# ─────────────────────────────────────────────────────────────────────────────
echo "--- 6.2.6: цена одного старта пода ---"
_w62_churn_n="${W62_CHURN:-3}"
_w62_t_churn=$(date -u +%FT%TZ)
for i in $(seq 1 "$_w62_churn_n"); do
    "$W62_KUBECTL" -n "$W62_NS" run "w62-churn-$i" --image=busybox:1.36 --restart=Never --command -- sleep 15 >/dev/null 2>&1
done
sleep 45
"$W62_KUBECTL" -n "$W62_NS" delete pod -l run --ignore-not-found --wait=false >/dev/null 2>&1
for i in $(seq 1 "$_w62_churn_n"); do "$W62_KUBECTL" -n "$W62_NS" delete pod "w62-churn-$i" --ignore-not-found --wait=false >/dev/null 2>&1; done
sleep "$W62_SETTLE"
_w62_alerts > "$W62_ART/alerts-churn-end.json"
_w62_churn=$(jq --arg t "$_w62_t_churn" '
    [ .[] | select(.timestamp > $t) | select(.comm|test("^(runc|containerd|conmon|crun|dockerd)")) ]
    ' "$W62_ART/alerts-churn-end.json" 2>/dev/null)
_w62_churn_n_alerts=$(echo "${_w62_churn:-[]}" | jq 'length' 2>/dev/null)
_w62_churn_n_alerts=${_w62_churn_n_alerts:-0}
_w62_per_pod=$(awk -v n="${_w62_churn_n_alerts:-0}" -v p="$_w62_churn_n" 'BEGIN{printf "%.1f", (p>0? n/p : 0)}')
echo "  запущено и снято подов: $_w62_churn_n; алертов от рантайм-comm: $_w62_churn_n_alerts → $_w62_per_pod на под"
echo "$_w62_churn" | jq -r 'group_by(.rule_id)|map({r:.[0].rule_id,n:length})|sort_by(-.n)[]|"    \(.r): \(.n)"' 2>/dev/null | head -20
echo "  6.2.6: величина без порога (постановка 6.2) — вход для сужения в следующей волне, а не вердикт"

echo "--- уборка ---"
"$W62_KUBECTL" -n "$W62_NS" delete pod w62-token-probe --ignore-not-found --wait=false >/dev/null 2>&1

echo
echo "=== ИТОГ КОНТРОЛЕЙ ВОЛНЫ 6.2: проваленных $WAVE62_FAILS ==="
[ "$WAVE62_FAILS" -gt 0 ] && echo "вердикты: $W62_VERDICTS"
exit 0
