#!/bin/bash
# wave6.3.9f-item3-baseline-controls.sh — опорный набор положительных
# контролей детекта (item 3 волны 6.3.9.F, находка №370/item 5 постановки
# волны 6.3.9).
#
# ЗАЧЕМ. `6.3.9.5` («ни один положительный контроль детекта не потерян»)
# сравнивает прогон B с чем-то — а на прогоне A (`collect-6.3-run6`) опорный
# снимок не был снят вовсе (находка №370: единственный контроль в архиве —
# `6.2.6.4`). Без него `6.3.9.5` на прогоне B выносит НЕИЗМЕРИМ, а
# неизмеримость этой метки отменяет снижение шума при ЛЮБОЙ величине.
# Постановка требует снять набор ВХОДОМ волны, ДО правки досева item 4 —
# этот скрипт и есть тот вход; он запускается ещё раз, без изменений, ПОСЛЕ
# правки (прогон B) для сравнения.
#
# СОСТАВ (постановка волны 6.3.9, item 5): 6.0.13…6.0.18, DNS-манифест
# (6.3.1), спуф argv[0], container_escape_proc_write, длинная метка 5.9.5c.
# 6.0.13…6.0.18 УЖЕ несут внутри себя container_escape_proc_write (=6.0.15)
# и спуф argv[0] (=6.0.16/6.0.17) — готовый `wave7-controls.sh` (волна 6.0m)
# исполняет все шесть, и здесь он переиспользуется как есть, а не
# переписывается: другой контроль на ту же находку был бы вторым источником
# дефектов вместо одного. Своих тел этот файл заводит два — 5.9.5c и 6.3.1,
# ни один из которых wave7-controls.sh не несёт.
#
# ГИГИЕНА КОНТРОЛЕЙ (см. память):
#   - каждый контроль несёт СВОЙ сторож результата, не код возврата
#     ([[positive-control-needs-result-sentinel]]);
#   - провал одного контроля не валит набор — die() здесь пишет строку и
#     продолжает, как в wave7-controls.sh ([[die-only-for-unmeasurable-run]]);
#   - артефакты — вне /root/ ([[control-artifacts-must-live-outside-root]]:
#     /root/ живёт под drift-правилом, и собственные файлы набора создавали
#     бы алерты в чужом окне, если бы прогон B делил с ним измерение);
#   - `set -u`, без `set -e` — ЭТОТ файл сам исполняется (`bash …`), не
#     source'ится, так что даже `set -e` не утёк бы наружу
#     ([[sourcing-lib-leaks-set-e]]), но и внутри он не нужен: die()
#     обязана позволить соседним контролям исполниться.
set -u
export PATH="$PATH:/usr/local/bin:/usr/local/go/bin"

SETUP="${SETUP:-/opt/ebpf-guard/deploy/docker-test-setup}"
VPS_IP="${VPS_IP:-localhost}"
W3_API="${W3_API:-http://${VPS_IP}:19090}"
W3_TOKEN="${W3_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
W3_KUBECTL="${W3_KUBECTL:-/usr/local/bin/kubectl}"
W3_NS="${W3_NS:-w639f3}"
W3_POD="${W3_POD:-w639f3-dns-probe}"
W3_MANIFEST="${W3_MANIFEST:-$SETUP/attacks/dns-rule-ids.txt}"

# Артефакты вне /root/ (память control-artifacts-must-live-outside-root).
W3_ART="${W3_ART:-/var/lib/w639f3-item3-artifacts}"
mkdir -p "$W3_ART" 2>/dev/null || true
# ФАЙЛ ВЕРДИКТОВ — СВОЙ НА КАЖДЫЙ ЗАПУСК, И СТАРЫЙ НЕ ЗАТИРАЕТСЯ.
#
# Набор исполняется ДВАЖДЫ по построению: опорный снимок (прогон A2, бинарь БЕЗ
# досева) и проверочный (прогон B, бинарь С досевом) — а `6.3.9.5` сравнивает
# один с другим. Фиксированное имя файла + `: >` означало бы, что второй запуск
# СТИРАЕТ то единственное, с чем обязан сравниваться, и метка вынесла бы
# НЕИЗМЕРИМ по вине самого прибора — ровно цена, которую находка №370 уже
# однажды предъявила волне. Поэтому имя несёт метку запуска, а `-latest`
# (копия, не симлинк: архив собирается `cp`) указывает на последний.
W3_TAG="${W3_TAG:-$(date -u +%Y%m%dT%H%M%SZ)}"
# РОЛЬ ЗАПУСКА — ВХОД КРИТЕРИЯ 6.3.9.5, А НЕ ПОДПИСЬ ДЛЯ ЧИТАТЕЛЯ.
#   baseline — снят на бинаре БЕЗ досева (прогон A2, вход волны);
#   check    — снят на бинаре С досевом (прогон B), сравнивается с baseline.
# Каждая роль пишет НОРМАЛИЗОВАННЫЙ реестр «<критерий> OK|FAIL» — по образцу
# emitted-labels.txt рантайма контролей: класс берётся из реестра, а не
# восстанавливается регэкспом по словам вердиктного текста (item 9 стража
# полноты — эвристика по словам верна ровно до первого объяснения, упомянувшего
# чужое вердиктное слово). Реестр роли baseline НЕ перезаписывается молча:
# затереть опорный снимок значит сделать 6.3.9.5 неизмеримой прибором.
W3_ROLE="${W3_ROLE:-baseline}"
case "$W3_ROLE" in
    baseline|check) ;;
    *) echo "=== ОТКАЗ: W3_ROLE=$W3_ROLE — допустимы baseline (прогон A2, БЕЗ досева) и check (прогон B, С досевом) ==="; exit 2 ;;
esac
W3_LABELS="${W3_LABELS:-$W3_ART/baseline-labels-$W3_ROLE.txt}"
if [ -e "$W3_LABELS" ] && [ "${W3_FORCE:-0}" != "1" ]; then
    echo "=== ОТКАЗ: реестр роли $W3_ROLE уже существует ($W3_LABELS). Перезапись стёрла бы снимок, с которым сравнивается 6.3.9.5; W3_FORCE=1 — только осознанно ==="
    exit 2
fi
: > "$W3_LABELS" 2>/dev/null || true
_w3_label() { # $1 = критерий (может не вычлениться из текста), $2 = класс
    # Пустой ключ записался бы строкой « FAIL» и при сверке прогона B прочитался
    # бы как «критерий без имени потерян» — безымянная запись обязана иметь имя.
    printf '%s %s\n' "${1:-набор_целиком}" "$2" >> "$W3_LABELS" 2>/dev/null || true
}
W3_VERDICTS="${W3_VERDICTS:-$W3_ART/baseline-controls-verdicts-$W3_TAG.txt}"
if [ -e "$W3_VERDICTS" ]; then
    echo "=== ОТКАЗ: $W3_VERDICTS уже существует — запуск с тем же W3_TAG затёр бы опорный снимок, с которым сравнивается 6.3.9.5. Задайте другой W3_TAG ==="
    exit 2
fi
: > "$W3_VERDICTS" 2>/dev/null || true
W3_DONE="${W3_DONE:-$W3_ART/DONE-$W3_TAG}"
rm -f "$W3_DONE" 2>/dev/null || true

W3_FAILS=0
die() {
    echo "=== ОПОРНЫЙ КОНТРОЛЬ ПРОВАЛЕН/НЕИЗМЕРИМ (набор продолжается): $* ==="
    W3_FAILS=$((W3_FAILS + 1))
    _w3_label "$(printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*[a-z]?' | head -1)" FAIL
    {
        echo "критерий=$(printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*[a-z]?' | head -1)"
        echo "время_UTC=$(date -u +%FT%TZ)"
        echo "причина: $*"
        echo "---"
    } >> "$W3_VERDICTS" 2>/dev/null || true
}
pass() {
    echo "=== $* ==="
    _w3_label "$(printf '%s' "$*" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*[a-z]?' | head -1)" OK
    { echo "$*"; echo "время_UTC=$(date -u +%FT%TZ)"; echo "---"; } >> "$W3_VERDICTS" 2>/dev/null || true
}

echo "# wave6.3.9f-item3-baseline-controls.sh, прогон от $(date -u +%FT%TZ)" >> "$W3_VERDICTS"
echo "=== ОПОРНЫЙ НАБОР ПОЛОЖИТЕЛЬНЫХ КОНТРОЛЕЙ (item 3 волны 6.3.9.F, находка №370) ==="
echo "HEAD: $(cd "$SETUP/../.." 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo '?')"

if [ -z "${W3_TOKEN:-}" ]; then
    die "ОПОРНЫЙ НАБОР НЕИЗМЕРИМ ЦЕЛИКОМ: bearer-токен агента не найден (/var/lib/ebpf-guard/token) — ни один HTTP-контроль не исполним"
fi

_alerts() { curl -s --max-time 20 -H "Authorization: Bearer $W3_TOKEN" "$W3_API/api/v1/alerts?limit=200000" 2>/dev/null; }
_rule_count() { # $1=rule_id
    _alerts | jq --arg r "$1" '[.[]|select(.rule_id==$r)]|length' 2>/dev/null || echo 0
}

echo
echo "--- 6.0.13…6.0.18 (container_escape_proc_write=6.0.15, argv[0]-спуф=6.0.16/6.0.17): переиспользуем wave7-controls.sh как есть ---"
if [ -r "$SETUP/wave7-controls.sh" ]; then
    W3_W7_VERDICTS="$W3_ART/wave7-verdicts-$W3_TAG.txt"
    DRIFT_PC_API="$W3_API" DRIFT_PC_TOKEN="$W3_TOKEN" WAVE7_VERDICTS="$W3_W7_VERDICTS" \
        bash "$SETUP/wave7-controls.sh" 2>&1 | sed 's/^/  [6.0h\/k\/l] /'
    if [ -s "$W3_W7_VERDICTS" ] && grep -q '^критерий=' "$W3_W7_VERDICTS"; then
        _w7_fail_ids=$(grep '^критерий=' "$W3_W7_VERDICTS" | cut -d= -f2 | sort -u | tr '\n' ' ')
        die "6.0.13…6.0.18: wave7-controls.sh записал провалы/неизмеримость по: ${_w7_fail_ids}(подробности — $W3_W7_VERDICTS)"
    else
        pass "6.0.13…6.0.18 ДОСТИГНУТО: wave7-controls.sh отработал без единой записи провала (container_escape_proc_write=6.0.15, argv[0]-спуф=6.0.16/6.0.17 включены в этот же прогон)"
    fi
else
    die "6.0.13…6.0.18 НЕИЗМЕРИМ: $SETUP/wave7-controls.sh не найден на стенде"
fi

echo
echo "--- 5.9.5c: длинная/высокоэнтропийная DNS-метка с ноды ---"
if ! command -v dig >/dev/null 2>&1; then
    die "5.9.5c НЕИЗМЕРИМ: dig недоступен на стенде"
else
    _593c_rules="dns_tunneling_long_domain exfil_dns_txt_long_label netintr_dns_long_label webshell_dns_exfil_long_subdomain"
    for r in $_593c_rules; do
        v=$(_rule_count "$r")
        eval "_593c_before_${r}=\${v:-0}"
    done
    _593c_filler_a=$(printf 'x%.0s' $(seq 1 60))
    _593c_filler_b=$(printf 'y%.0s' $(seq 1 60))
    _593c_qname="${_593c_filler_a}.${_593c_filler_b}.ebpfguard-5951c-w639f3.dns-tunnel-canary.invalid"
    dig +short +time=2 +tries=1 "$_593c_qname" >/dev/null 2>&1
    _593c_rc=$?
    echo "  dig на $_593c_qname выполнен (rc=$_593c_rc, длина qname: ${#_593c_qname})"
    sleep 15
    _593c_hit=0
    _593c_named=""
    for r in $_593c_rules; do
        after=$(_rule_count "$r")
        eval "before=\${_593c_before_${r}:-0}"
        d=$(( ${after:-0} - ${before:-0} ))
        echo "  $r: ${before:-0} -> ${after:-0} (Δ$d)"
        if [ "$d" -gt 0 ]; then _593c_hit=$((_593c_hit + 1)); _593c_named="$_593c_named $r"; fi
    done
    if [ "$_593c_hit" -lt 1 ]; then
        die "5.9.5c ПРОВАЛЕН: длинная метка подана (dig rc=$_593c_rc), ни одно из четырёх правил манифеста не поднялось"
    else
        pass "5.9.5c ДОСТИГНУТО: сработали $_593c_hit/4 правил ($_593c_named)"
    fi
fi

echo
echo "--- 6.3.1: DNS-манифест — длинный/DGA-подобный qname из пода busybox ---"
if [ ! -r "$W3_MANIFEST" ]; then
    die "6.3.1 НЕИЗМЕРИМ: манифест $W3_MANIFEST не читается"
else
    _631_ids=$(grep -v '^#' "$W3_MANIFEST" | grep -v '^[[:space:]]*$')
    _631_ids_sp=$(printf '%s' "$_631_ids" | tr '\n' ' ')
    "$W3_KUBECTL" create namespace "$W3_NS" --dry-run=client -o yaml 2>/dev/null | "$W3_KUBECTL" apply -f - >/dev/null 2>&1
    "$W3_KUBECTL" -n "$W3_NS" delete pod "$W3_POD" --ignore-not-found --wait=true >/dev/null 2>&1
    "$W3_KUBECTL" -n "$W3_NS" run "$W3_POD" --image=busybox:1.36 --restart=Never --command -- sleep 600 >/dev/null 2>&1
    _631_ready=0
    "$W3_KUBECTL" -n "$W3_NS" wait --for=condition=Ready "pod/$W3_POD" --timeout=90s >/dev/null 2>&1 && _631_ready=1
    if [ "$_631_ready" -ne 1 ]; then
        die "6.3.1 НЕИЗМЕРИМ: $W3_POD не поднялся за 90с — подать нагрузку неоткуда"
    else
        _631_label=$(head -c 64 /dev/urandom 2>/dev/null | base64 2>/dev/null | tr -dc 'a-z0-9' | head -c 55)
        [ -z "${_631_label:-}" ] && _631_label="x7k2qv9zwmrl4bnt8pd3jf6hs1ce5ay0gu3kv8wz2mqr7nxb"
        _631_domain="${_631_label}.w639f3-dga-probe.invalid"
        _631_t0=$(date -u +%s)
        _631_out=$("$W3_KUBECTL" -n "$W3_NS" exec "$W3_POD" -- nslookup "$_631_domain" 2>&1)
        echo "  запрошено: $_631_domain (${#_631_domain} симв.)"
        echo "  вывод nslookup (обрезан): $(printf '%s' "${_631_out:-}" | tr '\n' ' ' | cut -c1-200)"
        sleep 15
        _631_hit=$(_alerts | jq --arg ids "$_631_ids_sp" --arg pod "$W3_POD" --argjson t "$_631_t0" \
            '[.[]|select((.rule_id as $r|($ids|split(" "))|index($r)) and ((.enrichment.pod_name // "")==$pod) and ((.timestamp|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601? // 0) >= $t))]' 2>/dev/null)
        _631_n=$(printf '%s' "${_631_hit:-[]}" | jq 'length' 2>/dev/null)
        _631_rules=$(printf '%s' "${_631_hit:-[]}" | jq -r '.[].rule_id' 2>/dev/null | sort -u | tr '\n' ' ')
        echo "  алертов из манифеста от $W3_POD: ${_631_n:-0} (правила: ${_631_rules:-нет})"
        if [ -z "${_631_out:-}" ]; then
            die "6.3.1 НЕИЗМЕРИМ: exec в под не дал вывода — подача не подтверждена"
        elif [ "${_631_n:-0}" -lt 1 ]; then
            die "6.3.1 ПРОВАЛЕН: qname подан ($_631_domain), ни одно правило манифеста не поднялось"
        else
            pass "6.3.1 ДОСТИГНУТО: ${_631_n} алертов из манифеста подняты ($_631_rules)"
        fi
    fi
    "$W3_KUBECTL" -n "$W3_NS" delete pod "$W3_POD" --ignore-not-found --wait=false >/dev/null 2>&1
fi

echo
echo "=== ИТОГ ОПОРНОГО НАБОРА: провалов/неизмеримых = $W3_FAILS ==="
echo "  артефакт: $W3_VERDICTS"
if [ "$W3_FAILS" -gt 0 ]; then
    echo "  ⚠ опорный набор НЕПОЛОН — 6.3.9.5 на прогоне B, сравниваясь с этим снимком, обязана назвать неполные метки НЕИЗМЕРИМЫМИ, а не молчать о них"
fi
echo "$W3_FAILS" > "$W3_DONE"
# Копия под стабильным именем — её и читает прогон B как «последний снятый
# набор»; сам тегированный файл при этом остаётся на месте навсегда.
cp "$W3_VERDICTS" "$W3_ART/baseline-controls-verdicts-latest.txt" 2>/dev/null || true
echo "  последний снимок: $W3_ART/baseline-controls-verdicts-latest.txt (копия $W3_VERDICTS)"
echo "  реестр классов роли $W3_ROLE: $W3_LABELS"
sed 's/^/    /' "$W3_LABELS" 2>/dev/null
