#!/bin/bash
# w81-h5-smoke-report.sh <каталог смока> — вердикт по фазам w81-h5-smoke.sh.
# Дельты метрик — по ПОЛНОМУ имени серии с лейблами (память
# metric-anchor-must-carry-full-series-name); пустой снимок — НЕИЗМЕРИМ, а не
# ноль (память empty-metric-snapshot-is-silently-zero).
set -u
OUT=${1:?каталог смока}
fail=0

# val <файл> <имя серии>{<лейбл=...>,...} — сумма серий с этим именем, у
# которых есть КАЖДЫЙ названный лейбл (порядок лейблов client_golang сортирует
# сам, память metric-label-added-breaks-awk-anchors).
val() {
    awk -v spec="$2" '
        BEGIN { i = index(spec, "{"); name = substr(spec, 1, i - 1) "{"
                rest = substr(spec, i + 1); sub(/}$/, "", rest); n = split(rest, want, ",") }
        index($0, name) != 1 { next }
        { lab = substr($0, length(name) + 1); lab = "," substr(lab, 1, index(lab, "}") - 1) ","
          for (k = 1; k <= n; k++) if (index(lab, "," want[k] ",") == 0) next
          s += $NF; m++ }
        END { if (m) print s + 0; else print "" }' "$1"
}
delta() { # <f0> <f1> <серия>
    local a b
    [ -s "$1" ] && [ -s "$2" ] || { echo "НЕИЗМ"; return; }
    a=$(val "$1" "$3"); b=$(val "$2" "$3")
    echo $(( ${b:-0} - ${a:-0} ))
}
ATT='ebpf_guard_incidents_total{verdict="attack"}'
exc() { echo "ebpf_guard_rule_exceptions_total{exception_name=\"$2\",rule_id=\"$1\"}"; }
impact='ebpf_guard_alerts_total{rule_id="impact_systemd_service_disabled"}'
initp='ebpf_guard_alerts_total{rule_id="container_escape_init_proc"}'

for ph in A E F; do
    D="$OUT/$ph"
    [ -d "$D" ] || continue
    echo "== фаза $ph ($(cat "$D/target")): $(cat "$D/command")"
    if [ -f "$D/skipped" ]; then echo "  НЕИЗМЕРИМ: $(cat "$D/skipped")"; fail=1; continue; fi
    c=$(delta "$D/mC0.txt" "$D/mC1.txt" "$ATT"); e=$(delta "$D/mE0.txt" "$D/mE1.txt" "$ATT")
    echo "  attack-инцидентов: окно C $c, окно E $e"
    echo "  impact_systemd_service_disabled в E: $(delta "$D/mE0.txt" "$D/mE1.txt" "$impact")"
    echo "  container_escape_init_proc в E: $(delta "$D/mE0.txt" "$D/mE1.txt" "$initp")"
    for p in "container_escape_init_proc apt-method-init-cgroup" "container_escape_init_proc node-timer-detect-virt" \
             "mitre_vm_detect_dmi_read virt-detect-self" "container_escape_kmem_access fwupd-hardware-probe"; do
        set -- $p
        echo "  исключение $2 ($1) в E: $(delta "$D/mE0.txt" "$D/mE1.txt" "$(exc "$1" "$2")")"
    done
    for r in resolved unresolved no_resolver; do
        printf '  systemd_unit_lookups{%s} в E: %s\n' "$r" "$(delta "$D/mE0.txt" "$D/mE1.txt" "ebpf_guard_systemd_unit_lookups_total{result=\"$r\"}")"
    done
    # Инциденты окна E: корень, юнит, вердикт, счёт.
    t0=$(cat "$D/tE0"); t1=$(cat "$D/tE1")
    jq -r --argjson a "$t0" --argjson b "$t1" '
        (if type == "array" then . else (.incidents // .items // []) end)[]
        | select(((.first_seen // .FirstSeen) | sub("\\.[0-9]+";"") | fromdateiso8601) as $t | $t >= $a and $t <= $b)
        | "  инцидент \(.root_comm // .RootComm // "?") юнит=\(.root_unit // .RootUnit // "-") verdict=\(.verdict // .Verdict) score=\(.score // .Score) правил=\((.rule_ids // .RuleIDs // []) | length)"' \
        "$D/incidents.json" 2>/dev/null | sort | uniq -c | sort -rn | head -12
    case "$e" in
        0) echo "  ВЕРДИКТ $ph: ДОСТИГНУТО (attack в окне события 0)";;
        НЕИЗМ) echo "  ВЕРДИКТ $ph: НЕИЗМЕРИМ (пустой снимок)"; fail=1;;
        *) echo "  ВЕРДИКТ $ph: ПРОВАЛЕН (attack в окне события $e)"; fail=1;;
    esac
    case "$ph" in
        A) echo "  штампы: до $(awk '{print $2}' "$D/stamps-before.txt" 2>/dev/null | tr '\n' ' ')→ после $(awk '{print $2}' "$D/stamps-after.txt" 2>/dev/null | tr '\n' ' ')→ возвращены $(awk '{print $2}' "$D/stamps-restored.txt" 2>/dev/null | tr '\n' ' ')"
           grep -h -m3 -iE 'esm|news|Hit:|Get:|Fetched' "$D"/journal-*.txt 2>/dev/null | sed 's/^/    /' | head -6;;
    esac
done

D="$OUT/P"
if [ -d "$D" ]; then
    echo "== фаза P (положительные контроли)"
    sed 's/^/  /' "$D/steps.txt"
    P1=$(jq '[.[] | select((.details.base_rule_id // .rule_id) == "impact_systemd_service_disabled") | select(.comm == "systemctl")] | length' "$D/alerts.json")
    P1s=$(jq '[.[] | select((.details.base_rule_id // .rule_id) == "impact_systemd_service_disabled") | select((.details["proc.args"] // "") | test("stop w81h5-dummy"))] | length' "$D/alerts.json")
    P2=$(jq '[.[] | select((.details.base_rule_id // .rule_id) == "impact_systemd_service_disabled") | select((.details["proc.args"] // "") | . == "" or test("w81h5-dummy2"))] | length' "$D/alerts.json")
    P2a=$(jq -r '[.[] | select((.details.base_rule_id // .rule_id) == "impact_systemd_service_disabled") | select((.details["proc.args"] // "") | . == "" or test("w81h5-dummy2")) | (.details["proc.args"] // "")] | map(if . == "" then "<пусто>" else . end) | join(" | ")' "$D/alerts.json")
    N1=$(jq '[.[] | select((.details.base_rule_id // .rule_id) == "impact_systemd_service_disabled") | select((.details["proc.args"] // "") | test("is-active"))] | length' "$D/alerts.json")
    P3=$(jq '[.[] | select((.details.base_rule_id // .rule_id) == "container_escape_init_proc") | select(.comm | startswith("systemd-detect"))] | length' "$D/alerts.json")
    P4=$(jq '[.[] | select((.details.base_rule_id // .rule_id) == "container_escape_init_proc") | select(.comm == "http")] | length' "$D/alerts.json")
    echo "  P1 systemctl stop → impact: $P1s (всего impact от systemctl: $P1)"
    echo "  P2 exec -a systemctl stop → impact: $P2 (proc.args: ${P2a:-нет})"
    echo "  N1 systemctl is-active без спуфа → impact: $N1 (обязано быть 0)"
    [ "$N1" -eq 0 ] || { echo "  КОНТРОЛЬ N1: ПРОВАЛЕН (предикат не сужает)"; fail=1; }
    echo "  P3 detect-virt в недоверенном юните → init_proc: $P3"
    echo "  P4 /var/tmp/http → init_proc: $P4"
    for x in "P1:$P1s" "P2:$P2" "P3:$P3" "P4:$P4"; do
        [ "${x#*:}" -ge 1 ] 2>/dev/null || { echo "  КОНТРОЛЬ ${x%%:*}: ПРОВАЛЕН (правило ослеплено)"; fail=1; }
    done
fi
exit $fail
