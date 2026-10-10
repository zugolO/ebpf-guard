#!/bin/bash
# w83-smoke-report.sh <каталог смока> — вердикт по фазам w83-smoke.sh (долги 8.3: 8.3.1, 8.3.2, 8.3.3).
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
alerts() { echo "ebpf_guard_alerts_total{rule_id=\"$1\"}"; }
dedup() { echo "ebpf_guard_alerts_dedup_dropped_by_rule_total{rule_id=\"$1\"}"; }
rl() { echo "ebpf_guard_alerts_ratelimited_by_rule_total{rule_id=\"$1\"}"; }
SOFT="mitre_vm_detect_dmi_read mitre_sandbox_detect_proc_read sigma_memory_proc_dump sigma_cpu_info_access"
EXCS="mitre_vm_detect_dmi_read:node-timer-detect-virt mitre_sandbox_detect_proc_read:node-timer-detect-virt sigma_memory_proc_dump:node-timer-detect-virt sigma_cpu_info_access:node-timer-detect-virt evasion_hidden_elf_in_tmp:apt-gpgv-tmp-unit evasion_hidden_elf_in_tmp:apt-key-gpghome-unit evasion_hidden_elf_in_tmp:apt-gpgv-method-tmp impact_systemd_service_disabled:deb-systemd-invoke-stop"

# Объём «правило выпущено + дедуп + лимитер» (цена правила) в окне и подавления исключениями.
phase_report() { # <фаза> <каталог>
    local ph="$1" D="$2" c e r x
    echo "== фаза $ph ($(cat "$D/target" 2>/dev/null)): $(cat "$D/command" 2>/dev/null)"
    if [ -f "$D/skipped" ]; then echo "  НЕИЗМЕРИМ: $(cat "$D/skipped")"; fail=1; return; fi
    c=$(delta "$D/mC0.txt" "$D/mC1.txt" "$ATT"); e=$(delta "$D/mE0.txt" "$D/mE1.txt" "$ATT")
    echo "  attack-инцидентов: окно C $c, окно E $e"
    for r in evasion_hidden_elf_in_tmp impact_systemd_service_disabled $SOFT; do
        printf '  %-36s выпущено C/E %s/%s  дедуп C/E %s/%s  лимитер C/E %s/%s\n' "$r" \
            "$(delta "$D/mC0.txt" "$D/mC1.txt" "$(alerts $r)")" "$(delta "$D/mE0.txt" "$D/mE1.txt" "$(alerts $r)")" \
            "$(delta "$D/mC0.txt" "$D/mC1.txt" "$(dedup $r)")" "$(delta "$D/mE0.txt" "$D/mE1.txt" "$(dedup $r)")" \
            "$(delta "$D/mC0.txt" "$D/mC1.txt" "$(rl $r)")" "$(delta "$D/mE0.txt" "$D/mE1.txt" "$(rl $r)")"
    done
    for x in $EXCS; do
        printf '  исключение %s (%s) в E: %s\n' "${x#*:}" "${x%%:*}" "$(delta "$D/mE0.txt" "$D/mE1.txt" "$(exc "${x%%:*}" "${x#*:}")")"
    done
    for r in resolved unresolved no_resolver; do
        printf '  systemd_unit_lookups{%s} в E: %s\n' "$r" "$(delta "$D/mE0.txt" "$D/mE1.txt" "ebpf_guard_systemd_unit_lookups_total{result=\"$r\"}")"
    done
    for f in exe_path parent_exe_path; do
        printf '  exe_path_lookups{%s,unresolved/resolved} в E: %s/%s\n' "$f" \
            "$(delta "$D/mE0.txt" "$D/mE1.txt" "ebpf_guard_exe_path_lookups_total{field=\"$f\",result=\"unresolved\"}")" \
            "$(delta "$D/mE0.txt" "$D/mE1.txt" "ebpf_guard_exe_path_lookups_total{field=\"$f\",result=\"resolved\"}")"
    done
    # Остаток алертов окна по правилам и comm — что осталось без оси.
    jq -r --argjson a "$(cat "$D/tE0")" --argjson b "$(cat "$D/tE1")" '
        (if type=="array" then . else (.alerts // []) end)[]
        | select((.details.base_rule_id // .rule_id) | IN("evasion_hidden_elf_in_tmp","impact_systemd_service_disabled","mitre_vm_detect_dmi_read","mitre_sandbox_detect_proc_read","sigma_memory_proc_dump","sigma_cpu_info_access"))
        | "    остаток \((.details.base_rule_id // .rule_id)) comm=\(.comm // "?") \((.details.filename // .details["file.path"] // .details["proc.args"] // "") | .[0:60])"' \
        "$D/alerts-CE.json" 2>/dev/null | sort | uniq -c | sort -rn | head -12
}

for ph in A E; do
    D="$OUT/$ph"; [ -d "$D" ] || continue
    phase_report "$ph" "$D"
    case "$ph" in
        A) echo "  штампы: до $(awk '{print $2}' "$D/stamps-before.txt" 2>/dev/null | tr '\n' ' ')→ после $(awk '{print $2}' "$D/stamps-after.txt" 2>/dev/null | tr '\n' ' ')→ возвращены $(awk '{print $2}' "$D/stamps-restored.txt" 2>/dev/null | tr '\n' ' ')"
           h=$(delta "$D/mE0.txt" "$D/mE1.txt" "$(exc evasion_hidden_elf_in_tmp apt-gpgv-tmp-unit)")
           k=$(delta "$D/mE0.txt" "$D/mE1.txt" "$(exc evasion_hidden_elf_in_tmp apt-key-gpghome-unit)")
           case "$h$k" in *НЕИЗМ*) echo "  ВЕРДИКТ 8.3.3: НЕИЗМЕРИМ"; fail=1;;
               *) if [ "${h:-0}" -ge 1 ] || [ "${k:-0}" -ge 1 ]; then echo "  ВЕРДИКТ 8.3.3: ДОСТИГНУТО (исключения юнита подавили gpgv=$h apt-key=$k)"
                  else echo "  ВЕРДИКТ 8.3.3: ПРОВАЛЕН/НЕ ВОСПРОИЗВЕДЕНО (исключения юнита подавили 0 — событие не дало формы или ось не сработала; смотри остаток выше)"; fail=1; fi;; esac;;
        E) v=0
           for r in $SOFT; do n=$(delta "$D/mE0.txt" "$D/mE1.txt" "$(exc $r node-timer-detect-virt)"); [ "${n:-0}" != НЕИЗМ ] && [ "${n:-0}" -ge 1 ] && v=$((v+1)); done
           echo "  ВЕРДИКТ 8.3.2: исключение node-timer-detect-virt сработало на $v из 4 мягких правил (форма — что detect-virt успел прочитать в этом тике)";;
    esac
done

D="$OUT/I"
if [ -d "$D" ]; then
    phase_report I "$D"
    echo "  шебанг deb-systemd-invoke / perl: $(tr '\n' ' ' < "$D/invoke-shebang.txt")"
    echo "  итог пакета: $(grep -E 'rc=' "$D/pkg.log" | tr '\n' ' ')"
    echo "  состояние после: $(tr '\n' ' ' < "$D/dpkg-after.txt")"
    echo "  свидетель образа родителя (systemctl со stop):"
    grep -E 'args=[^ ]* *(--[a-z-]+ )*stop' "$D/parent-sampler.txt" | sed 's/^[0-9.]* //' | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    stops=$(grep -cE 'args=[^ ]* *(--[a-z-]+ )*stop' "$D/parent-sampler.txt")
    img=$(grep -E 'args=[^ ]* *(--[a-z-]+ )*stop' "$D/parent-sampler.txt" | sed -n 's/.*parent_exe=\([^ ]*\).*/\1/p' | sort | uniq -c | sort -rn | head -3 | tr '\n' ';')
    s=$(delta "$D/mE0.txt" "$D/mE1.txt" "$(exc impact_systemd_service_disabled deb-systemd-invoke-stop)")
    i=$(delta "$D/mE0.txt" "$D/mE1.txt" "$(alerts impact_systemd_service_disabled)")
    echo "  замечено systemctl stop сэмплером: $stops; образы родителя: ${img:-нет}"
    if [ "$stops" -eq 0 ]; then echo "  ВЕРДИКТ 8.3.1: НЕИЗМЕРИМ (сэмплер не поймал stop — событие не воспроизведено)"; fail=1
    elif [ "${s:-0}" != НЕИЗМ ] && [ "${s:-0}" -ge 1 ] && [ "${i:-0}" = 0 ]; then echo "  ВЕРДИКТ 8.3.1: ДОСТИГНУТО (исключение deb-systemd-invoke-stop подавило $s, impact выпущено 0)"
    else echo "  ВЕРДИКТ 8.3.1: ПРОВАЛЕН (исключение подавило ${s:-?}, impact выпущено ${i:-?}; образ родителя — см. выше: ожидали /usr/bin/deb-systemd-invoke)"; fail=1; fi
fi

D="$OUT/P"
if [ -d "$D" ]; then
    echo "== фаза P (положительные контроли)"
    sed 's/^/  /' "$D/steps.txt"
    cnt() { jq --arg r "$1" --arg f "${2:-}" '[.[] | select((.details.base_rule_id // .rule_id) == $r) | select(($f == "") or ((.comm // "") | startswith($f)) or ((.details["proc.args"] // "") | test($f)) or ((.details.filename // .details["file.path"] // "") | test($f)))] | length' "$D/alerts.json"; }
    P1=$(cnt impact_systemd_service_disabled "stop w83-dummy\.service"); P2=$(cnt impact_systemd_service_disabled "stop w83-dummy2"); P3=$(cnt impact_systemd_service_disabled "stop w83-dummy3")
    echo "  P1 голый stop → impact: $P1; P2 stop из копии deb-systemd-invoke: $P2; P3 stop из perl: $P3"
    for r in $SOFT; do echo "  P4 detect-virt в недоверенном юните → $r: $(cnt $r systemd-detect)"; done
    P5=$(cnt evasion_hidden_elf_in_tmp "apt-key-gpghome"); echo "  P5/P6 запись apt-key-формы вне apt-daily → hidden_elf: $P5"
    for x in "P1:$P1" "P2:$P2" "P3:$P3" "P5:$P5"; do
        [ "${x#*:}" -ge 1 ] 2>/dev/null || { echo "  КОНТРОЛЬ ${x%%:*}: ПРОВАЛЕН (правило ослеплено)"; fail=1; }
    done
    for r in $SOFT; do
        n=$(cnt $r systemd-detect)
        [ "$n" -ge 1 ] 2>/dev/null && echo "  КОНТРОЛЬ P4/$r: ДОСТИГНУТО ($n)" || echo "  КОНТРОЛЬ P4/$r: 0 (detect-virt это правило не читает — не провал, форма см. фазу E)"
    done
fi
exit $fail
