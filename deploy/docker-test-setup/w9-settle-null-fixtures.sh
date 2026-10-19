#!/bin/bash
# Фикстуры решения Е4(2) (волна 9, заход A): settle-луп mode=null и критерий 5.9.8f.
# Настоящий counting_settle_loop и sum_metric извлекаются sed-ом из attacks/run-all-attacks.sh (не копии);
# curl/date/sleep подменены функциями — ряд метрик и часы задаются фикстурой, стенд не нужен.
#   w9-settle-null-fixtures.sh [--mutate]     bash 4+
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${SRC:-$HERE/attacks/run-all-attacks.sh}
GATE=${GATE:-$HERE/attacks/run-gate.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
sed -n '/^sum_metric() {/,/^}/p' "$SRC" > "$T/sum.sh"
sed -n '/^counting_settle_loop() {/,/^}/p' "$SRC" > "$T/loop.sh"
[ -s "$T/sum.sh" ] && [ -s "$T/loop.sh" ] || { echo "die: функции не извлечены из $SRC"; exit 2; }

# loop <режим> <ряд> [null-маркер] — печатает «причина итерации». Ряд: темп событий/с по срезам через запятую
# (повторяется последним значением); «none» — /metrics не отвечает.
loop() {
    local mode=$1 rates=$2 marker=${3:-$T/no-marker}
    (
        source "$T/sum.sh"; source "$T/loop.sh"
        NOW=1000; IFS=, read -r -a R <<< "$rates"
        S=$(mktemp); echo "0 0" > "$S"        # CUR CALL — файл: curl зовётся в подоболочке подстановки
        date() { echo "$NOW"; }
        sleep() { NOW=$((NOW + 1)); }
        curl() {
            [ "${R[0]}" = none ] && return 0
            local cur call r; read -r cur call < "$S"
            r=${R[$call]:-${R[$((${#R[@]} - 1))]}}; cur=$((cur + r)); echo "$cur $((call + 1))" > "$S"
            echo "ebpf_guard_events_total{type=\"file\"} $cur"
            echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\"} 0"
        }
        export EBPF_GUARD_TOKEN=x EBPF_GUARD_API=http://x
        counting_settle_loop "$mode" 30 0 1000 "$marker"
        echo "$SETTLE_REASON $SETTLE_I"
    )
}
w() { local got; got=$(echo "$3" | tail -1); if [ "$got" = "$2" ]; then ok "$1"; else bad "$1 — ожидалось «$2», получено «${got}»"; fi; }

# ── settle-луп ────────────────────────────────────────────────────────────────
w null-flat-no-early-exit  "background_window 30" "$(loop null 100)"                                    # ровный фон: старый луп вышел бы flattened на 4-м срезе
w null-bursty-background   "background_window 30" "$(loop null 300,300,4000,300,300,3800,300,300,300,3900)"  # волнистый фон стенда (229…3826): прежде — монетка
w null-timeout-kept        "timeout 3"            "$(loop null none)"                                   # /metrics молчит — это не окно фона
echo "background_window" > /dev/null
printf 'sum=1000\nwindow_seconds=10\n' > "$T/marker"
w idle-flat-flattened      "flattened 2"          "$(loop idle 100 "$T/marker")"                        # режим с внешним фоном — прежнее поведение
w idle-never-ceiling       "ceiling 30"           "$(loop idle 5000 "$T/marker")"                       # сходиться нечему — ceiling остаётся честным
w nonnull-no-marker-flat   "flattened 4"          "$(loop ringbuf_overflow 100)"                        # без null-маркера окно трёх темпов, как раньше

# ── критерий 5.9.8f в run-gate.sh ──────────────────────────────────────────────
sed -n '/^echo "=== 5.9.8f. settle_reason/,/^echo ""$/p' "$GATE" > "$T/c.sh"
[ -s "$T/c.sh" ] || { echo "die: блок 5.9.8f не извлечён из $GATE"; exit 2; }
crit() { # <null> <idle> <ringbuf|-> — маркеры с этими settle_reason; печатает итоговую строку PASS/FAIL/SKIP
    local d=$T/crit.$RANDOM; mkdir -p "$d"
    printf 'settle_reason=%s\n' "$1" > "$d/counting-control-null-X.txt"
    [ "$2" != "-" ] && printf 'settle_reason=%s\n' "$2" > "$d/counting-control-idle-X.txt"
    local rb=""; [ "$3" != "-" ] && { printf 'settle_reason=%s\n' "$3" > "$d/rb.txt"; rb=$d/rb.txt; }
    ( RESULTS_DIR=$d TIMESTAMP=X ringbuf_overflow_marker=$rb
      record_covered() { :; }; pass() { echo "PASS $*"; }; fail() { echo "FAIL $*"; }; skip() { echo "SKIP $*"; }
      source "$T/c.sh" ) 2>&1 | grep -aE '^(PASS|FAIL|SKIP)'
}
w c-null-ceiling-old-harness-not-judged "PASS ни один из 2 проверенных маркеров settle-лупа не докрутил до потолка (5.9.8f, №93)" "$(crit ceiling flattened flattened)"   # старый харнесс: null=ceiling — не провал
w c-null-background-window              "PASS ни один из 2 проверенных маркеров settle-лупа не докрутил до потолка (5.9.8f, №93)" "$(crit background_window flattened flattened)"
o=$(crit background_window ceiling flattened); case "$o" in "FAIL 1 из 2 "*) ok "c-idle-ceiling-fails";; *) bad "c-idle-ceiling-fails — «${o}»";; esac
o=$(crit background_window flattened ceiling); case "$o" in "FAIL 1 из 2 "*) ok "c-ringbuf-ceiling-fails";; *) bad "c-ringbuf-ceiling-fails — «${o}»";; esac
o=$(crit ceiling - - 2>/dev/null); case "$o" in SKIP*) ok "c-null-alone-is-unjudged";; *) bad "c-null-alone-is-unjudged — «${o}»";; esac

# ── мутации ────────────────────────────────────────────────────────────────────
if [ "${1:-}" = --mutate ]; then
    mut() { # <имя> <файл-источник> <sed>
        local f; f=$(mktemp); sed "$3" "$2" > "$f"
        if cmp -s "$f" "$2"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        local env; case "$2" in "$SRC") env="SRC=$f";; *) env="GATE=$f";; esac
        if env "$env" bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi
        rm -f "$f"
    }
    mut null-early-exit   "$SRC"  's/if \[ "\$mode" != "null" \] \&\& awk -v s="\$spread"/if awk -v s="$spread"/'
    mut null-ceiling-name "$SRC"  's/SETTLE_REASON="background_window"/SETTLE_REASON="ceiling"/'
    mut null-no-rename    "$SRC"  's/if \[ "\$mode" = "null" \] \&\& \[ "\$SETTLE_REASON" = "ceiling" \]; then/if false; then/'
    mut gate-judges-null  "$GATE" 's/if \[ "\$settle_label" = "null" \]; then/if false; then/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
