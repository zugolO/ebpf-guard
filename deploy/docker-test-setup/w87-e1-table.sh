#!/bin/bash
# Волна 8.7, заход Е1: таблица «CPU по стадиям» из профилей с меткой stage.
#   w87-e1-table.sh <BIN> <имя> <pprof...>   — профили СЛИВАЮТСЯ (pprof принимает несколько файлов).
#   Печатает: всего сэмплов; по каждой стадии секунды и доля ОТ ВСЕХ сэмплов; остаток «без метки»
#   (рантайм, GC, планировщик, горутины без стадии). Вердикта не даёт: вход решения Д15.
set -u
BIN=${1:?BIN или -}; NAME=${2:?имя}; shift 2
[ $# -ge 1 ] || { echo "нет профилей" >&2; exit 2; }
go tool pprof -tags $([ "$BIN" = - ] || echo "$BIN") "$@" 2> /dev/null | awk -v name="$NAME" -v tk="${TAGKEY:-stage}" '
    function secs(x) { v = x + 0; if (x ~ /ms$/) v /= 1000; else if (x ~ /us$/) v /= 1e6; else if (x ~ /m$/ && x !~ /ms$/) v *= 60; return v }
    /^ *[a-z_]+: Total / {
        key = $1; sub(/:$/, "", key); instage = (key == tk)
        if (instage) { tot = secs($5); lab = secs($3) }
        next
    }
    instage && /\([ 0-9.]+%\):/ {
        s = $1; stage = $NF; rows[stage] = secs(s); order[++n] = stage
    }
    END {
        if (tot == 0) { print "# " name ": меток " tk " в профиле нет"; exit 3 }
        printf "# %s: всего сэмплов %.2f с, с меткой %s %.2f с (%.1f%%)\n", name, tot, tk, lab, 100 * lab / tot
        for (i = 1; i <= n; i++) printf "%-22s %8.2f с %6.2f%%\n", order[i], rows[order[i]], 100 * rows[order[i]] / tot
        printf "%-22s %8.2f с %6.2f%%\n", "(без метки)", tot - lab, 100 * (tot - lab) / tot
    }'
