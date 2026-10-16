#!/bin/bash
# w87-profiles.sh — приборы П0 волны 8.7 (CPU под пакетом, block/mutex idle).
#
#   w87-profiles.sh pack-cpu <API host:port> <TOKEN> <OUT> [CHUNK_S]
#       Пишет <OUT>/cpu-NNN.pprof (по CHUNK_S секунд, 30) подряд, пока не появится <OUT>/STOP-CPU.
#       Запускается ФОНОМ на окно пакета атак (хост и каждый прогон пода): один длинный профиль режется
#       WriteTimeout сервера, поэтому куски по 30 с. Метки event_type ставит сам агент (enable_pprof).
#       Печатает в <OUT>/cpu-index.txt: файл, размер.
#   w87-profiles.sh block-mutex <API> <TOKEN> <OUT> [SECS]
#       Окно block/mutex: включить переключатель, SECS (600) секунд, снять block и mutex, выключить,
#       проверить по /metrics, что флаг вернулся в 0. НЕ вызывается на окне 8.7.2 (idle CPU).
#
# Профили без сэмплов — не профиль: размер файла печатается в индекс, судит эмиттер 8.7.6.
set -u
MODE=${1:?pack-cpu|block-mutex}; API=${2:?}; TOKEN=${3:?}; OUT=${4:?}
mkdir -p "$OUT"
_c() { curl -s --max-time "${CURL_MAX:-60}" -H "Authorization: Bearer $TOKEN" "$@"; }
case "$MODE" in
pack-cpu)
    CHUNK=${5:-30}; i=0; : > "$OUT/cpu-index.txt"
    while [ ! -e "$OUT/STOP-CPU" ]; do
        i=$((i + 1)); f=$(printf '%s/cpu-%03d.pprof' "$OUT" "$i")
        CURL_MAX=$((CHUNK + 30)) _c -o "$f" "http://$API/debug/pprof/profile?seconds=$CHUNK"
        printf '%s %s\n' "$(basename "$f")" "$(wc -c < "$f" | tr -d ' ')" >> "$OUT/cpu-index.txt"
    done
    ;;
block-mutex)
    SECS=${5:-600}
    sw() { _c -X POST -H 'Content-Type: application/json' -d "{\"enabled\":$1}" "http://$API/api/v1/tuning/pprof-block-mutex"; }
    flag() { _c "http://$API/metrics" | awk '/^ebpf_guard_runtime_flag\{flag="pprof_block_mutex"\}/ { print $NF }'; }
    [ "$(flag)" = 0 ] || { echo "die: pprof_block_mutex не 0 до окна ($(flag))" > "$OUT/DONE"; exit 1; }
    sw true > "$OUT/switch-on.json"
    [ "$(flag)" = 1 ] || { echo "die: переключатель не включил block/mutex" > "$OUT/DONE"; sw false >/dev/null; exit 1; }
    sleep "$SECS"
    _c -o "$OUT/block.pprof" "http://$API/debug/pprof/block"
    _c -o "$OUT/mutex.pprof" "http://$API/debug/pprof/mutex"
    _c -o "$OUT/goroutine.txt" "http://$API/debug/pprof/goroutine?debug=1"
    sw false > "$OUT/switch-off.json"
    [ "$(flag)" = 0 ] || { echo "die: block/mutex не выключены после окна" > "$OUT/DONE"; exit 1; }
    echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
    ;;
*) echo "режим $MODE неизвестен" >&2; exit 2 ;;
esac
