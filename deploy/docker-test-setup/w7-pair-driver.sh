#!/bin/bash
# Драйвер пары A/B ОДНОЙ порции оси `nr` (item б3 волны 7). Номер порции —
# первый аргумент. Исполняется НА СТЕНДЕ одним отцепленным процессом: ни один
# заход по ssh не попадает внутрь окна ни одной роли.
#
# Роль A — состояние дерева (monitored_syscalls не задан, откат на
# DefaultMonitoredSyscalls()). Роль B — тот же список побуквенно плюс номера
# порции. Бинарь ОДИН на обе роли, пайплайн ОДИН.
#
# Живёт в репозитории (раньше — /root/w669-pair2.sh и только там): пара
# воспроизводима из git, а не из файлов вне него. Запуск с mac — w7-pair-run.sh.
#
# ПЛАНОВЫЕ ГРАНИЦЫ ОКОН публикуются в $LOGDIR/w7-pair-P<порция>.plan ДО первой
# роли (Д2). Ожидатель по нему ставится на расчётный финиш, а не «на глаз»:
# 30.09 два опроса маркера легли ВНУТРЬ окна роли B (№317/№318).
#
# Состав роли НЕ считается по конфигу: число значений лейбла nr в снимке
# /metrics окна ЕСТЬ аллоулист прогона (N номеров + other), оно читается у
# рантайма из архива роли ([[entry-guard-must-read-runtime-not-config]]).
# Счётчик по тексту конфига убран: awk без терминатора списка втягивал
# path_denylist и печатал 37 вместо 34 (№513).
#
# Переопределения нужны только фикстуре: W7_SETUP, W7_LOGDIR, W7_REPO,
# W7_PAIR_DRYRUN=1 (пайплайны не идут, роль B патчит КОПИЮ конфига).
set -u
POR="${1:?порция не названа}"
REPO="${W7_REPO:-/opt/ebpf-guard}"
SETUP="${W7_SETUP:-$REPO/deploy/docker-test-setup}"
LOGDIR="${W7_LOGDIR:-/root}"
CFG="${W7_CFG:-$SETUP/config-test.yaml}"
DRY="${W7_PAIR_DRYRUN:-0}"
# Длина роли — ИЗМЕРЕННАЯ: пары 05.09…30.09 дали 3458…3466 с при прологе 1800 и
# окне 600; на пару 2·3460 + развязка ≈ 1 ч 55 мин. Не угадывается заново.
PROLOGUE="${PROLOGUE:-1800}"
WINDOW="${WINDOW:-600}"
ROLE_SECS="${W7_ROLE_SECS:-3460}"
# Окно начинается не ровно на PROLOGUE: барьер готовности и старт добавляют
# секунды. Допуск публикуется рядом, а не прячется.
WINDOW_SLACK="${W7_WINDOW_SLACK:-300}"
GAP_SECS="${W7_GAP_SECS:-5}"
SETTLE_SECS="${W7_SETTLE_SECS:-120}"
PLAN="$LOGDIR/w7-pair-P${POR}.plan"
MARK="$LOGDIR/W669-PAIR-P${POR}-DONE"

mkdir -p "$LOGDIR"
rm -f "$MARK"
exec >>"$LOGDIR/w669-pair-driver-P${POR}.log" 2>&1
echo "=== драйвер пары порции ${POR} стартовал $(date -u +%FT%TZ) ==="

_t0=$(date +%s)
_a0=$_t0
_a1=$(( _a0 + ROLE_SECS ))
_b0=$(( _a1 + GAP_SECS ))
_b1=$(( _b0 + ROLE_SECS ))
_end=$(( _b1 + SETTLE_SECS ))
{
    echo "PORTION=$POR"
    echo "PLAN_EPOCH=$_t0"
    echo "ROLE_SECS=$ROLE_SECS"
    echo "PROLOGUE=$PROLOGUE"
    echo "WINDOW=$WINDOW"
    echo "WINDOW_SLACK=$WINDOW_SLACK"
    echo "A_START=$_a0"
    echo "A_WINDOW_START=$(( _a0 + PROLOGUE ))"
    echo "A_WINDOW_END=$(( _a0 + PROLOGUE + WINDOW ))"
    echo "A_END=$_a1"
    echo "B_START=$_b0"
    echo "B_WINDOW_START=$(( _b0 + PROLOGUE ))"
    echo "B_WINDOW_END=$(( _b0 + PROLOGUE + WINDOW ))"
    echo "B_END=$_b1"
    # Первый момент, когда на стенд МОЖНО зайти: конец роли B плюс осадка.
    echo "SAFE_AFTER=$_end"
    echo "MARKER=$MARK"
} >"$PLAN.tmp" && mv -f "$PLAN.tmp" "$PLAN"
echo "план окон опубликован: $PLAN (безопасный заход после $(date -u -d "@$_end" +%FT%TZ 2>/dev/null || date -u -r "$_end" +%FT%TZ))"

# Число значений лейбла nr в снимке окна роли = аллоулист прогона (+ other,
# + unset, если ось его печатает). Читается из АРХИВА роли, не из конфига.
_role_nr_count() {
    local snap="$1/controls/artifacts/metrics-window-end.txt"
    [ -s "$snap" ] || { echo "?"; return; }
    grep -a 'ebpf_guard_syscall_events_by_nr_total{nr="' "$snap" \
        | sed 's/.*nr="\([^"]*\)".*/\1/' | grep -avxE 'other|unset' | sort -u | wc -l | tr -d ' '
}

_run() {
    local role="$1" name="$2"
    rm -f /root/PIPELINE-6.4-DONE
    echo "--- роль $role: пайплайн пошёл $(date -u +%FT%TZ)"
    if [ "$DRY" = "1" ]; then
        echo "--- роль $role: СУХОЙ ПРОГОН, пайплайн не ставится"
        return 0
    fi
    ( cd "$SETUP" && env W7_PORTION="$POR" W64_INTENT=probe \
        OUT="/root/run-6.4-${name}.log" COLLECT="/root/collect-6.4-${name}" \
        bash run-6.4-pipeline.sh ) >/dev/null 2>&1
    echo "--- роль $role: пайплайн вышел с rc=$? $(date -u +%FT%TZ)"
    if ! grep -aq "6.4.8 ДОСТИГНУТО" "/root/run-6.4-${name}.log"; then
        echo "СТОП ДРАЙВЕРА: роль $role не получила 6.4.8 ДОСТИГНУТО — вторая половина пары не ставится"
        grep -a "6.4.8\|ОТКАЗ СОБРАТЬ" "/root/run-6.4-${name}.log" | tail -3
        return 1
    fi
    echo "--- роль $role: значений nr в аллоулисте РАНТАЙМА = $(_role_nr_count "/root/collect-6.4-${name}")"
    grep -a "6.6.9 " "/root/run-6.4-${name}.log" | grep -avE "фикстура|^ +OK |реплей" | tail -1
    return 0
}

if [ "$DRY" != "1" ]; then
    cd "$REPO" && git diff --quiet -- deploy/docker-test-setup/config-test.yaml \
        || { echo "СТОП ДРАЙВЕРА: config-test.yaml отличается от git ДО роли A"; exit 1; }
fi
_run A "w669P${POR}A" || exit 1

python3 "$SETUP/w7-roleB-patch.py" "$POR" "$CFG" || { echo "СТОП ДРАЙВЕРА: правка конфига роли B не удалась"; exit 1; }
_run B "w669P${POR}B"; _rc=$?

if [ "$DRY" != "1" ]; then
    cd "$REPO" && git checkout -- deploy/docker-test-setup/config-test.yaml
    systemctl restart ebpf-guard-test.service
    echo "--- конфиг откачен к состоянию git, агент перезапущен $(date -u +%FT%TZ)"
fi
echo "=== драйвер пары порции ${POR} закончил rc=${_rc} $(date -u +%FT%TZ) ==="
date -u +%FT%TZ > "$MARK"
