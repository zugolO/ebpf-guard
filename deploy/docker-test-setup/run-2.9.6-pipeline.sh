#!/usr/bin/env bash
# ЗАМЕР №2.9.6 — приёмка волны 5.9.6, повторное подтверждение входа в волну 6.
# Цепочка та же, что у №2.9.5 (преflight -> сборка -> P0-3 -> очистка ->
# SMOKE -> пауза -> idle-час -> атаки -> гейт -> отчёт, ОДНИМ detached-
# процессом). Отличие от №2.9.5 одно, но оно определяет всю структуру:
#
#   Волна 5.9.6 ВПЕРВЫЕ за пять замеров правит BPF C-код, и правит его в
#   самом опасном месте — макросах reserve_event()/reserve_event_with_
#   sampling() (bpf/common.h), через которые проходит КАЖДОЕ событие
#   КАЖДОГО коллектора. Отсюда два следствия для этого файла:
#
#   [1/10] `make generate` перестал быть формальностью: до №2.9.6 его можно
#          было пропустить без последствий (BPF не менялся с волны 5.5),
#          теперь пропуск означает, что замер меряет СТАРОЕ ядро новым
#          гейтом. Жёсткий стоп на ошибке остаётся, но теперь он ловит ещё
#          и верификатор: `-Wall -Werror` в BPF_CFLAGS плюс проверка
#          загрузки в [4/10].
#
#   [4/10] НОВЫЙ ШАГ, риск №2 постановки №2.9.6 (P0-класса): ошибка в
#          reserve_event* не искажает измерение, а роняет сбор целиком — и
#          по зелёному гейту это НЕ ВИДНО, потому что пустой поток даёт
#          идеально сходящийся баланс 5.9.6b. Поэтому между рестартом с
#          новым бинарём и полуторачасовой цепочкой стоит smoke-гейт,
#          который за ~40с отвечает на единственный вопрос, ради которого
#          он существует: коллекторы грузятся и события идут. Красный smoke
#          — повод не начинать замер, а не строка в отчёте после него.
#          Порядок «сначала ненулевой поток, потом баланс и потери» —
#          прямое требование риска №2, а не удобство.
#
# Преflight волн 5.9.4/5.9.5 остаётся целиком (машинные гейты дожили до
# этого замера невредимыми) и добавляет проверки волны 5.9.6: SumPerCPUUint64
# (Go-обвязка счётчиков), `bash -n` на обоих скриптах харнесса (за 1.5 часа
# до гейта дешевле поймать сломанную правку синтаксисом, чем на 19-й секции),
# наличие реестра dns-decode-reasons.txt (критерий 21 без него FAIL'ит) и
# python3 (критерий 20 без него SKIP'ает оба режима).
#
# Почему одним процессом — находка №43 (замер №2.9.1): разорванная цепочка
# требует второго ssh-входа между idle и атаками, и этот вход сам становится
# событием внутри измеряемого слепого окна.
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.6-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.6-DONE. Полный лог: /root/run-2.9.6-pipeline.log
#
# ПРЕДУПРЕЖДЕНИЕ (риск №2 постановки 5.9.5, дожил без изменений):
# run_kill_scenario намеренно доводит энфорсер до разрушительного действия
# против одноразового дочернего процесса харнесса. Жертва одноразовая и шаг
# стоит ПОСЛЕ окна атак — сломанный предохранитель (dry_run не погасил kill)
# портит один шаг замера, а не весь прогон, но убивает реальный процесс.
exec > /root/run-2.9.6-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.6
P0_OUT=$SETUP/idle-results/p0-3-2.9.6
export PATH="$PATH:/usr/local/go/bin"

# Параметры волны 5.9.6, объявленные ЗДЕСЬ и печатаемые в преflight, а не
# оставленные умолчаниями внутри run-all-attacks.sh: п.4 порядка работы
# требует, чтобы величины, влияющие на критерий, были названы ДО прогона и
# лежали в артефактах замера, а не восстанавливались потом чтением кода.
export COUNTING_CONTROL_N="${COUNTING_CONTROL_N:-10000}"
export COUNTING_CONTROL_DROP_N="${COUNTING_CONTROL_DROP_N:-300000}"
export COUNTING_CONTROL_BG_WINDOW="${COUNTING_CONTROL_BG_WINDOW:-3}"
export INDUCED_DROP_MAX_FILES="${INDUCED_DROP_MAX_FILES:-20000}"

echo "=== [0/10] преflight: что именно меряется ==="
cd /opt/ebpf-guard
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (до пересборки): /' || true
# Декларативные наборы гоняются CLI-чекером, а не `go test` — на 5.9.3f два
# набора были красными с волны 3, и ни один прогон этого не показал.
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5

# Машинные гейты волн 5.9.4/5.9.5. Каждый закрывает находку, которая на
# прошлых замерах доживала до живого прогона: №52 (dry_run не гасил kill),
# №53 (не существовало инвентаря разрушительных правил), №56 (исключение по
# comm слепило собственный позитивный контроль), №62 (kill-сценарий не имел
# защищённого контрольного правила — 5.9.5a). Красный тест здесь — повод не
# начинать замер, а не строка в отчёте после него.
echo "--- преflight: go-тесты волн 5.9.4/5.9.5 ---"
go test -count=1 ./internal/enforcer/ -run 'DryRunSentinel|TestExecuteKill_DryRun|TestExecuteThrottle_DryRun' 2>&1 | tail -3
go test -count=1 -v ./internal/correlator/ -run 'TestDestructiveRulesInventory_RepoRules|TestExclusionsCollidingWithAttackerComms_RepoRules|TestRootkitBPFRules_MatchCommandNotCaller|TestKillScenarioControlRule_ActionIsKill' 2>&1 \
    | grep -E 'разрушительных|правил проверено|^(ok|FAIL|--- )' | sed 's/^/  /'

# Волна 5.9.6. SumPerCPUUint64 — единственная новая Go-функция на пути
# счётчиков ядра (5.9.6a/5.9.6b); если она врёт, врут обе левые части.
echo "--- преflight: go-тесты волны 5.9.6 ---"
go test -count=1 ./internal/bpf/ -run 'SumPerCPU' 2>&1 | tail -3
go test -count=1 ./internal/collector/ -run 'DNS|Malformed' 2>&1 | tail -3

# Синтаксис обоих скриптов харнесса. Волна 5.9.6 добавила в них ~630 строк
# (секции 18-21 гейта, run_counting_control, settle-опрос в run_induced_drop);
# сломанная правка проявилась бы через 1.5 часа на 19-й секции гейта, когда
# прогон уже нельзя повторить в тот же день.
echo "--- преflight: синтаксис харнесса ---"
bash -n $SETUP/attacks/run-all-attacks.sh && echo "  run-all-attacks.sh: синтаксис ок"
bash -n $SETUP/attacks/run-gate.sh && echo "  run-gate.sh: синтаксис ок"

# Реестры, без которых критерии волны 5.9.6 не читаются: dns-decode-reasons.txt
# (крит. 21 FAIL'ит на любом незарегистрированном reason'е — это и есть его
# приём, но пропавший файл превратит находку в шум), detection-baseline.txt
# (5.9.6f привела его к 69 типам; печатаем число, чтобы «добавлено: 0» в
# крит. 6 читалось относительно известной базы, а не относительно догадки).
echo "--- преflight: реестры ---"
for f in dns-decode-reasons.txt detection-baseline.txt silent-rules.txt intentional-loss.txt; do
    if [ -s "$SETUP/attacks/$f" ]; then
        echo "  $f: $(grep -cv '^[[:space:]]*\(#\|$\)' "$SETUP/attacks/$f") значащих строк"
    else
        echo "  $f: ОТСУТСТВУЕТ ИЛИ ПУСТ — соответствующий критерий будет нечитаем"
    fi
done
# 5.9.6f: сигнатура прошлого прогона живёт рядом со скриптом и переживает
# замер. Печатаем, есть ли она: если есть и совпадёт, крит. 6 напечатает
# «база брошена», и это должно быть ожидаемым, а не сюрпризом.
ls -l "$SETUP/attacks/detection-baseline-diff-state.txt" 2>/dev/null | sed 's/^/  сигнатура прошлого прогона: /' \
    || echo "  сигнатуры прошлого прогона нет — предупреждение «база брошена» на этом замере невозможно по построению"

# python3 — единственная внешняя зависимость критерия 20 (5.9.6c). Без него
# оба режима контроля счётности дают SKIP, то есть страховка риска №2
# остаётся невзведённой, а волна теряет свой P0-пункт. Не стоп (замер всё
# ещё осмыслен), но обязано быть видно в преflight, а не выясняться из гейта.
if command -v python3 >/dev/null 2>&1; then
    echo "  python3: $(python3 --version 2>&1) — контроль счётности 5.9.6c исполним"
else
    echo "  python3: НЕ НАЙДЕН — критерий 20 (5.9.6c) даст SKIP в обоих режимах, страховка риска №2 не взведена"
fi
echo "  параметры волны 5.9.6: COUNTING_CONTROL_N=$COUNTING_CONTROL_N COUNTING_CONTROL_DROP_N=$COUNTING_CONTROL_DROP_N COUNTING_CONTROL_BG_WINDOW=$COUNTING_CONTROL_BG_WINDOW INDUCED_DROP_MAX_FILES=$INDUCED_DROP_MAX_FILES"

# dry_run обязан быть включён в конфиге замера: критерий 17 (5.9.5a, парность
# enforcement_dryrun_total/enforcement_actions_total) бессмыслен, если
# dry_run выключен, а ноль убийств в таком прогоне ничего не доказывает.
grep -n -A7 '^enforcement:' "$SETUP/config-test.yaml" | sed 's/^/  конфиг enforcement: /'
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/10] make generate && make build (5.9.6a меняет BPF — generate обязателен) ==="
cd /opt/ebpf-guard
if ! make generate; then
    echo "СТОП: make generate упал — волна 5.9.6 правит bpf/common.h, прогон на старых объектах бессмыслен"
    touch /root/PIPELINE-2.9.6-DONE
    exit 1
fi
# Правки *_bpf_gen.go до этого момента были ручными заглушками
# ([[bpf-gen-files-are-stubs]]). После generate они — вывод bpf2go; если
# карта не появилась в объекте, поля пропадут, и это обязано быть видно
# здесь, а не по пустой серии в /metrics через два часа.
echo "--- generate: новые карты волны 5.9.6 в сгенерированных биндингах ---"
# Файлы *_bpf_gen.go — рукописные заглушки, и make generate их УДАЛЯЕТ,
# заменяя выводом bpf2go в *_x86_bpfel.go. Грепать заглушки после generate
# значит грепать несуществующие файлы: шаг печатал бы «No such file» и не
# проверял ничего — ровно та слепота, против которой он поставлен.
gen_maps_missing=0
for c in syscall network fileaccess privesc; do
    gf=$(ls internal/bpf/${c}_*_bpfe*.go 2>/dev/null | head -1)
    if [ -z "$gf" ]; then
        echo "  $c: сгенерированных биндингов нет — bpf2go не выдал объект"
        gen_maps_missing=1
        continue
    fi
    n=$(grep -c 'RingbufFullCounters\|EventsEmittedCounters' "$gf")
    echo "  $c ($gf): полей новых карт = $n"
    [ "$n" -eq 0 ] && gen_maps_missing=1
done
if [ "$gen_maps_missing" -ne 0 ]; then
    echo "ВНИМАНИЕ: карты волны 5.9.6 отсутствуют хотя бы в одном объекте — 5.9.6a/5.9.6b не доедут до /metrics; SMOKE-гейт [4/10] обязан это подтвердить красным"
fi
git status --porcelain internal/bpf/ | sed 's/^/  generate изменил: /'
if ! make build; then
    echo "СТОП: make build упал"
    touch /root/PIPELINE-2.9.6-DONE
    exit 1
fi
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (после пересборки): /' || true
ls -l build/ebpf-guard | sed 's/^/  /'
echo "сборка завершена в $(date -u +%H:%M:%S) UTC"

echo "=== [2/10] риск №3 (5.9.4): отдельный короткий прогон P0-3 ДО замера ==="
# NO_RESTART=1 в основном окне (5.9.1c) отменяет проверку рестарта/5.6d,
# которая на №2.4 поймала настоящий дефект (находка №20). Гоняем её здесь
# отдельно и коротко; её рестарт остаётся далеко за пределами журнального
# окна idle-часа.
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [3/10] очистка стора + рестарт агента (уже с новым бинарём) ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
echo 0 > /var/lib/ebpf-guard/observer-root-pid
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"
# Критерии 5.9.4a/17 считаются за ВЕСЬ аптайм агента — точка отсчёта журнала
# фиксируется здесь, а не угадывается потом по времени файлов.
date -u +"%Y-%m-%d %H:%M:%S" > /root/agent-start-2.9.6.txt
systemctl show ebpf-guard-test.service -p ExecMainStartTimestamp | sed 's/^/  /'

echo "=== [4/10] SMOKE-гейт волны 5.9.6 (риск №2, P0): коллекторы грузятся, поток не пуст ==="
# Единственный вопрос этого шага: не ослепила ли правка reserve_event* сбор
# целиком. Пустой поток даёт СХОДЯЩИЙСЯ баланс 5.9.6b и зелёный гейт — то
# есть большой гейт этот отказ не поймает по построению, и поймать его
# обязано что-то, стоящее ДО него. Стоит после рестарта с новым бинарём и
# ДО паузы [5/10], поэтому собственные curl'ы этого шага остаются за
# пределами журнального окна idle-часа.
SMOKE_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
SMOKE_API="http://${VPS_IP:-localhost}:19090"
smoke_fail=0

sleep 20   # дать коллекторам подняться и прицепить программы
echo "--- smoke: журнал загрузки BPF ---"
# Хвост журнала, а не --since по метке из agent-start-2.9.6.txt: метка
# записана в UTC, а journalctl --since читает её в ЛОКАЛЬНОЙ зоне стенда, и
# на не-UTC хосте окно уехало бы на несколько часов — молча, показав пустой
# журнал и зелёный smoke. Здесь окно и не нужно: агент перезапущен 20
# секундами выше, всё интересное лежит в последних строках. (Критерий 17 и
# отчёт по-прежнему получают метку файлом — они считают за весь аптайм и
# обращаются с ней явно.)
smoke_journal=$(journalctl -u ebpf-guard-test.service --no-pager -n 400 2>/dev/null || true)
echo "$smoke_journal" | grep -iE 'verifier|failed to load|load program|permission denied|collector .* (started|failed)' | tail -20 | sed 's/^/  /'
if echo "$smoke_journal" | grep -qiE 'verifier|failed to load'; then
    echo "SMOKE FAIL: в журнале есть ошибка загрузки/верификатора"
    smoke_fail=1
fi

smoke_health=$(curl -s --max-time 10 -H "Authorization: Bearer $SMOKE_TOKEN" "$SMOKE_API/health" 2>/dev/null)
echo "  /health: $smoke_health"
if ! echo "$smoke_health" | grep -q '"status"'; then
    echo "SMOKE FAIL: агент не отвечает на /health — дальше мерить нечего"
    smoke_fail=1
fi

# Наведём заведомую файловую активность вне дерева наблюдателя (он обнулён
# в [3/10]) и посмотрим, растут ли ОБЕ новые серии. Тот же идиом, что
# emit_counting_canary в run-all-attacks.sh, но на два порядка меньше: здесь
# не нужна точность счёта, нужен факт «не ноль».
smoke_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $SMOKE_TOKEN" "$SMOKE_API/metrics" 2>/dev/null; }
smoke_sum() { awk -F'} ' -v p="$1" '$0 ~ p {s+=$2} END{printf "%.0f", s+0}'; }

smoke_before=$(smoke_metrics)
if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import os
p='/tmp/ebpf-guard-smoke-canary'
open(p,'w').close()
for _ in range(20000):
    fd=os.open(p, os.O_RDONLY); os.close(fd)
" || echo "  smoke: генератор не отработал, полагаемся на фоновую активность"
else
    ls -laR /usr/share >/dev/null 2>&1 || true
fi
sleep 8
smoke_after=$(smoke_metrics)
rm -f /tmp/ebpf-guard-smoke-canary

for c in syscall network fileaccess; do
    em_a=$(echo "$smoke_before" | smoke_sum "ebpf_guard_events_emitted_kernel_total\{collector=\"$c\"\}")
    em_b=$(echo "$smoke_after"  | smoke_sum "ebpf_guard_events_emitted_kernel_total\{collector=\"$c\"\}")
    rf_present=$(echo "$smoke_after" | grep -c "reason=\"ringbuf_full\".*collector=\"$c\"\|collector=\"$c\".*reason=\"ringbuf_full\"" || true)
    echo "  $c: emitted_kernel $em_a -> $em_b (Δ$((em_b - em_a))), серия ringbuf_full присутствует: $rf_present"
    # Серия обязана СУЩЕСТВОВАТЬ у всех трёх (пре-регистрируется нулём в
    # main.go) — её отсутствие означает, что коллектор не поднялся либо
    # карта не прицепилась, а не что потерь не было.
    if [ "$rf_present" -eq 0 ]; then
        echo "SMOKE FAIL: $c — серия events_dropped_total{reason=\"ringbuf_full\"} отсутствует (5.9.6a не доехала до /metrics)"
        smoke_fail=1
    fi
done

# Рост обязан быть хотя бы у fileaccess: канарейка бьёт именно по нему.
# Ноль здесь при живом агенте — это и есть «правка ослепила коллектор»,
# сценарий риска №2 в чистом виде.
fa_a=$(echo "$smoke_before" | smoke_sum 'ebpf_guard_events_emitted_kernel_total\{collector="fileaccess"\}')
fa_b=$(echo "$smoke_after"  | smoke_sum 'ebpf_guard_events_emitted_kernel_total\{collector="fileaccess"\}')
ev_a=$(echo "$smoke_before" | smoke_sum '^ebpf_guard_events_total\{.*type="file"')
ev_b=$(echo "$smoke_after"  | smoke_sum '^ebpf_guard_events_total\{.*type="file"')
echo "  fileaccess: Δemitted_kernel=$((fa_b - fa_a)), Δevents_total{file}=$((ev_b - ev_a))"
if [ "$((fa_b - fa_a))" -le 0 ]; then
    echo "SMOKE FAIL: emitted_kernel{fileaccess} не вырос под заведомой файловой нагрузкой — reserve_event* не считает либо коллектор ослеп (риск №2)"
    smoke_fail=1
fi
if [ "$((ev_b - ev_a))" -le 0 ]; then
    echo "SMOKE FAIL: events_total{type=file} не вырос — события не доходят до userspace (риск №2: правка макроса уронила сбор)"
    smoke_fail=1
fi

if [ "$smoke_fail" -ne 0 ]; then
    echo "=== СТОП: SMOKE-гейт волны 5.9.6 красный. Замер не начат — чинить 5.9.6a/5.9.6b, ==="
    echo "=== затем повторить пайплайн. Полтора часа на прогон, который не сможет  ==="
    echo "=== отличить исправную систему от ослепшей, тратить нельзя (риск №2).    ==="
    touch /root/PIPELINE-2.9.6-DONE
    exit 1
fi
echo "SMOKE OK: коллекторы грузятся, обе серии волны 5.9.6 живы и растут. $(date -u +%H:%M:%S) UTC"

echo "=== [5/10] пауза 660с: deploy-рестарт и smoke должны выйти за окно журнала idle-run ==="
sleep 660

echo "=== [6/10] idle-час, NO_RESTART=1 (5.9.1c) ==="
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [7/10] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
# Переменные экспортируются в ЭТОМ процессе, а не в файл для отдельного
# входа (это и было дефектом №43). run_counting_control (5.9.6c, оба режима),
# run_kill_scenario (5.9.5a) и run_induced_drop (5.9.5b/5.9.6d) уже часть
# full_run() внутри run-all-attacks.sh — отдельных шагов здесь не требуется.
# Порядок внутри full_run существенен и задан там: контроль счётности стоит
# ПЕРВЫМ, до атак, чтобы окно с известным N было максимально чистым.
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
# 5.9.5i (находка №70): IDLE_STATE_END должен быть экспортирован ДО
# run-all-attacks.sh, не только до run-gate.sh — get_baseline_metrics сама
# ждёт до 15с перед снятием baseline, если зазор с конца idle-часа получился
# меньше 10с (иначе критерий 16 напечатает «не измерялось»).
export IDLE_STATE_END=$IDLE_OUT/state-end.json
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"

echo "=== [8/10] гейт, один вызов ==="
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
# 5.9.4g (№58): критерий 16 считает объём слепого окна по множеству id снимков
# /api/v1/alerts, а не по кумулятивному счётчику (idle-run.sh рестартует агента
# в конце и обнуляет его). Эта же переменная кормит gap_rule_ids (5.9.6h):
# без неё третья фаза не сработает вообще и «фаза не определена» останется
# как было.
export IDLE_ALERTS_END=$IDLE_OUT/alerts-end.json
# 5.9.5a: критерий 17 читает журнал за ВЕСЬ аптайм от той же точки отсчёта,
# что и отчёт [10/10].
export AGENT_START_FILE=/root/agent-start-2.9.6.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.6.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"
# Пункты 1-6 постановки №2.9.6 не подлежат толкованию — вытаскиваем их
# строки отдельно, чтобы приёмка волны читалась без листания всего гейта.
echo "--- пункты 1-6 постановки (обязательные, волна о полноте учёта) ---"
grep -E '=== (18|19|20)\.|ringbuf_full|emitted_kernel|потеряно ДО резерва|контроль счётности|наведённый дроп \(5\.9\.6d\)' \
    /root/gate-2.9.6.txt | sed 's/^/  /'

echo "=== [9/10] сводка idle-части ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null

echo "=== [10/10] отчёт сверх гейта: величины постановки, которых гейт не считает ==="
# Считает только по файлам на диске и по журналу, ни одного сетевого запроса —
# безопасно запускать и повторно, уже после прогона. Отчёт заморожен на
# замер: если run-2.9.6-report.sh ещё не написан, берём предыдущий и ГОВОРИМ
# об этом — п.10 (idle-алерты на метках срезов, критерий 5.9.6i) он считает
# тем же способом, но величины постановки №2.9.6 в нём отсутствуют, и
# принимать волну по нему целиком нельзя.
if [ -x "$SETUP/run-2.9.6-report.sh" ] || [ -f "$SETUP/run-2.9.6-report.sh" ]; then
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.6.txt \
        bash $SETUP/run-2.9.6-report.sh 2>&1 | tee /root/report-2.9.6.txt
else
    echo "ВНИМАНИЕ: run-2.9.6-report.sh отсутствует — считаем отчётом №2.9.5."
    echo "ВНИМАНИЕ: п.10 (idle-алерты на метках срезов) он посчитает, величины"
    echo "ВНИМАНИЕ: постановки №2.9.6 (пп.1-6) — нет; они только в гейте."
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.6.txt \
        bash $SETUP/run-2.9.5-report.sh 2>&1 | tee /root/report-2.9.6.txt
fi

echo "=== ПАЙПЛАЙН №2.9.6 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.6-DONE
