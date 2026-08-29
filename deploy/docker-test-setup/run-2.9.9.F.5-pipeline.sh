#!/usr/bin/env bash
# ЗАМЕР №2.9.9.F.5 — приёмка волны 5.9.9.F.5 (plan.md, "Волна 5.9.9.F.5"),
# переехал из run-2.9.9.F.4-pipeline.sh (замер №2.9.9.F.4 принят наполовину —
# см. таблицу волны в plan.md). Файл — копия предшественника с правками
# ТРЁХ пунктов волны 5.9.9.F.5, исполненных первыми по её порядку (5a/5b/5c —
# три величины без входа; 5d-5j этой правкой НЕ затронуты и остаются долгом
# волны):
#
#   5.9.9.F.5a (№152): блок величины 10 (пункт 10 приёмки ниже, бывший
#     «10)» в унаследованном файле) больше не засчитывает 0 без входа
#     молча — он ищет в манифесте атак запись
#     `exfil_archive_parent_positive_control` с `comm_verified=true` (её
#     пишет позитивный контроль сам, см. run-all-attacks.sh) и печатает
#     `FAIL(сторож)`, если запись есть, а `comm_verified` не true — контроль
#     подтвердил себя, но подтвердил НЕ то. Если записи нет вовсе — как и
#     раньше, «величина 10 НЕ засчитывается», без домысливания.
#   5.9.9.F.5b (№153): блок величины 3 (idle-час, verdict="attack") больше
#     не читает состав промоушенов из финального снимка
#     `/api/v1/incidents` — актор берётся из журнала агента за окно
#     idle-часа (запись `incident promoted` формата IncidentTracker, см.
#     internal/correlator/incident_tracker.go) тем же приёмом, каким
#     5.9.4h уже читает journalctl. При `FAIL` печатается актор из
#     журнала, а не «актор неизвестен, вытеснен снимком».
#   5.9.9.F.5c (№157, находка №134 закрыта данными №2.9.9.F.4 — жёсткая
#     константа `<= 4` снята): величина 6 («наведено преflight-шагом»)
#     сравнивается не с числом с прошлого замера, а с тем, дал ли хоть один
#     из наведённых типов рост ВНЕ преflight-окна (idle-час или окно атак) —
#     то есть с тем, действительно ли поглощение произошло, а не с тем,
#     сколько типов вообще было наведено.
#
# Остальной текст этого блока (описание 5.9.9.F.4a-i) — унаследованная
# история предыдущего замера, оставлена без изменений построчно.
#
#   5.9.9.F.4b (№142/№143): в шаге [9.6/14] у пары 5.9.9.F.3c
#     — Δincident_confirmed_attack перестал быть глобальной величиной:
#       вместо счётчика алертов типа incident_confirmed_attack за окно
#       считается число incidents (`/api/v1/incidents`) с verdict="attack",
#       чей process_chain/comms содержит актора формы "(...)" — величина
#       по актору, а не по фону, который сам шаг [9.5/14]-[9.6/14] и
#       производит (находка №142: субъектом инцидента на отклонённом
#       замере был не man-db, а фон самого измерителя).
#     — порядок половин перевёрнут: сначала позитив (unshare -Urm,
#       ppid != 1), затем негатив (systemctl start man-db.service) — провал
#       негатива не имеет права прятать проверку на ослепление (находка
#       №143). 3a/3b уже были positive-first в унаследованном файле и не
#       трогались.
#   5.9.9.F.4a (№141): признак systemd-sandbox-child расширен с шести
#     правил до фактических двенадцати — список взят из архива поимённо
#     (proc_inject_memfd_create, integrity_proc_self_exe_exec,
#     sigma_memfd_create_anonymous, rootkit_pam_module_added,
#     cred_shadow_read, drift_new_library_in_system_dir добавлены в
#     rules/*.yaml к исходным шести). Преflight-сторож 3c и загруженность
#     через /api/v1/rules в шаге [9.6/14] расширены на все двенадцать.
#   5.9.9.F.4c (№147): дерево ЭТОГО пайплайна регистрирует себя в
#     observer-root-pid (тем же файлом/механизмом 5.9a, каким это делает
#     idle-run.sh) сразу после die(), а не только на idle-часе — раньше файл
#     ОБНУЛЯЛСЯ на рестарте агента [5/14] и ничего не подхватывал вплоть до
#     idle-run.sh на шаге [11/14], то есть SMOKE [6/14], оба контроля DNS
#     [7/14], контроль счётности [8/14], переполнение кольца [9/14],
#     CPU-давление [9.7/14] и три пары контролей волны [9.6/14] — все шесть
#     ПОСЛЕ рестарта, то есть внутри аптайма, который меряет гейт — работали
#     БЕЗ исключения дерева пайплайна. Регистрация переживает рестарт [5/14]
#     (файл на диске, новый агент переопрашивает его сам; шаг лишь
#     переподтверждает подхват через /debug/state, вместо прежнего
#     `echo 0 > observer-root-pid`) и обнуляется явно ПЕРЕД шагом [11/14] —
#     границей окна замера, а не на рестарте — чтобы idle-час и окно атак
#     видели стенд без исключения дерева пайплайна (baseline не имеет права
#     тоже прятать себя). Величина «доля алертов аптайма от акторов
#     измерителя и сборки» печатается пунктом (8) блока приёмки ниже.
#   5.9.9.F.4d (№144): `owasp_path_traversal` и `web_path_traversal_extended`
#     (rules/owasp-web.yaml, rules/web-attacks-enhanced.yaml) сужены до
#     comm веб-воркера (тот же список, что у owasp_web_sensitive_file_read) —
#     раньше условие держалось на одном filename-regex "../" и ловило
#     grep/ld/clang/llvm-strip/*.test во время make build и самого
#     измерителя (50 критикалов, 27% всех, находка №144). Новый позитивный
#     контроль `run_path_traversal_positive_control` (run-all-attacks.sh)
#     читает файл с буквальным "../" в пути под comm=apache2 — раньше ни у
#     одного из двух правил не было ни одного сценария в манифесте атак.
#     Величина — пункт (9) блока приёмки ниже.
#
#   5.9.9.F.4e/4f/4g/4h: правки лежат в дереве (правила exfil/drift,
#     загрузчик, записи журнала) — у каждой добавлен свой преflight-сторож
#     ниже, по тому же правилу, что и у 4a-4d: сторож обязан падать на
#     НЕправленом дереве, иначе он не сторож.
#
#   5.9.9.F.4i (перенос 5.9.9.F.3 целиком): все семь пунктов 5.9.9.F.3
#     сторожатся в этом файле без правок их кода, WAVE_CRITERIA_IDS
#     перечисляет пункты ОБЕИХ волн, и артефакты прогона названы по замеру
#     №2.9.9.F.4 (иначе прогон писал бы в файлы отклонённого №2.9.9.F.3 и
#     затирал их архив).
#
# (история) ЗАМЕР №2.9.9.F.4 — приёмка волн 5.9.9.F.4 И 5.9.9.F.3 сразу
# (plan.md, "Волна 5.9.9.F.4"; пункт 4i переносит все семь пунктов
# 5.9.9.F.3 внутрь этой приёмки — замер №2.9.9.F.3 оборвался на шаге
# [9.6/14] и отклонён). Этот замер (№2.9.9.F.4) принят наполовину — таблица
# волны 5.9.9.F.5 выше. Этот файл (№2.9.9.F.5) добавляет только 5a/5b/5c.
#
# Структура унаследована от №2.9.9.F.2 дословно (преflight -> реплеи ->
# сборка -> P0-3 -> очистка -> SMOKE -> контроли вне окна -> пауза ->
# idle-час -> атаки -> гейт -> отчёт, ОДНИМ detached-процессом). Отличия от
# №2.9.9.F.2 ровно пять, и все они следуют прямо из содержания волны:
#
#   1. ВОСЬМОЙ архив реплея — collect-2.9.9.F.2 — и ЧЕТЫРНАДЦАТЬ реплеев
#      вместо двенадцати: 13/14 (фаза idle проверяется раньше «наведено
#      преflight'ом», 5.9.9.F.3d, находка №134) и 14/14 (SKIP=0 на архиве
#      без единой правки самих критериев, 5.9.9.F.3e, находки №135/№136/
#      №137). Оба — на collect-2.9.9.F.2, и он единственный, где это
#      возможно: только у него есть пакет systemd 11:57:39 внутри idle-часа
#      (вход для 3d) и ровно те три SKIP, которые снимает 3e.
#
#   2. НОВЫЙ шаг [9.6/14] — три пары контролей продуктовых правок волны
#      (5.9.9.F.3a/3b/3c), ВНЕ окна замера, рядом с контролями DNS/счётности
#      и переполнением кольца (запрет №3). Это ГЛАВНОЕ отличие замера:
#      все три правки УМЕНЬШАЮТ число алертов и по счётчику неотличимы от
#      ослепления (находка №57). У каждой обязаны исполниться обе половины —
#      позитивная (правило осталось видящим) и негативная (правило перестало
#      видеть то, ради чего правилось), иначе пункт волны считается
#      неисполненным и цепочка встаёт ДО траты полутора часов.
#
#   3. НОВЫЙ преflight-сторож 5.9.9.F.3f (находка №138): каждый пункт
#      текущей волны обязан иметь строку в criteria-index.txt. Список
#      пунктов объявлен переменной WAVE_CRITERIA_IDS ниже — по п.4 порядка
#      работы величина, влияющая на критерий, лежит в артефактах замера, а
#      не восстанавливается потом чтением кода. Старый сторож («непокрытых
#      пунктов постановки: 0») перебирает сам индекс и пункт, строки для
#      которого нет, заметить не способен — так 5.9.9.F.2c и 5.9.9.F.2g
#      прошли весь замер №2.9.9.F.2 незаведёнными.
#
#   4. Блок приёмки после гейта печатает ШЕСТЬ величин, названных
#      постановкой заранее, включая ту, что запрещает чинить FAIL реестром:
#      новых акторов idle-часа = 0 БЕЗ дописывания mandb/find/install в
#      idle-actors.txt.
#
#   5. Преflight сторожит, что реестр idle-actors.txt НЕ пополнялся акторами
#      пакета systemd. Дописывание их туда перевело бы FAIL замера
#      №2.9.9.F.2 в PASS правкой реестра — ровно то, что постановка
#      5.9.9.F.2 запретила явно, и то, ради чего волна 5.9.9.F.3 и собрана.
#
# ГЛАВНЫЙ РИСК ВОЛНЫ, названный постановкой заранее и относящийся к этому
# файлу напрямую: правки 3a/3b/3c уменьшают число алертов, и «правило
# сузилось» неотличимо от «правило ослепло» по любому счётчику. Поэтому
# жёсткие стопы на шаге [9.6/14] стоят у ОБЕИХ половин каждой пары, а не
# только у негативной: ноль на позитивном контроле — это находка №57, а не
# успех волны, и полный замер объявил бы его регрессом детекта в крит. 6
# после потраченного idle-часа.
#
# Второй риск, названный постановкой: 5.9.9.F.3c правит ШЕСТЬ правил сразу.
# Если структурный признак песочницы systemd оказался невыразим полями
# события, пункт обязан быть раздроблен ДО правки, а не после FAIL — сторож
# преflight'а ниже проверяет, что в дереве лежит то, что объявлено, а не
# половина.
#
# Запуск (обязательно detached, иначе обрыв ssh убивает замер):
#   setsid nohup bash /opt/ebpf-guard/deploy/docker-test-setup/run-2.9.9.F.5-pipeline.sh >/dev/null 2>&1 &
# Предпрогон (~25 минут, без idle-часа и атак):
#   SMOKE_ONLY=1 setsid nohup bash .../run-2.9.9.F.5-pipeline.sh >/dev/null 2>&1 &
# Готовность: файл /root/PIPELINE-2.9.9.F.5-DONE. Полный лог: /root/run-2.9.9.F.5-pipeline.log
#
# ПРЕДУПРЕЖДЕНИЕ (риск №2 постановки 5.9.5, дожил без изменений):
# run_kill_scenario намеренно доводит энфорсер до разрушительного действия
# против одноразового дочернего процесса харнесса. Жертва одноразовая и шаг
# стоит ПОСЛЕ окна атак — сломанный предохранитель (dry_run не погасил kill)
# портит один шаг замера, а не весь прогон, но убивает реальный процесс.
exec > /root/run-2.9.9.F.5-pipeline.log 2>&1
set -x
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
IDLE_OUT=$SETUP/idle-results/idle-2.9.9.F.5
P0_OUT=$SETUP/idle-results/p0-3-2.9.9.F.5
export PATH="$PATH:/usr/local/go/bin"

die() {
    echo "=== СТОП: $* ==="
    echo "=== ЗАМЕР №2.9.9.F.5 НЕ НАЧАТ. $(date -u +%H:%M:%S) UTC ==="
    # 5.9.9.F.4c: не оставлять observer-root-pid указывающим на процесс
    # пайплайна после его смерти — определена ниже die(), поэтому вызов
    # безопасен, даже если сама регистрация ещё не произошла (файла нет —
    # echo завершится ошибкой и будет проглочен).
    echo 0 > /var/lib/ebpf-guard/observer-root-pid 2>/dev/null || true
    touch /root/PIPELINE-2.9.9.F.5-DONE
    exit 1
}

# 5.9.9.F.4c (находка №147): тот же механизм 5.9a/5.9.1a, каким idle-run.sh
# исключает СВОЁ дерево, но здесь регистрируется корень ЭТОГО пайплайна —
# преflight, сборка, рестарт, SMOKE, оба контроля DNS, счётность,
# переполнение кольца, CPU-давление и три пары контролей волны [9.6/14],
# то есть всё, что раньше давало 55% алертов аптайма (curl/jq/grep/go/ld/
# clang/llvm-strip/bpf2go/*.test/cmdlinescan). Регистрация обязана пережить
# рестарт агента [5/14] (файл на диске, новый агент переопрашивает его
# сам — раньше на этом же месте стояло `echo 0 > observer-root-pid`,
# обнулявшее исключение НАВСЕГДА до idle-run.sh) и обязана быть снята явно
# ПЕРЕД шагом [11/14] (см. release_pipeline_observer_root ниже) — baseline и
# окно атак обязаны видеть стенд без исключения дерева пайплайна, иначе
# крит. 5.9.9.F.2d и величина 3 приёмки стали бы ложно-зелёными по той же
# причине, по которой ослепление неотличимо от сужения (главный риск
# постановки 4c).
OBSERVER_ROOT_PID_FILE="${OBSERVER_ROOT_PID_FILE:-/var/lib/ebpf-guard/observer-root-pid}"
OBS_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
OBS_API="http://${VPS_IP:-localhost}:19090"
register_pipeline_observer_root() {
    if ! echo "$$" > "$OBSERVER_ROOT_PID_FILE" 2>/dev/null; then
        echo "ВНИМАНИЕ 5.9.9.F.4c: не удалось записать $OBSERVER_ROOT_PID_FILE — дерево пайплайна не исключается, находка №147 не закрыта на этом прогоне"
        return
    fi
    echo "5.9.9.F.4c: дерево пайплайна зарегистрировано как observer_root, root_pid=$$ ($(date -u +%H:%M:%S) UTC)"
    local confirmed=0
    for _ in $(seq 1 7); do
        local reported
        reported="$(curl -s --max-time 5 -H "Authorization: Bearer $OBS_TOKEN" "$OBS_API/debug/state" 2>/dev/null \
            | jq -r '.engine_stats.observer_root_pid // empty' 2>/dev/null)"
        if [ "$reported" = "$$" ]; then
            confirmed=1
            break
        fi
        sleep 2
    done
    if [ "$confirmed" -eq 1 ]; then
        echo "5.9.9.F.4c: агент подтвердил подхват root_pid=$$ через /debug/state"
    else
        echo "ВНИМАНИЕ 5.9.9.F.4c: агент не подтвердил подхват root_pid=$$ за ~14с — до шага [5/14] это НОРМАЛЬНО (старый бинарь мог ещё не поднять сервис или observer_exclude выключен в его конфиге); если предупреждение повторяется ПОСЛЕ [5/14], находка №147 не закрыта"
    fi
}
release_pipeline_observer_root() {
    echo 0 > "$OBSERVER_ROOT_PID_FILE" 2>/dev/null || true
    # Снятие ПОДТВЕРЖДАЕТСЯ у агента ровно так же, как подтверждается
    # регистрация. Без этого «обнулил» — заявление о записи в файл, а не о
    # состоянии фильтра: находка №151 предпрогона №2.9.9.F.5 в том и
    # состояла, что поллер агента ИГНОРИРОВАЛ ноль (`pid == 0 -> continue`),
    # исключение оставалось взведённым навсегда, а сам файл при этом честно
    # содержал 0. Ждать обязательно и по второй причине: поллер тикает раз в
    # 2с, а следом за снятием идёт наведённый контроль, чьи события фильтр
    # обязан уже пропускать.
    local released=0 reported
    for _ in $(seq 1 7); do
        reported="$(curl -s --max-time 5 -H "Authorization: Bearer $OBS_TOKEN" "$OBS_API/debug/state" 2>/dev/null \
            | jq -r '.engine_stats.observer_root_pid // empty' 2>/dev/null)"
        if [ -z "$reported" ] || [ "$reported" = "0" ]; then
            released=1
            break
        fi
        sleep 2
    done
    if [ "$released" -eq 1 ]; then
        echo "5.9.9.F.4c: root_pid обнулён и снятие подтверждено агентом ($(date -u +%H:%M:%S) UTC) — стенд виден без исключения дерева пайплайна"
    else
        echo "ВНИМАНИЕ 5.9.9.F.4c: агент за ~14с не подтвердил снятие исключения (в /debug/state всё ещё root_pid=$reported) — наведённые контроли ниже будут ослеплены in-kernel фильтром 5.9.2g, находка №151 не закрыта"
    fi
}
register_pipeline_observer_root

# Параметры волны объявлены ЗДЕСЬ и печатаются в преflight (п.4 порядка
# работы): величина, влияющая на критерий, обязана лежать в артефактах
# замера, а не восстанавливаться потом чтением кода.
export COUNTING_CONTROL_N="${COUNTING_CONTROL_N:-10000}"
# COUNTING_CONTROL_DROP_N НЕ объявляется: режим drop удалён волной
# 5.9.9.F.2a (находка №123) вместе с переменной. Возврат её сюда означал бы
# возврат режима, у которого нет способа переполнить кольцо, — преflight
# ниже сторожит это отдельной проверкой по дереву.
export INDUCED_DROP_MAX_FILES="${INDUCED_DROP_MAX_FILES:-20000}"
export RINGBUF_OVERFLOW_N="${RINGBUF_OVERFLOW_N:-300000}"
export RINGBUF_OVERFLOW_SERVICE="${RINGBUF_OVERFLOW_SERVICE:-ebpf-guard-test.service}"
# 5.9.8a: число межпоточных резолвов позитивного контроля. Маленькое
# намеренно — контроль отвечает на вопрос «видит ли коллектор межпоточный
# fd вообще», а не мерит пропускную способность.
export DNS_CROSS_THREAD_N="${DNS_CROSS_THREAD_N:-8}"
# 5.9.9.F.2b (№125): параметры наведённого CPU-давления. min_dwell СЮДА НЕ
# ВЫНОСИТСЯ намеренно — шаг обязан читать его у самого агента (журнальная
# запись "cpu pressure: adaptive load shedding enabled"), иначе смена
# дефолта снова сделает критерий невыполнимым молча. Здесь только потолки
# ожидания и размер всплеска, то есть величины измерителя, а не агента.
export CPU_PRESSURE_MAX_FILES="${CPU_PRESSURE_MAX_FILES:-20000}"
export CPU_PRESSURE_MAX_REDUCE_WAIT="${CPU_PRESSURE_MAX_REDUCE_WAIT:-180}"

# 5.9.9.F.3f (находка №138): СПИСОК ПУНКТОВ ТЕКУЩЕЙ ВОЛНЫ. Объявлен здесь, а
# не выведен из criteria-index.txt, потому что в этом весь смысл сторожа:
# старый преflight («непокрытых пунктов постановки: 0») перебирает строки
# самого индекса и пункт, строки для которого НЕТ, заметить не может по
# построению. Так 5.9.9.F.2c и 5.9.9.F.2g прошли весь замер №2.9.9.F.2
# незаведёнными, а гейт напечатал 0. Сверка идёт списком против индекса, а
# не индексом против себя.
# 5.9.9.F.4i: список — пункты ОБЕИХ волн. Перенос 5.9.9.F.3 означает, что
# её семь пунктов принимаются этим замером наравне с девятью пунктами
# 5.9.9.F.4; пункт без строки в criteria-index.txt нигде не проверяется, и
# сторож 5.9.9.F.3f ниже валит преflight именно за это.
export WAVE_CRITERIA_IDS="${WAVE_CRITERIA_IDS:-5.9.9.F.3a 5.9.9.F.3b 5.9.9.F.3c 5.9.9.F.3d 5.9.9.F.3e 5.9.9.F.3f 5.9.9.F.3g 5.9.9.F.4a 5.9.9.F.4b 5.9.9.F.4c 5.9.9.F.4d 5.9.9.F.4e 5.9.9.F.4f 5.9.9.F.4g 5.9.9.F.4h 5.9.9.F.4i 5.9.9.F.5a 5.9.9.F.5b 5.9.9.F.5c 5.9.9.F.5e 5.9.9.F.5f}"
# 5.9.9.F.3a/3b/3c: имена канареек продуктовых контролей. Вынесены сюда по
# той же причине, что и прочие параметры: величина, на которой стоит вердикт
# пункта волны, обязана лежать в артефактах замера.
export FP_CONTROL_TAG="${FP_CONTROL_TAG:-ebpfguard-f4-$(date -u +%Y%m%d_%H%M%S)}"

echo "=== [0/14] преflight: что именно меряется ==="
cd /opt/ebpf-guard || die "нет /opt/ebpf-guard"
git log -1 --format='коммит замера: %H %s (%ci)'
git status --porcelain | sed 's/^/  локальная правка: /'
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (до пересборки): /' || true
./build/ebpf-guard rules check tests/rules/ 2>&1 | tail -5

echo "--- преflight: интерпретатор ---"
echo "  bash: ${BASH_VERSION}"
[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "bash ${BASH_VERSION} — run-gate.sh требует 4+ (declare -A, секция 19)"

echo "--- преflight: go-тесты волн 5.9.4/5.9.5 ---"
go test -count=1 ./internal/enforcer/ -run 'DryRunSentinel|TestExecuteKill_DryRun|TestExecuteThrottle_DryRun' 2>&1 | tail -3
go test -count=1 -v ./internal/correlator/ -run 'TestDestructiveRulesInventory_RepoRules|TestExclusionsCollidingWithAttackerComms_RepoRules|TestRootkitBPFRules_MatchCommandNotCaller|TestKillScenarioControlRule_ActionIsKill' 2>&1 \
    | grep -E 'разрушительных|правил проверено|^(ok|FAIL|--- )' | sed 's/^/  /'

echo "--- преflight: go-тесты волны 5.9.6 ---"
go test -count=1 ./internal/bpf/ -run 'SumPerCPU' 2>&1 | tail -3
go test -count=1 ./internal/collector/ -run 'DNS|Malformed' 2>&1 | tail -3

echo "--- преflight: go-тесты волны 5.9.7 (риск №3: сужение != ослепление) ---"
go test -count=1 -v ./internal/correlator/ -run 'TestWave597' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave597' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.7e/f красные — сужение rootkit_ssh_authorized_keys_modified/sigma_sensitive_dir_listing не доказано как не-ослепление (риск №3)"

# Волна 5.9.8. Два независимых набора, оба обязательны:
#   - парсер DNS-заголовка (5.9.8a): TLS-ClientHello не становится DNS-событием
#     НИ ПРИ КАКОЙ причине отказа, валидный заголовок не отвергается;
#   - сужение webshell_script_write_via_web_process по comm (5.9.8g) вместе с
#     его позитивной половиной — тот же риск №3 в третий раз.
echo "--- преflight: go-тесты волны 5.9.8 ---"
go test -count=1 -v ./internal/collector/ -run 'TestParseDNSWireMessage' 2>&1 | grep -E '^(--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/collector/ -run 'TestParseDNSWireMessage' >/dev/null 2>&1 \
    || die "юнит-тесты разбора DNS-заголовка (5.9.8a) красные — второй заслон против TLS в DNS-пути не доказан"
go test -count=1 -v ./internal/correlator/ -run 'TestWave598' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave598' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.8g красные — сужение webshell_script_write_via_web_process не доказано как не-ослепление (риск №3)"

# Волна 5.9.9. Сужение webshell_crontab_modification по comm (5.9.9b,
# находка №98) — тот же риск №3 в четвёртый раз, и его юнит-половина обязана
# стоять здесь по той же причине, что 5.9.7e и 5.9.8g: сужение, ослепившее
# правило, красит преflight, а не идёт в отчёт после idle-часа.
echo "--- преflight: go-тесты волны 5.9.9 ---"
go test -count=1 -v ./internal/correlator/ -run 'TestWave599' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestWave599' >/dev/null 2>&1 \
    || die "юнит-тесты 5.9.9b красные — сужение webshell_crontab_modification не доказано как не-ослепление (риск №3)"

echo "--- преflight: синтаксис харнесса ---"
bash -n $SETUP/attacks/run-all-attacks.sh || die "run-all-attacks.sh: синтаксическая ошибка"
bash -n $SETUP/attacks/run-gate.sh         || die "run-gate.sh: синтаксическая ошибка"
bash -n $SETUP/attacks/replay-gate.sh      || die "replay-gate.sh: синтаксическая ошибка"
bash -n $SETUP/idle-run.sh                 || die "idle-run.sh: синтаксическая ошибка"
echo "  синтаксис всех четырёх скриптов ок"

# СТОРОЖ НАХОДКИ №86 (P0), без изменений с №2.9.7: корень наблюдателя не
# шире пролога, иначе observer_should_drop() уронит все атаки прогона.
echo "--- преflight: сторож находки №86 (корень наблюдателя не шире пролога) ---"
grep -q 'run_measurement_prologue()' $SETUP/attacks/run-all-attacks.sh \
    || die "находка №86: run_measurement_prologue отсутствует — регистрация observer_root не сужена до пролога"
top_level_reg=$(grep -nE '^(observer_root_register[[:space:]]*$|echo[[:space:]]+"?\$\$"?[[:space:]]*>)' $SETUP/attacks/run-all-attacks.sh || true)
if [ -n "$top_level_reg" ]; then
    echo "$top_level_reg" | sed 's/^/  регистрация на верхнем уровне: /'
    die "находка №86: регистрация observer_root вызвана на верхнем уровне run-all-attacks.sh — все атаки прогона будут отброшены в ядре, recall станет 0/6"
fi
echo "  ок: корень наблюдателя регистрируется только внутри пролога"

# 5.9.9.Fg (находка №112, ЭТА ПРАВКА): все сторожа «определён и вызывается»
# ниже искали вызов ПО ВСЕМУ файлу — а вызовы шагов есть ещё и в
# interactive_mode (пункты меню 1 и 6), который на замере не исполняется
# никогда. Поэтому сторож проходил на функции, отсутствующей в full_run(), —
# ровно то, что он обязан ловить, и ровно это и случилось с
# run_cred_proc_maps_positive_control (её не было в full_run(); исправлено
# той же правкой). Проверяем ТЕЛО full_run(), а не файл.
# Шаги волны делятся на два класса, и оба законны:
#   - внутри full_run() — окно замера (крит. 7 читает их по манифесту);
#   - внутри своей ветки main() (--dns-fd-reuse-controls, --counting-control,
#     --ringbuf-overflow, --cred-proc-maps-control) — вне окна, по запрету №3.
# Незаконен ровно один случай: вызов ТОЛЬКО из interactive_mode, который на
# замере не исполняется никогда. Поэтому ищем вызов в файле БЕЗ тела
# interactive_mode.
calls_outside_menu() {
    sed '/^interactive_mode() {/,/^}/d' $SETUP/attacks/run-all-attacks.sh | grep -qE "^[[:space:]]+$1[[:space:]]*$"
}
calls_in_full_run() {
    sed -n '/^full_run() {/,/^}/p' $SETUP/attacks/run-all-attacks.sh | grep -qE "^[[:space:]]+$1[[:space:]]*$"
}

echo "--- преflight: позитивный контроль 5.9.7e присутствует в цепочке (риск №3) ---"
grep -q 'run_ssh_keys_positive_control()' $SETUP/attacks/run-all-attacks.sh || die "риск №3: run_ssh_keys_positive_control отсутствует"
calls_in_full_run run_ssh_keys_positive_control || die "риск №3: run_ssh_keys_positive_control определён, но не вызывается из full_run()"
echo "  ок: позитивный контроль 5.9.7e в цепочке"

# То же требование, но для волны 5.9.8: три шага харнесса, без которых три
# пункта постановки остаются без входа. Проверяется И определение, И вызов —
# «определён, но не вызывается» уже случалось (5.9.7e).
echo "--- преflight: шаги волны 5.9.8 присутствуют в цепочке ---"
for fn in run_dns_fd_reuse_negative_control run_dns_cross_thread_positive_control run_webshell_script_write_positive_control; do
    grep -q "^$fn()" $SETUP/attacks/run-all-attacks.sh || die "5.9.8: $fn отсутствует в run-all-attacks.sh — соответствующий пункт постановки без входа"
    calls_outside_menu "$fn" || die "5.9.8: $fn вызывается только из interactive_mode — на замере шаг не исполнится (находка №112)"
    echo "  ок: $fn определён и вызывается"
done

# То же для волны 5.9.9: позитивная половина сужения (5.9.9b) и сценарий
# container_escape_cap_sys_admin (5.9.9c, находка №101). Обе категории
# читает крит. 7 (recall) — функция, определённая, но не вызванная, дала бы
# не «контроль не исполнился», а тихое отсутствие категории в манифесте.
echo "--- преflight: шаги волны 5.9.9 присутствуют в цепочке ---"
for fn in run_webshell_crontab_positive_control run_container_escape_positive_control; do
    grep -q "^$fn()" $SETUP/attacks/run-all-attacks.sh || die "5.9.9: $fn отсутствует в run-all-attacks.sh — соответствующий пункт постановки без входа"
    calls_in_full_run "$fn" || die "5.9.9: $fn определён, но не вызывается из full_run() — шаг не исполнится"
    echo "  ок: $fn определён и вызывается"
done

# То же для волны 5.9.9.F: позитивный контроль cred_proc_maps_mass_read
# (5.9.9.Fa, находка №107). Стоит отдельным блоком, а не строкой в цикле
# выше, потому что у него две половины, и без второй сужение правила
# недоказуемо: шаг в цепочке И юнит-тесты на оба исхода. Ревизия волны
# 5.9.9.F: постановка считала этот контроль уже существующим — его не было,
# и правило, суженное без него, дало бы 0 алертов за прогон при живом
# detection-baseline.txt, то есть красный крит. 6 с формулировкой «регресс
# детекта».
echo "--- преflight: шаг и юнит-тесты волны 5.9.9.F присутствуют (5.9.9.Fa, №107) ---"
grep -q "^run_cred_proc_maps_positive_control()" $SETUP/attacks/run-all-attacks.sh     || die "5.9.9.Fa: run_cred_proc_maps_positive_control отсутствует — суженное cred_proc_maps_mass_read остаётся без единого входа (находка №57)"
calls_in_full_run run_cred_proc_maps_positive_control     || die "5.9.9.Fa: run_cred_proc_maps_positive_control определён, но не вызывается из full_run() — шаг не исполнится (находка №112)"
grep -q '\^/proc/\[0-9\]+/(task/\[0-9\]+/)?(maps|mem|environ)\$' rules/credential-access.yaml     || die "5.9.9.Fa: numeric-PID предикат отсутствует в rules/credential-access.yaml — правка №107 не в дереве"
go test -count=1 -v ./internal/correlator/ -run 'TestP1_17_CredProcMapsMassRead_NumericPID|TestP1_17_ProcSelfNarrowingIsRuleLocal' 2>&1     | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/correlator/ -run 'TestP1_17_CredProcMapsMassRead_NumericPID|TestP1_17_ProcSelfNarrowingIsRuleLocal' >/dev/null 2>&1     || die "5.9.9.Fa: юнит-тесты красные — либо сужение не доказано как не-ослепление, либо нарушен запрет волны (/proc/self у owasp_web_sensitive_file_read)"
echo "  ок: шаг вызывается из full_run(), оба юнит-теста зелёные"

# Волна 5.9.9.F.2. Правок правил в ней нет, поэтому сторожа здесь другие:
# они охраняют не «сужение != ослепление», а «пункт волны вообще способен
# исполниться». Каждый из трёх ловит ровно тот класс дефекта, который уже
# случался с этой волной на ревью: шаг написан, но не вызывается; режим
# удалён, но вернулся; продуктовая правка откачена частично.
echo "--- преflight: шаг 5.9.9.F.2b присутствует в цепочке (№125) ---"
grep -q "^run_cpu_pressure_control()" $SETUP/attacks/run-all-attacks.sh \
    || die "5.9.9.F.2b: run_cpu_pressure_control отсутствует в run-all-attacks.sh — крит. 14 останется в SKIP четвёртый замер подряд, приёмка SKIP=0 недостижима"
calls_outside_menu run_cpu_pressure_control \
    || die "5.9.9.F.2b: run_cpu_pressure_control вызывается только из interactive_mode — на замере шаг не исполнится (находка №112)"
grep -q -- '--cpu-pressure-control' $SETUP/attacks/run-all-attacks.sh \
    || die "5.9.9.F.2b: ветки --cpu-pressure-control нет в main() — шаг [9.7/14] ниже не сможет его позвать"
# Маркер шага обязан искаться ПО МАСКЕ: шаг идёт вне окна замера, отдельным
# вызовом со своим TIMESTAMP, и поиск по TIMESTAMP основного прогона не
# нашёл бы его никогда (ревизия исполнения волны, Р2).
grep -q 'cpu_pressure_control_marker=$(latest_marker' $SETUP/attacks/run-gate.sh \
    || die "5.9.9.F.2b: run-gate.sh ищет маркер cpu-pressure-control не по маске — крит. 14 не увидит исполнившийся шаг (ревизия волны, Р2)"
echo "  ок: шаг определён, вызывается своей веткой main(), маркер ищется по маске"

echo "--- преflight: режим drop контроля счётности не вернулся (5.9.9.F.2a, №123) ---"
# Ищется ИСПОЛНЯЕМАЯ строка, а не любое вхождение: имя переменной осталось в
# комментарии run-all-attacks.sh, объясняющем, почему режим удалён, — и это
# правильное место для него.
grep -vE '^[[:space:]]*#' $SETUP/attacks/run-all-attacks.sh | grep -q 'COUNTING_CONTROL_DROP_N' \
    && die "5.9.9.F.2a: COUNTING_CONTROL_DROP_N вернулся в исполняемый код run-all-attacks.sh — режим drop не переполняет кольцо и никогда не переполнял (находка №123), его половину тождества несёт крит. 22"
grep -qE '^for c20_mode in idle; do$' $SETUP/attacks/run-gate.sh \
    || die "5.9.9.F.2a: секция 20 run-gate.sh перебирает не только idle — режим drop удалён волной, его SKIP был одним из четырёх, которые эта волна снимает"
grep -q 'formula="${4:-legacy}"' $SETUP/attacks/run-gate.sh \
    || die "5.9.9.F.2a: counting_control_residual без параметра formula — крит. 22 считает старым асимметричным допуском, который проходит любой результат (находка №124)"
echo "  ок: режим drop удалён, крит. 22 считает замкнутым тождеством"

# ============================ ВОЛНА 5.9.9.F.3 ============================
# Три продуктовых пункта (3a/3b/3c) и четыре измерительных. Сторожа ниже
# охраняют РАЗНОЕ, и это различие существенно:
#   - у продуктовых проверяется, что правка ЛЕЖИТ В ДЕРЕВЕ и что её
#     юнит-половина зелёная. Живая половина (правило не ослепло) стоит
#     ниже, шагом [9.6/14], и её здесь заменить нечем;
#   - у измерительных проверяется, что механизм СПОСОБЕН упасть.
# Определения помощников стоят ЗДЕСЬ, до первого сторожа волны, а не
# перед сторожем 3b: сторож 3a ниже зовёт rule_condition() раньше, и при
# определении ниже по файлу bash печатал "command not found", а `|| die`
# превращал это в ЛОЖНЫЙ СТОП «правка не в дереве» на правленом дереве
# (предпрогон №2.9.9.F.3, 10:08 UTC).
#
# Интервальные квантификаторы ({0,4}) здесь НЕ используются намеренно:
# awk на стенде — mawk, и полагаться на их поддержку значит получить сторож,
# который молча ничего не матчит. Отступы в rules/*.yaml фиксированы: ключи
# правила — четыре пробела, вложенность условия — шесть и больше.
rule_condition() {
    sed -n "/id: $1/,/^  - id:/p" "$2" | awk '
        /^    (condition|condition_group):/ { inc=1 }
        /^    (severity|action|tags|exceptions|enrichment|labels|name|description):/ { inc=0 }
        inc && !/^[[:space:]]*#/'
}
rule_meta() {
    sed -n "/id: $1/,/^  - id:/p" "$2" | grep -E '^    (severity|event_type|action):'
}
# Ревизия волны 5.9.9.F.3 (2026-08-26): у сторожа 3c ниже rule_condition()
# давал ЛОЖНОЕ ПАДЕНИЕ. Структурный признак песочницы живёт в блоке
# exceptions:, а rule_condition() ровно на строке `exceptions:` выключает
# печать — то есть сторож искал признак в единственном месте, где его по
# устройству правила быть не может, и на правленом дереве давал f3c_hit=0.
# rule_predicate() — это то, что обещал (но нигде не определял) комментарий
# сторожа 3b: тело правила без name:/description: и их свёрнутых
# продолжений, то есть условия, метаданные И исключения.
rule_predicate() {
    sed -n "/id: $1/,/^  - id:/p" "$2" | awk '
        /^    (condition|condition_group|severity|action|tags|event_type|exceptions|enrichment|labels):/ { inc=1 }
        /^    (name|description):/ { inc=0 }
        inc && !/^[[:space:]]*#/'
}

echo "--- преflight: 5.9.9.F.3a — rootkit_hidden_dir_dev заякорен и не видит штатные ноды /dev (№131) ---"
grep -q 'id: rootkit_hidden_dir_dev' rules/rootkit-detection.yaml \
    || die "5.9.9.F.3a: правило rootkit_hidden_dir_dev исчезло из rules/rootkit-detection.yaml — удаление вместо сужения приёмкой волны не является"
# Якорь ищется в УСЛОВИИ (rule_condition выше), а не в теле правила: тело
# содержит и имя, и описание, и tags — сторож по телу дал бы ложный пропуск,
# как это и случилось при первой редакции сторожа 3b.
rule_condition rootkit_hidden_dir_dev rules/rootkit-detection.yaml | grep -qE '\^/dev/' \
    || die "5.9.9.F.3a: regex rootkit_hidden_dir_dev не заякорен (^) в условии — /dev/ продолжит матчиться подстрокой внутри /tmp/namespace-dev-*/dev/mqueue (находка №131), правка не в дереве"
sed -n '/id: rootkit_hidden_dir_dev/,/^  - id:/p' rules/rootkit-detection.yaml | grep -qE 'urandom|random|console|exceptions:' \
    || die "5.9.9.F.3a: у rootkit_hidden_dir_dev нет ни исключения, ни упоминания штатных нод — /dev/urandom (7 строчных букв) продолжит давать critical по regex [a-z]{6,}, а это 10 из 12 срабатываний правила на №2.9.9.F.2"
echo "  ок: правило на месте, regex заякорен, штатные ноды учтены"

echo "--- преflight: 5.9.9.F.3b — privesc_suid_suspicious_path проверяет SUID/exec либо переименован (№132) ---"
grep -q 'id: privesc_suid_suspicious_path' rules/privesc.yaml \
    || die "5.9.9.F.3b: правило privesc_suid_suspicious_path исчезло из rules/privesc.yaml — удаление вместо сужения приёмкой волны не является"
# ВАЖНО: искать надо в ПРЕДИКАТЕ, а не в тексте правила. Описание правила
# буквально содержит слова «SUID binary was executed», и сторож, читающий
# тело целиком, давал ложный пропуск на неправленом дереве — то есть был бы
# критерием без достижимого FAIL, ровно тем классом (№123/№124), который
# чинила прошлая волна. rule_predicate() выбрасывает name:/description: и
# их свёрнутые продолжения, оставляя только условия и метаданные.
# ВАЖНО: искать надо в БЛОКЕ УСЛОВИЯ, а не в теле правила целиком. Проверено
# на неправленом дереве обоими исходами, и обе более грубые редакции этого
# сторожа давали ЛОЖНЫЙ ПРОПУСК: описание правила буквально содержит «SUID
# binary was executed», а tags: — слово `suid`. Сторож, читающий тело
# целиком, был бы критерием без достижимого FAIL — ровно тот класс
# (№123/№124), который чинила прошлая волна.
f3b_cond=$(rule_condition privesc_suid_suspicious_path rules/privesc.yaml)
f3b_meta=$(rule_meta privesc_suid_suspicious_path rules/privesc.yaml)
if echo "$f3b_cond" | grep -qiE 'suid|setuid|mode|exec|proc\.args'; then
    echo "  privesc_suid_suspicious_path: предикат получил условие на SUID/exec"
elif echo "$f3b_meta" | grep -qE 'severity:[[:space:]]*(warning|info)'; then
    echo "  privesc_suid_suspicious_path: предикат не выражен, правило понижено до warning (второй допустимый исход постановки)"
else
    die "5.9.9.F.3b: privesc_suid_suspicious_path остался critical и по-прежнему не проверяет ни бит SUID, ни факт exec — 37 критикалов при нуле истинных (находка №132), правка не в дереве"
fi
echo "$f3b_cond" | grep -qE '\^/tmp/' \
    || die "5.9.9.F.3b: regex privesc_suid_suspicious_path не заякорен (^) — правило продолжит матчить /tmp/ подстрокой в любом месте пути"
f3b_sigma=$(rule_condition sigma_binary_in_tmp_executed rules/sigma-linux.yaml)$(rule_meta sigma_binary_in_tmp_executed rules/sigma-linux.yaml)
[ -n "$f3b_sigma" ] \
    || die "5.9.9.F.3b: правило sigma_binary_in_tmp_executed исчезло из rules/sigma-linux.yaml — удаление вместо сужения приёмкой волны не является"
# proc\.args — это и есть проверка факта exec: поле заполняется коллектором
# ТОЛЬКО на execve/execveat (internal/collector/syscall.go), и именно на нём
# живёт правило-компаньон exec_from_tmp. Ревизия волны (2026-08-26): без
# этой альтернативы сторож падал на правленом дереве, то есть запрещал
# единственный исход, которым пункт вообще выразим.
echo "$f3b_sigma" | grep -qiE 'elf|exec|magic|mode|proc\.args|severity:[[:space:]]*info' \
    || die "5.9.9.F.3b: sigma_binary_in_tmp_executed по-прежнему голый prefix /tmp/ без проверки ELF и exec — правило с именем «ELF binary executed» срабатывает на создание каталога (находка №132)"
echo "  ок: оба правила семьи /tmp правлены"

echo "--- преflight: 5.9.9.F.3c/5.9.9.F.4a — признак песочницы systemd структурный, а не список comm, и покрывает двенадцать правил (№133/№141) ---"
# Ключевая проверка волны. Литеральный список comm НЕ чинит дефект: comm
# ребёнка равен (mandb), а не systemd, и следующий юнит даст (logrotate),
# (apt-daily), (fstrim) — ровно так не обобщилось исключение №111.
# 5.9.9.F.4a (№141): список расширен с исходных шести правил 3c до
# фактических двенадцати — вторая половина взята из архива отклонённого
# замера №2.9.9.F.3 поимённо.
f3c_hit=0
f3c_total=12
for r in container_escape_mount container_escape_chroot container_escape_unshare_user \
         container_escape_cap_sys_admin privesc_unshare_user_ns cis_5_2_1_privileged_container \
         proc_inject_memfd_create integrity_proc_self_exe_exec sigma_memfd_create_anonymous \
         rootkit_pam_module_added cred_shadow_read drift_new_library_in_system_dir; do
    body=$(for y in rules/*.yaml; do rule_predicate "$r" "$y"; done)
    [ -n "$body" ] || die "5.9.9.F.3c/5.9.9.F.4a: правило $r не найдено в rules/*.yaml — двенадцать правил пункта обязаны остаться на месте, удаление приёмкой не является"
    if echo "$body" | grep -qE 'ppid|systemd-private|namespace-dev|parent_comm'; then
        f3c_hit=$((f3c_hit + 1))
        echo "  $r: структурный признак песочницы присутствует"
    else
        echo "  $r: структурного признака НЕТ"
    fi
done
# Дробление пункта объявляется ДО правки (постановка). Здесь это означает:
# либо признак есть у всех двенадцати, либо переменная объявила дробление явно.
if [ "$f3c_hit" -lt "$f3c_total" ] && [ "${WAVE_F3C_SPLIT:-0}" != "1" ]; then
    die "5.9.9.F.3c/5.9.9.F.4a: структурный признак песочницы systemd есть только у $f3c_hit правил из $f3c_total, и дробление пункта НЕ объявлено (WAVE_F3C_SPLIT=1). Постановка требует объявлять дробление до правки, а не после FAIL — иначе замер измерит половину волны и назовёт это приёмкой"
fi
[ "$f3c_hit" -ge 1 ] \
    || die "5.9.9.F.3c/5.9.9.F.4a: ни у одного из двенадцати правил нет структурного признака песочницы — правка №133/№141 не в дереве вовсе, и idle-час снова даст три verdict=\"attack\" на старте любого sandboxed-юнита"
# Вторая половина пункта: pid 1 перестаёт ловить сам себя на /proc/1/*.
# Предикат тот же, что у №107 (self никогда не интересен ЭТОМУ правилу).
for r in container_escape_init_proc mitre_sandbox_detect_proc_read; do
    body=$(for y in rules/*.yaml; do rule_predicate "$r" "$y"; done)
    [ -n "$body" ] || die "5.9.9.F.3c: правило $r не найдено — вторая половина пункта без входа"
    echo "$body" | grep -qE 'ppid|pid|exceptions:' \
        || echo "  ВНИМАНИЕ: $r не различает чтение СВОЕГО /proc/1/* — pid 1 продолжит ловить сам себя (родня находки №107)"
done
echo "  ок: 5.9.9.F.3c/5.9.9.F.4a в дереве ($f3c_hit/$f3c_total правил со структурным признаком)"

echo "--- преflight: 5.9.9.F.3d — фаза idle проверяется раньше «наведено преflight'ом» (№134) ---"
# Ищется ПОРЯДОК ветвления, а не наличие признака: до правки in_induced
# стоял первым и поглощал idle целиком, потому что idle-час предшествует
# baseline по построению цепочки.
# Печать (диагностика для человека) обязана видеть ТЕ ЖЕ строки, что и
# проверка ниже: после правки 3d ветка induced существует в двух формах —
# составной `if [ -n "$phase_parts" ] && [ "$in_induced" -eq 1 ]` и одиночной
# `elif [ "$in_induced" -eq 1 ]`. Прежний шаблон с якорем ^ не матчил ни ту,
# ни другую, и «порядок веток» печатался БЕЗ induced вовсе — читателю
# казалось, что ветки нет в дереве.
awk '/&& \[ "\$in_induced" -eq 1 \]; then/{print NR": phase_parts+induced (составная)"} /^[[:space:]]*elif \[ "\$in_induced" -eq 1 \]; then/{print NR": induced (одиночная)"} /^[[:space:]]*elif \[ -n "\$phase_parts" \]; then/{print NR": phase_parts"} /^[[:space:]]*elif \[ -z "\$IDLE_METRICS_START" \]/{print NR": fallback"}' \
    $SETUP/attacks/run-gate.sh | sort -n | sed 's/^/  порядок веток: /'
# ПЕРВОЕ вхождение каждого, а не последнее: `if [ "$in_induced" -eq 1 ]`
# встречается дважды — ветка печати фазы и ветка счётчика ниже, — и awk,
# берущий последнее, сравнивал бы ветку счётчика с веткой печати и всегда
# отвечал «порядок верный».
if awk 'i==0 && /if \[ "\$in_induced" -eq 1 \]; then/{i=NR} p==0 && /elif \[ -n "\$phase_parts" \]; then/{p=NR} END{exit !(i>0 && p>0 && i<p)}' $SETUP/attacks/run-gate.sh; then
    die "5.9.9.F.3d: в run-gate.sh ветка in_induced по-прежнему стоит ПЕРЕД phase_parts — метка «наведено шагом преflight'а» продолжит поглощать фазу idle целиком (находка №134), и семь idle-FP пакета systemd уйдут в detection-baseline.txt как артефакты преflight-шага"
fi
echo "  ок: фаза idle проверяется раньше induced"

echo "--- преflight: 5.9.9.F.3e — три SKIP бухгалтерии починены (№135/№136/№137) ---"
# №135: текст fail() крит. 5.9.9.F.1d несёт свой id наравне с pass().
awk '/^[[:space:]]*fail "новый\(е\) актор\(ы\) idle-часа вне idle-actors.txt/{print}' $SETUP/attacks/run-gate.sh \
    | grep -q '5.9.9.F.1d, №115' \
    || die "5.9.9.F.3e/№135: текст fail() крит. 5.9.9.F.1d не несёт «5.9.9.F.1d, №115» — упавший критерий снова засчитается как неисполнившаяся ветка и оштрафует прогон дважды за один исход"
# №136: record_covered для 5.9.9.Fc вызывается ПОСЛЕ загрузки индекса.
if awk '/record_covered "окно журнала:"/{r=NR} /^CRITERIA_INDEX_FILE=/{c=NR} END{exit !(r>0 && c>0 && r<c)}' $SETUP/attacks/run-gate.sh; then
    die "5.9.9.F.3e/№136: record_covered \"окно журнала:\" по-прежнему вызывается ДО загрузки criteria-index.txt — на пустых массивах CRITERIA_SELF_* вызов является no-op по построению, и 5.9.9.Fc не покрывается никогда, каким бы ни был исход критерия"
fi
# №137: паттерн 5.9.9.F.2b в индексе взят с pass()/fail(), а не с echo.
f3e_pat=$(awk -F'\t' '$1=="5.9.9.F.2b"{print $3}' $SETUP/attacks/criteria-index.txt | head -1)
[ -n "$f3e_pat" ] || die "5.9.9.F.3e/№137: у пункта 5.9.9.F.2b нет строки в criteria-index.txt"
awk -v pat="$f3e_pat" '
        /^[[:space:]]*(pass|fail|warn|skip) / && index($0, pat) > 0 { found=1 }
        END { exit !found }' $SETUP/attacks/run-gate.sh \
    || die "5.9.9.F.3e/№137: паттерн 5.9.9.F.2b («$f3e_pat») не найден ни в одном вызове pass()/fail()/warn()/skip() — он снова взят со строки echo, через record_covered такие строки не проходят, и критерий останется в SKIP при любом исходе"
echo "  ок: все три дефекта бухгалтерии починены в дереве"

echo "--- преflight: 5.9.9.F.3f — каждый пункт волны заведён в criteria-index.txt (№138) ---"
f3f_missing=""
for wid in $WAVE_CRITERIA_IDS; do
    awk -F'\t' -v w="$wid" '!/^[[:space:]]*#/ && $1==w {found=1} END{exit !found}' $SETUP/attacks/criteria-index.txt \
        || f3f_missing="$f3f_missing $wid"
done
# Задним числом — два пункта прошлой волны, обнаруженные находкой №138.
for wid in 5.9.9.F.2c 5.9.9.F.2g; do
    awk -F'\t' -v w="$wid" '!/^[[:space:]]*#/ && $1==w {found=1} END{exit !found}' $SETUP/attacks/criteria-index.txt \
        || f3f_missing="$f3f_missing $wid(задним числом)"
done
if [ -n "$f3f_missing" ]; then
    die "5.9.9.F.3f/№138: пункты постановки без строки в criteria-index.txt:$f3f_missing. Старый сторож «непокрытых пунктов: 0» этого не видит по построению — он перебирает сам индекс. Пункт без строки нигде не проверяется, то есть исчезает та же дыра, которую закрывала 5.9.7h (№83)"
fi
echo "  ок: все $(echo $WAVE_CRITERIA_IDS | wc -w) пунктов волны + 5.9.9.F.2c/2g заведены в индексе"

echo "--- преflight: 5.9.9.F.3g — записи журнала (№139/№140) ---"
go test -count=1 ./internal/collector/ -run 'DNS|Truncat' >/dev/null 2>&1 \
    || echo "  ВНИМАНИЕ: юнит-тесты разбора DNS красные — пункт 3g (словарь причин, №140) под вопросом; на вердикт замера не влияет (P3)"
echo "  ок (P3, на вердикт замера не влияет)"

echo "--- преflight: 5.9.9.F.4e — exfil_archive_to_network_pipe несёт предикат архиватора (№145) ---"
grep -q 'id: exfil_archive_to_network_pipe' rules/exfiltration-extended.yaml \
    || die "5.9.9.F.4e: правило exfil_archive_to_network_pipe исчезло из rules/exfiltration-extended.yaml — удаление приёмкой не является"
# Ищется в ПРЕДИКАТЕ, а не в теле: description правила и до правки говорил
# «tar/zip/gzip», именно этим находка №145 и была — имя обещало предикат,
# которого не было. Сторож по телу дал бы ложный пропуск.
rule_predicate exfil_archive_to_network_pipe rules/exfiltration-extended.yaml | grep -qE 'parent_comm' \
    || die "5.9.9.F.4e: в условии exfil_archive_to_network_pipe нет proc.parent_comm — предикат архиватора не в дереве, правило по-прежнему алертит на любой execve сетевой утилиты (96 алертов, первое место по объёму на отклонённом №2.9.9.F.3)"
rule_predicate exfil_archive_to_network_pipe rules/exfiltration-extended.yaml | grep -qE '"tar"|\btar\b' \
    || die "5.9.9.F.4e: список архиваторов в предикате пуст или не содержит tar — сужение объявлено, но не выражено"
grep -q 'run_exfil_archive_parent_positive_control' $SETUP/attacks/run-all-attacks.sh \
    || die "5.9.9.F.4e: в манифесте атак нет run_exfil_archive_parent_positive_control — правка, уменьшающая число алертов, без позитивного контроля неотличима от ослепления (риск волны, названный заранее)"
grep -q 'run_exfil_archive_parent_positive_control' <(awk '/^full_run\(\)/,/^}/' $SETUP/attacks/run-all-attacks.sh) \
    || die "5.9.9.F.4e: run_exfil_archive_parent_positive_control определён, но не вызывается из full_run() — контроль, который не исполняется, величиной 10 не является"
echo "  ок: предикат архиватора в дереве, позитивный контроль подключён к full_run()"
echo "  ГРАНИЦА ПУНКТА (записана постановкой заранее): выражена только РОДИТЕЛЬСКАЯ половина"
echo "  (tar -> curl). Классический shell-пайп tar czf - | curl делает их БРАТЬЯМИ, и движок"
echo "  такой связи не хранит — величина 10 читается по родительской форме, sibling-форма"
echo "  остаётся невыполненной до отдельной stateful-фичи коррелятора (см. plan.md, 4e)."

echo "--- преflight: 5.9.9.F.5a — позитивный контроль exfil даёт comm=tar, а не comm интерпретатора (№152) ---"
grep -q 'run_exfil_archive_parent_positive_control' $SETUP/attacks/run-all-attacks.sh \
    || die "5.9.9.F.5a: run_exfil_archive_parent_positive_control пропал из run-all-attacks.sh"
grep -q 'comm_verified' $SETUP/attacks/run-all-attacks.sh \
    || die "5.9.9.F.5a: контроль не пишет поле comm_verified в манифест — сторож блока величины 10 не сможет отличить 'comm=tar подтверждён' от 'контроль подтвердил не то' (та же болезнь №152 — 0 неотличим от неисполнения)"
grep -q '/proc/self/comm' <(awk '/^run_exfil_archive_parent_positive_control\(\)/,/^}/' $SETUP/attacks/run-all-attacks.sh) \
    || die "5.9.9.F.5a: контроль не читает /proc/self/comm архиватора — доказательство comm=tar отсутствует, позитивный контроль остаётся недостоверным ровно как на №2.9.9.F.4"
echo "  ок: контроль читает /proc/self/comm архиватора и пишет comm_verified в манифест"

echo "--- преflight: 5.9.9.F.4f — семейство drift правлено, базовая линия решена явно (№146) ---"
rule_predicate drift_new_exec_critical rules/drift-rules.yaml | grep -q 'proc.args' \
    || die "5.9.9.F.4f: drift_new_exec_critical по-прежнему не читает факт exec (нет proc.args в условии) — предикат op==open не означает исполнения, и правило остаётся первым местом по критикалам аптайма (44 на №2.9.9.F.2)"
rule_predicate drift_new_exec_critical rules/drift-rules.yaml | grep -qE 'event_type:[[:space:]]*syscall' \
    || die "5.9.9.F.4f: drift_new_exec_critical остался event_type: file — proc.args на файловом событии не заполняет НИ ОДИН коллектор (тот же дефект, которым был ослеплён sigma_binary_in_tmp_executed до ревизии 5.9.9.F.3)"
if grep -qE '^[[:space:]]*values:[[:space:]]*\[\][[:space:]]*$' rules/drift-rules.yaml; then
    die "5.9.9.F.4f: в rules/drift-rules.yaml остался пустой values: [] — «всегда истина» в предикате, и загрузчик 5.9.9.F.4g теперь ОТВЕРГНЕТ этот файл целиком (порядок пунктов волны: 4f раньше 4g)"
fi
# Третий риск волны, названный постановкой заранее: включение
# profiler.drift_baseline даёт learning_period ровно длиной idle-часа. Выбор
# волны 4f — НЕ включать (см. plan.md и блок-комментарий в конце файла
# правил). Сторож ловит расхождение конфига с этим выбором: включили — обязан
# быть доказан закрытый learning ДО открытия baseline, а этого доказательства
# в дереве нет.
if awk '/^profiler:/{p=1} p && /drift_baseline:/{d=1} d && /enabled:[[:space:]]*true/{print; exit}' $SETUP/config-test.yaml | grep -q true; then
    die "5.9.9.F.4f: в config-test.yaml включён profiler.drift_baseline, а волна выбрала обратное. learning_period по умолчанию 3600с — ровно длина idle-часа: шесть правил класса замолчат по построению, и обязательные величины 3 и 11 станут ЛОЖНО-зелёными. Либо вернуть enabled: false, либо предъявить сторож, доказывающий закрытие learning ДО открытия baseline (постановка требует сторожа, а не расчёта на таймингах)"
fi
grep -q 'Class-wide baseline decision' rules/drift-rules.yaml \
    || die "5.9.9.F.4f: в rules/drift-rules.yaml нет записи о решении по базовой линии — постановка требует объявить выбор ДО правки и записать его; без записи следующая сессия включит baseline, не увидев риска learning_period == idle-час"
echo "  ок: drift_new_exec_critical переведён на факт exec, пустых values: [] нет, решение по baseline записано"

echo "--- преflight: 5.9.9.F.4g — загрузчик отвергает пустой values: [] (№148) ---"
go test -count=1 ./internal/correlator/ -run 'TestRuleLoaderEmptyValuesList' >/dev/null 2>&1 \
    || die "5.9.9.F.4g: юнит-тест TestRuleLoaderEmptyValuesList красный или отсутствует — сторож загрузчика не в дереве"
# Не `./build/ebpf-guard rules check`: на этом шаге в build/ лежит ЕЩЁ СТАРЫЙ
# бинарь (пересборка — шаг [3/14]), а у старого загрузчика этой проверки нет,
# то есть зелёный ответ ничего не доказывал бы. Ищем сам дефект в наборе.
f4g_empty=$(grep -rn -E '^[[:space:]]*values:[[:space:]]*\[\][[:space:]]*$' rules/ || true)
[ -z "$f4g_empty" ] \
    || die "5.9.9.F.4g: в наборе rules/ остались пустые values: [] — после ужесточения загрузчика агент не поднимется с этим набором вовсе: $(echo "$f4g_empty" | tr '\n' ' ')"
echo "  ок: загрузчик отвергает пустой список, весь набор rules/ грузится"

echo "--- преflight: 5.9.9.F.4h — записи журнала: хопы различимы, порог DNS выше межвсплескового интервала (№149/№150) ---"
go test -count=1 ./internal/collector/ -run 'TestDropLogger_RecordDoesNotDuplicateCollectorKeyAndDistinguishesHops' >/dev/null 2>&1 \
    || die "5.9.9.F.4h/№149: юнит-тест различимости хопов красный или отсутствует — дубль ключа collector и неразличимые хопы fileaccess не закрыты"
dns_thr=$(awk '/^const dnsStaleThreshold/{print $NF; exit}' internal/collector/dns.go)
dns_thr_min=$(awk '/^const dnsStaleThreshold/{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) {print $i; exit}}' internal/collector/dns.go)
[ -n "$dns_thr_min" ] && [ "$dns_thr_min" -ge 6 ] 2>/dev/null \
    || die "5.9.9.F.4h/№150: dnsStaleThreshold = ${dns_thr_min:-?} мин — измеренный живьём межвсплесковый интервал тихого стенда 312с уже длиннее 5 минут, порог обязан быть выше него (иначе 59 пар WARN/recovered за idle-час, как на №2.9.9.F.3, и обязательная величина 12 недостижима)"
echo "  ок: хопы различимы юнит-тестом, dnsStaleThreshold = ${dns_thr_min} мин (> 312с наблюдённого интервала)"

echo "--- преflight: 5.9.9.F.4i — перенос волны 5.9.9.F.3 целиком ---"
# Пункт не имеет собственной правки кода по построению: он требует, чтобы все
# семь пунктов 5.9.9.F.3 остались в дереве и получили приёмку ЭТИМ замером.
# Их сторожа отработали выше; здесь проверяется то, чего у них нет, — что
# перенос объявлен там, где его читает бухгалтерия гейта.
f4i_missing=""
for wid in 5.9.9.F.3a 5.9.9.F.3b 5.9.9.F.3c 5.9.9.F.3d 5.9.9.F.3e 5.9.9.F.3f 5.9.9.F.3g; do
    case " $WAVE_CRITERIA_IDS " in *" $wid "*) ;; *) f4i_missing="$f4i_missing $wid" ;; esac
done
[ -z "$f4i_missing" ] \
    || die "5.9.9.F.4i: пункты 5.9.9.F.3 выпали из WAVE_CRITERIA_IDS:$f4i_missing — перенос волны объявлен постановкой, но её пункты не сверяются на этом замере, то есть 5.9.9.F.3 второй замер подряд не принимается ни одной величиной"
echo "  ок: все семь пунктов 5.9.9.F.3 сверяются этим замером наравне с пунктами 5.9.9.F.4"

echo "--- преflight: реестр idle-actors.txt заведён (5.9.9.F.2d, №118) ---"
[ -s "$SETUP/attacks/idle-actors.txt" ] \
    || die "5.9.9.F.2d: idle-actors.txt отсутствует или пуст — состав idle-часа не с чем сверять, критерий по НОВОМУ АКТОРУ без входа"
idle_actors_n=$(awk -F'\t' '!/^[[:space:]]*(#|$)/ && NF>=1 {print $1}' "$SETUP/attacks/idle-actors.txt" | sort -u | wc -l)
echo "  idle-actors.txt: $idle_actors_n различных comm (оба окна суток: утро 2.9.9.F + ночь 2.9.9.F.1)"
[ "$idle_actors_n" -ge 30 ] \
    || die "5.9.9.F.2d: в idle-actors.txt только $idle_actors_n акторов — реестр заведён из ОДНОГО окна суток, и первый же idle-час в другом часе даст FAIL реестром, а не находкой"

# 5.9.9.F.3, запрет постановки, названный явно: акторы пакета systemd
# 11:57:39 (находка №133) в реестр НЕ дописываются. Дописывание перевело бы
# FAIL замера №2.9.9.F.2 в PASS правкой реестра — то есть впитало бы
# реальный дефект детекта в сторожевой реестр и превратило крит. 5.9.9.F.2d
# из сторожа в узаконивание. Если правки 3a/3b/3c верны, эти акторы просто
# перестают порождать алерты и в состав idle-часа не попадают вовсе.
for banned in mandb '(mandb)' find '(find)' install '(install)'; do
    # find УЖЕ есть в реестре законно (утро 2.9.9.F, MOTD-цепочка) — его
    # проверяем только в скобочной форме, остальные в обеих.
    [ "$banned" = "find" ] && continue
    if awk -F'\t' -v b="$banned" '!/^[[:space:]]*#/ && $1==b {found=1} END{exit !found}' "$SETUP/attacks/idle-actors.txt"; then
        die "5.9.9.F.3: актор «$banned» дописан в idle-actors.txt. Постановка волны запрещает это явно: FAIL замера №2.9.9.F.2 вынесен крит. 5.9.9.F.2d на пакете systemd (находка №133), и перевод его в PASS правкой реестра — ровно то, что постановка 5.9.9.F.2 запретила («такой FAIL есть успех волны и в PASS правкой порога не переводится»). Чинить надо предикаты 3a/3b/3c, а не реестр"
    fi
done
echo "  ок: акторы пакета systemd в реестр не дописаны (FAIL чинится предикатом, не реестром)"

echo "--- преflight: юнит-тест 5.9.9.F.2g (дубль ключа collector в JSON, №127) ---"
go test -count=1 -v ./internal/collector/ -run 'TestMalformedLogger_RecordDoesNotDuplicateCollectorKey' 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL)' | sed 's/^/  /'
go test -count=1 ./internal/collector/ -run 'TestMalformedLogger_RecordDoesNotDuplicateCollectorKey' >/dev/null 2>&1 \
    || die "5.9.9.F.2g: юнит-тест дубля ключа collector красный — запись malformed event record снова невалидна для строгих парсеров (находка №127)"

# Сторож 5.9.8a на уровне ИСХОДНИКА BPF: ключ dns_socket_map обязан быть
# процессным (tgid), а не потоковым. Проверяется здесь, а не только в
# контролях [7/14], потому что здесь это стоит секунду, а там — минуты.
echo "--- преflight: ключ dns_socket_map процессный, а не потоковый (5.9.8a) ---"
grep -q '__u32 tgid;' bpf/dns.bpf.c || die "5.9.8a: struct dns_socket_key не несёт поля tgid — правка №94 не в дереве, замер измерил бы старый ключ"
grep -q 'key.pid_tgid = bpf_get_current_pid_tgid();' bpf/dns.bpf.c \
    && die "5.9.8a: в bpf/dns.bpf.c остался потоковый ключ (key.pid_tgid = …) — правка №94 откачена частично"
echo "  ок: ключ строится из current_tgid()"

echo "--- преflight: реестры ---"
for f in dns-decode-reasons.txt detection-baseline.txt silent-rules.txt intentional-loss.txt criteria-index.txt dns-idle-fp.txt background-rules.txt idle-actors.txt; do
    if [ -f "$SETUP/attacks/$f" ]; then
        echo "  $f: $(grep -cv '^[[:space:]]*\(#\|$\)' "$SETUP/attacks/$f") значащих строк"
    else
        echo "  $f: ОТСУТСТВУЕТ — соответствующий критерий будет нечитаем"
    fi
done
[ -s "$SETUP/attacks/criteria-index.txt" ] \
    || die "criteria-index.txt отсутствует или пуст — run-gate.sh обрушится преflight'ом (exit 3), 5.9.7h не проверяем"

# 5.9.8h: WARN «база брошена» второй замер подряд означал, что сигнатура
# прошлого прогона осталась от прогона на АРХИВЕ (шаг [2/14] снимает её за
# собой, но старая могла дожить с прошлых сессий). Печатается явно.
ls -l "$SETUP/attacks/detection-baseline-diff-state.txt" 2>/dev/null | sed 's/^/  сигнатура прошлого прогона: /' \
    || echo "  сигнатуры прошлого прогона нет — предупреждение «база брошена» на этом замере невозможно по построению"

if command -v python3 >/dev/null 2>&1; then
    echo "  python3: $(python3 --version 2>&1) — 5.9.7a/5.9.7b/5.9.8a исполнимы"
else
    die "python3 не найден — контроль счётности (5.9.7a), run_ringbuf_overflow (5.9.7b) и оба контроля DNS (5.9.8a) без входа"
fi
command -v jq >/dev/null 2>&1 || die "jq не найден — гейт и разбивки по comm непроверяемы"

echo "  параметры замера: COUNTING_CONTROL_N=$COUNTING_CONTROL_N INDUCED_DROP_MAX_FILES=$INDUCED_DROP_MAX_FILES RINGBUF_OVERFLOW_N=$RINGBUF_OVERFLOW_N DNS_CROSS_THREAD_N=$DNS_CROSS_THREAD_N"
echo "  параметры волны 5.9.9.F.2: CPU_PRESSURE_MAX_FILES=$CPU_PRESSURE_MAX_FILES CPU_PRESSURE_MAX_REDUCE_WAIT=$CPU_PRESSURE_MAX_REDUCE_WAIT (min_dwell читается у агента, не задаётся здесь)"

grep -n -A7 '^enforcement:' "$SETUP/config-test.yaml" | sed 's/^/  конфиг enforcement: /'
grep -n 'track_write' "$SETUP/config-test.yaml" | sed 's/^/  конфиг file_ops: /'
grep -q 'track_write:[[:space:]]*true' "$SETUP/config-test.yaml" \
    || die "track_write выключен — rootkit_ssh_authorized_keys_modified (5.9.7e) немо по построению"
echo "преflight завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [1/14] ЖЁСТКИЙ СТОП №1: replay-gate.sh на ВОСЬМИ архивах, 14 реплеев (5.9.7c…5.9.9.F.3) ==="
# collect-2.9.5 — тождество умеет SKIP по отсутствующей левой части;
# collect-2.9.6 — сходится там, где сходилось, и новая формула фона проходит
# там, где старая валила; синтетическая потеря 1000 событий — тождество умеет
# падать; collect-2.9.7 (5.9.8e) — крит. 9 даёт 88.6/мин, а не SKIP;
# collect-2.9.8 (5.9.9a) — «база брошена» даёт ОБА исхода; collect-2.9.9
# (5.9.9.Fe) — вторая и третья ветки спасения фонового правила различаются;
# collect-2.9.9.F (5.9.9.F.1a/5.9.9.F.1c) — крит. 16 умеет PASS и FAIL, ноль
# web_sql_injection_files объясняется реестром.
#
# СЕДЬМОЙ архив, НОВОЕ на этом замере — collect-2.9.9.F.1. На нём стоят все
# четыре реплея волны 5.9.9.F.2, и он единственный, где это возможно: только
# рядом с ним лежат agent-start-*.txt (окно журнала крит. 17) и
# journal-agent-*.log (журнальные строки для крит. 5.9.4h), и только он
# вместе с collect-2.9.9.F покрывает ОБА окна суток для idle-actors.txt.
#
# У каждого из НОВЫХ реплеев (13/14 и 14/14) проверяется ОТРИЦАТЕЛЬНЫЙ исход, а не
# только положительный. Это прямое требование постановки волны: все её
# правки меняют вердикт гейта, и критерий, ставший зелёным потому, что
# разучился падать, вернул бы 0 и прошёл бы здесь незамеченным — ровно этим
# и была находка №124.
find_archive() {
    local name="$1" d
    for d in "/opt/ebpf-guard/server-logs/$name" "/root/$name" "/tmp/$name" "$SETUP/../../server-logs/$name"; do
        [ -d "$d/attacks" ] && { echo "$d"; return 0; }
    done
    return 1
}
C295_DIR="${REPLAY_C295_DIR:-$(find_archive collect-2.9.5 || true)}"
C296_DIR="${REPLAY_C296_DIR:-$(find_archive collect-2.9.6 || true)}"
C297_DIR="${REPLAY_C297_DIR:-$(find_archive collect-2.9.7 || true)}"
C298_DIR="${REPLAY_C298_DIR:-$(find_archive collect-2.9.8 || true)}"
C299_DIR="${REPLAY_C299_DIR:-$(find_archive collect-2.9.9 || true)}"
C299F_DIR="${REPLAY_C299F_DIR:-$(find_archive collect-2.9.9.F || true)}"
C299F1_DIR="${REPLAY_C299F1_DIR:-$(find_archive collect-2.9.9.F.1 || true)}"
C299F2_DIR="${REPLAY_C299F2_DIR:-$(find_archive collect-2.9.9.F.2 || true)}"
echo "  архив 2.9.5: ${C295_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.6: ${C296_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.7: ${C297_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.8: ${C298_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.9: ${C299_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.9.F: ${C299F_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.9.F.1: ${C299F1_DIR:-НЕ НАЙДЕН}"
echo "  архив 2.9.9.F.2: ${C299F2_DIR:-НЕ НАЙДЕН}"
if [ -z "$C295_DIR" ] || [ -z "$C296_DIR" ] || [ -z "$C297_DIR" ] || [ -z "$C298_DIR" ] || [ -z "$C299_DIR" ] || [ -z "$C299F_DIR" ] || [ -z "$C299F1_DIR" ] || [ -z "$C299F2_DIR" ]; then
    die "архивы collect-2.9.5…collect-2.9.9.F.2 не найдены на стенде. Скопировать (например в /root/) либо задать REPLAY_C295_DIR…REPLAY_C299F2_DIR. Пропуск реплея — это находка №85, повторённая десятый раз"
fi
# Реплеи 9-12 читают не только attacks/, но и журнал с меткой старта агента
# рядом с архивом. Их отсутствие даёт не «реплей пропущен», а «реплей не
# проверил ничего», поэтому проверяется здесь, до вызова.
for f in journal-agent-2.9.9.F.1.log agent-start-2.9.9.F.1.txt; do
    [ -s "$C299F1_DIR/$f" ] \
        || die "реплеи 9/12 и 11/12: $C299F1_DIR/$f отсутствует — окно журнала крит. 17 и строка «no reachable nr» крит. 5.9.4h непроверяемы ни на чём другом"
done
for d in "$C299F_DIR" "$C299F1_DIR"; do
    for f in idle/metrics-start.txt idle/metrics-end.txt idle/alerts-start.json idle/alerts-end.json; do
        [ -s "$d/$f" ] \
            || die "реплей 10/12: $d/$f отсутствует — состав idle-часа не с чем сверять, реестр idle-actors.txt непроверяем на этом окне суток"
    done
done
# Реплеи 13/14 и 14/14 читают idle-час и журнал архива 2.9.9.F.2: без них
# 3d проверять не на чем (вход фазы idle — пакет systemd 11:57:39), а 3e
# не на чем проверять SKIP=0 (три SKIP есть только у этого архива).
for f in idle/metrics-start.txt idle/metrics-end.txt idle/alerts-start.json idle/alerts-end.json; do
    [ -s "$C299F2_DIR/$f" ] \
        || die "реплеи 13/14 и 14/14: $C299F2_DIR/$f отсутствует — пакет systemd 11:57:39 (вход фазы idle, №134) и состав idle-часа непроверяемы"
done
for f in journal-agent-2.9.9.F.2.log agent-start-2.9.9.F.2.txt; do
    [ -s "$C299F2_DIR/$f" ] \
        || die "реплей 14/14: $C299F2_DIR/$f отсутствует — SKIP=0 на архиве недостижим по построению (крит. 17 и крит. 5.9.4h останутся без входа), и вердикт 3e был бы вынесен по чужой причине"
done
bash $SETUP/attacks/replay-gate.sh "$C295_DIR" "$C296_DIR" "$C297_DIR" "$C298_DIR" "$C299_DIR" "$C299F_DIR" "$C299F1_DIR" "$C299F2_DIR" 2>&1 | tee /root/replay-2.9.9.F.5.txt
replay_rc=${PIPESTATUS[0]}
echo "  replay-gate вернул $replay_rc"
[ "$replay_rc" -eq 4 ] && die "replay-gate: неподходящий bash (находка №88) — цепочка зовёт старый интерпретатор"
[ "$replay_rc" -eq 0 ] \
    || die "REPLAY-GATE красный (код $replay_rc) — известные ответы на архивах не воспроизводятся. Риск №1 постановки материализовался: правки гейта 5.9.9.F.2a-2f меняют вердикт на уже снятых данных"

# --- реплеи 1-8: унаследованные, проверяются теми же строками -------------
grep -q '88\.6/мин' /root/replay-2.9.9.F.5.txt \
    || die "реплей 4/12 не напечатал 88.6/мин — крит. 9 на collect-2.9.7 не воспроизвёл известный ответ (5.9.8e, №90)"
grep -q 'повторный вызов за тот же замер молчит' /root/replay-2.9.9.F.5.txt \
    || die "реплей 5/12: повторный вызов гейта за тот же замер не промолчал — самонаведение №99 не починено (5.9.9a)"
grep -q 'умеет падать, а не только молчать (5.9.9a)' /root/replay-2.9.9.F.5.txt \
    || die "реплей 5/12: с подменённым TIMESTAMP WARN «база брошена» не напечатан — механизм 5.9.6f ослеплён правкой 5.9.9a"
grep -q 'выросло за idle-час' /root/replay-2.9.9.F.5.txt \
    || die "реплей 6/12: вторая ветка спасения фонового правила («выросло за idle-час») не напечатана (5.9.9.Fe)"
grep -q 'напечатаны разными формулировками' /root/replay-2.9.9.F.5.txt \
    || die "реплей 6/12: вторая и третья ветки спасения не различены на одном прогоне — ветка idle_prewindow_list не проверена (5.9.9.Fe, №111)"
# 5.9.9.F.2f (№126): текст реплея 7 изменён волной — к случаю добавлено само
# смещение в миллисекундах. Проверяется вместе со случаем, одной строкой:
# «случай 1 напечатан, а смещение потеряно» — это неисполнившийся 2f.
grep -q 'случай 1 (алерт старше регистрации корня), смещение -26мс напечатано' /root/replay-2.9.9.F.5.txt \
    || die "реплей 7/12: крит. 16 не вынес PASS со случаем 1 И смещением -26мс — либо классификация не отработала (проверить iso_to_epoch), либо 5.9.9.F.2f не печатает смещение (находка №126)"
grep -q 'критерий 16 умеет падать, а не только пропускать' /root/replay-2.9.9.F.5.txt \
    || die "реплей 7/12: с алертом за confirm_epoch крит. 16 НЕ упал — правка 5.9.9.F.1a ослепила критерий, что хуже находки №116 (тихо, а не шумно)"
grep -q 'ноль 5.9.9.F.1c объясняется печатью, а не допущением' /root/replay-2.9.9.F.5.txt \
    || die "реплей 8/12: нулевой web_sql_injection_files не отнесён реестром — приёмка 5.9.9.F.1c осталась бы допущением, а не проверкой"
grep -q 'ветка реестра различает объяснённый ноль и регресс детекта' /root/replay-2.9.9.F.5.txt \
    || die "реплей 8/12: крит. 6 не упал на правиле вне реестров — значит первый исход реплея 8 не доказывает ничего"

# --- реплеи 9-12: ВОЛНА 5.9.9.F.2, оба исхода у каждого -------------------
# 5.9.9.F.2c (№128): ветка 5.9.9.Fc («окно журнала не задано») до этой волны
# не исполнялась на пайплайне ни разу — её поломка была бы невидима.
grep -q 'без AGENT_START_FILE крит. 17 = SKIP «окно журнала не задано», вердикта нет' /root/replay-2.9.9.F.5.txt \
    || die "реплей 9/12: без AGENT_START_FILE крит. 17 вынес вердикт вместо SKIP — вернулась подстановка --boot, и предохранитель судился бы по чужим прогонам всего аптайма хоста (5.9.9.Fc, №110)"
grep -q 'оба исхода 5.9.9.Fc воспроизведены на одном архиве' /root/replay-2.9.9.F.5.txt \
    || die "реплей 9/12: с заданным AGENT_START_FILE крит. 17 не дал PASS — первый исход тогда доказывает только то, что критерий никогда ничего не выносит (5.9.9.F.2c, №128)"
# 5.9.9.F.2d (№118): три исхода, и третий обязателен — без него два PASS
# доказывали бы только то, что критерий не падает никогда.
[ "$(grep -c 'состав idle-часа целиком покрыт idle-actors.txt, новых акторов 0' /root/replay-2.9.9.F.5.txt)" -ge 2 ] \
    || die "реплей 10/12: idle-actors.txt покрыл меньше двух реальных окон суток — реестр подогнан под одно окно, и на замере даст FAIL реестром, а не находкой (5.9.9.F.2d, №118)"
grep -q 'вне idle-actors.txt — крит. FAIL и назван поимённо' /root/replay-2.9.9.F.5.txt \
    || die "реплей 10/12: синтетический актор вне реестра НЕ уронил критерий — сверка с idle-actors.txt зелёная на любом составе, то есть находка №118 не закрыта, а замаскирована"
# 5.9.9.F.2e (№122): оба исхода — деградация без journalctl и 11 правил с ним.
grep -q 'без journalctl крит. 5.9.4h деградирует к старому «0» текстом, не падает' /root/replay-2.9.9.F.5.txt \
    || die "реплей 11/12: без источника журнала крит. 5.9.4h не деградировал корректно — чтение журнала стало обязательным, и гейт упадёт там, где раньше честно молчал (5.9.9.F.2e)"
grep -q 'называет 11 правил категорией (а), «немых правил: 0» не печатается' /root/replay-2.9.9.F.5.txt \
    || die "реплей 11/12: с журналом крит. 5.9.4h не назвал 11 правил без достижимого nr — величина, которую агент печатает сам, снова никем не читается (находка №122)"
# 5.9.9.F.2a (№123/№124): замкнутое тождество обязано и сходиться, и падать.
grep -q 'считает замкнутым тождеством с симметричным ±1500 и даёт PASS на исправном прогоне' /root/replay-2.9.9.F.5.txt \
    || die "реплей 12/12: крит. 22 не пошёл замкнутым тождеством — либо formula=closed не применяется, либо выбран не тот маркер ringbuf-overflow-*.txt (ревизия волны, Р4)"
grep -q 'замкнутое тождество умеет падать' /root/replay-2.9.9.F.5.txt \
    || die "реплей 12/12: с заниженным на 5000 Δringbuf_full крит. 22 НЕ упал — допуск снова прячет потерю в кольце, находка №124 не закрыта"
# --- реплеи 13-14: ВОЛНА 5.9.9.F.3, оба исхода у каждого -------------------
# 5.9.9.F.3d (№134): фаза idle перестаёт поглощаться меткой «наведено шагом
# преflight'а». Вход — пакет systemd 11:57:39 архива 2.9.9.F.2: семь типов,
# помеченных там преflight'ом, обязаны получить метку idle. Отрицательный
# исход столь же обязателен: если ни один тип не остался induced, значит
# правка не переупорядочила ветки, а выключила четвёртую фазу целиком —
# это не починка №134, а откат 5.9.9d/№100.
grep -q 'фаза idle не поглощается меткой преflight' /root/replay-2.9.9.F.5.txt \
    || die "реплей 13/14: на collect-2.9.9.F.2 семь типов пакета systemd не получили метку idle — ветка in_induced по-прежнему поглощает idle целиком (находка №134), и idle-FP уйдут в detection-baseline.txt как артефакты преflight-шага"
grep -q 'четвёртая фаза сохранена' /root/replay-2.9.9.F.5.txt \
    || die "реплей 13/14: после правки НИ ОДИН тип не остался «наведено преflight'ом» — фаза 4 выключена целиком, а не переупорядочена. Это откат 5.9.9d (№100), а не починка №134: типы, наведённые контролями DNS вне окон, снова уйдут в «не определено»"
# 5.9.9.F.3e (№135/№136/№137): SKIP=0 на архиве БЕЗ правки самих критериев.
# Второй исход обязателен по той же причине, что у 12/12: механизм, который
# печатает 0 всегда, вернул бы 0 и здесь.
# Ревизия волны (2026-08-26): проверяется ИМЕННО ТРОЙКА пунктов, а не
# «SKIP=0» целиком. Офлайн-реплей идёт без агента и без attack-manifest.json,
# и его собственные SKIP'и (пустой токен, темп непроверяем, recall
# непроверяем) к волне отношения не имеют и сняты быть не могут по
# построению — критерий, названный «SKIP=0», а проверяющий тройку, был бы
# критерием, судящим не то, что называет. Величина приёмки №1 (SKIP=0/FAIL=0)
# по-прежнему имеет входом только полный гейт замера, шаг [13/14].
grep -q 'три неисполнившиеся ветки архива (5.9.9.Fc/5.9.9.F.1d/5.9.9.F.2b) исполняются без правки самих критериев' /root/replay-2.9.9.F.5.txt \
    || die "реплей 14/14: на архиве 2.9.9.F.2 хотя бы один из трёх пунктов (5.9.9.Fc/5.9.9.F.1d/5.9.9.F.2b) снова числится неисполнившимся — дефекты бухгалтерии №135/№136/№137 не сняты, и единственный SKIP замера №2.9.9.F.2 воспроизведётся на этом"
grep -q 'счётчик неисполнившихся веток умеет расти' /root/replay-2.9.9.F.5.txt \
    || die "реплей 14/14: с изъятой строкой индекса счётчик неисполнившихся веток НЕ вырос — 5.9.9e печатает 0 при любом составе, то есть SKIP=0 на этом замере не значит ничего (класс №124)"
echo "реплей 14/14 пройден в $(date -u +%H:%M:%S) UTC"

echo "=== [2/14] ЖЁСТКИЙ СТОП №2: сверка criteria-index.txt (5.9.7h/5.9.8h) ==="
c296_ts=$(ls "$C296_DIR"/attacks/baseline-state-*.json 2>/dev/null | head -1 | sed 's/.*baseline-state-\(.*\)\.json/\1/')
[ -n "$c296_ts" ] || die "не удалось определить TIMESTAMP архива 2.9.6 для сверки criteria-index.txt"
# Побочный эффект run-gate.sh (detection-baseline-diff-state.txt, 5.9.6f)
# снимается здесь же: прогон на архиве не является «прошлым замером», иначе
# шаг [13/14] сравнит настоящий замер с сигнатурой архива и напечатает WARN
# «база брошена» третий замер подряд (5.9.8h).
DIFF_STATE="$SETUP/attacks/detection-baseline-diff-state.txt"
DIFF_BAK=""
if [ -f "$DIFF_STATE" ]; then DIFF_BAK=$(mktemp); cp "$DIFF_STATE" "$DIFF_BAK"; fi
ci_out=$(EBPF_GUARD_API="http://127.0.0.1:1" EBPF_GUARD_TOKEN="" \
    bash $SETUP/attacks/run-gate.sh "$C296_DIR/attacks" "$c296_ts" 2>&1 | head -8)
if [ -n "$DIFF_BAK" ]; then cp "$DIFF_BAK" "$DIFF_STATE"; rm -f "$DIFF_BAK"; else rm -f "$DIFF_STATE"; fi
echo "$ci_out" | sed 's/^/  /'
echo "$ci_out" | grep -q 'непокрытых пунктов постановки: 0' \
    || die "criteria-index.txt: у пункта постановки нет машинной печати в гейте (5.9.7h) — это находка №83, повторённая"
echo "сверка пройдена в $(date -u +%H:%M:%S) UTC"

echo "=== [3/14] make generate && make build (жёстко: 5.9.8a правит bpf/dns.bpf.c) ==="
cd /opt/ebpf-guard
make generate || die "make generate упал"
echo "--- generate: карты волны 5.9.6 живы в сгенерированных биндингах ---"
gen_maps_missing=0
for c in syscall network fileaccess privesc; do
    gf=$(ls internal/bpf/${c}_*_bpfe*.go 2>/dev/null | head -1)
    if [ -z "$gf" ]; then
        echo "  $c: сгенерированных биндингов нет — bpf2go не выдал объект"
        gen_maps_missing=1
        continue
    fi
    n=$(grep -c 'RingbufFullCounters\|EventsEmittedCounters' "$gf")
    echo "  $c ($gf): полей карт = $n"
    [ "$n" -eq 0 ] && gen_maps_missing=1
done
[ "$gen_maps_missing" -eq 0 ] || echo "ВНИМАНИЕ: карты 5.9.6 отсутствуют хотя бы в одном объекте — SMOKE-гейт [6/14] обязан это подтвердить красным"
# 5.9.8a: DNS-объект обязан быть ПЕРЕСОБРАН этим generate, а не взят с полки.
# Проверяется по факту существования свежего .o и биндинга с DnsSocketMap.
dns_gen=$(ls internal/bpf/dns_*_bpfe*.go 2>/dev/null | head -1)
[ -n "$dns_gen" ] || die "5.9.8a: сгенерированных биндингов DNS нет — bpf2go не выдал объект, правка ключа не попала бы в ядро"
grep -q 'DnsSocketMap' "$dns_gen" || die "5.9.8a: в $dns_gen нет DnsSocketMap — биндинг не соответствует правленому bpf/dns.bpf.c"
ls -l internal/bpf/dns_*_bpfe*.o 2>/dev/null | sed 's/^/  DNS-объект: /'
git status --porcelain internal/bpf/ | sed 's/^/  generate изменил: /'
make build || die "make build упал"
./build/ebpf-guard version 2>&1 | sed 's/^/  бинарь (после пересборки): /' || true
ls -l build/ebpf-guard | sed 's/^/  /'
echo "сборка завершена в $(date -u +%H:%M:%S) UTC"

echo "=== [4/14] риск №3 (5.9.4): отдельный короткий прогон P0-3 ДО замера ==="
cd $SETUP
OUT_DIR=$P0_OUT DURATION=120 INTERVAL=60 NO_RESTART=0 bash ./idle-run.sh
echo "P0-3 прогон завершён в $(date -u +%H:%M:%S) UTC"
grep -h "before:\|after:\|P0-3" $P0_OUT/idle-run.log

echo "=== [5/14] очистка стора + рестарт агента (уже с новым бинарём) ==="
systemctl stop ebpf-guard-test.service
rm -f /var/lib/ebpf-guard/test-events.db /var/lib/ebpf-guard/test-events.db-shm /var/lib/ebpf-guard/test-events.db-wal
# 5.9.9.F.4c (№147): раньше здесь стояло `echo 0 > observer-root-pid` — это и
# было дефектом: с этой строки и до idle-run.sh на шаге [11/14] дерево
# пайплайна оставалось НЕисключённым, хотя SMOKE/DNS/счётность/кольцо/
# CPU-давление/[9.6/14] — всё внутри аптайма, который меряет гейт. Файл на
# диске переживает рестарт сам, менять его не нужно; новый бинарь его
# переопрашивает при старте — шаг только переподтверждает подхват.
systemctl start ebpf-guard-test.service
echo "рестарт в $(date -u +%H:%M:%S) UTC"
register_pipeline_observer_root
date -u +"%Y-%m-%d %H:%M:%S" > /root/agent-start-2.9.9.F.5.txt
systemctl show ebpf-guard-test.service -p ExecMainStartTimestamp | sed 's/^/  /'

# 5.9.9.F.4c, поправка предпрогона №2.9.9.F.5 (находка №151). ИСКЛЮЧЕНИЕ
# ДЕРЕВА СНИМАЕТСЯ НА ВСЁ ВРЕМЯ НАВЕДЁННЫХ КОНТРОЛЕЙ [6/14]...[9.5/14].
#
# Постановка 4c назвала окном исключения «преflight, сборку И контроли ВНЕ
# окна замера». Третья часть этого перечисления невыполнима по построению, и
# предпрогон показал это числом: генераторы всех наведённых контролей —
# ПОТОМКИ этого самого процесса, а фильтр 5.9.2g режет дерево В ЯДРЕ, до
# кольца. Контроль счётности [8/14] дал канареечную серию 0 из N=10000
# (на №2.9.9.F.3, где исключения не было, — 10001) и остановил цепочку; за
# ним ровно так же ослепли бы переполнение кольца [9/14], CPU-давление
# [9.7/14], три пары продуктовых контролей [9.6/14] и cred_proc_maps
# [9.5/14] — то есть ВСЕ жёсткие стопы волны разом, причём в форме, которую
# сама волна велит читать как ослепление правил (находка №57).
#
# Поэтому исключение покрывает то, ради чего оно и заводилось, — инструментарий
# вне контролей (преflight, реплеи, сборка, пауза [10/14], гейт [13/14],
# отчёт), а на участке наведённых контролей снимается. Плата названа числом,
# а не спрятана: поллинг самих контролей (curl/jq) попадает в снимок аптайма
# величины 8, и если доля акторов измерителя не уложится в 5%, это остаток
# пункта 4c для следующей волны, а не повод вернуть исключение и ослепить
# контроли.
release_pipeline_observer_root

echo "=== [6/14] SMOKE-гейт: коллекторы грузятся, поток не пуст, серии волны на месте ==="
SMOKE_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
SMOKE_API="http://${VPS_IP:-localhost}:19090"
smoke_fail=0

sleep 20
echo "--- smoke: журнал загрузки BPF ---"
smoke_journal=$(journalctl -u ebpf-guard-test.service --no-pager -n 400 2>/dev/null || true)
echo "$smoke_journal" | grep -iE 'verifier|failed to load|load program|permission denied|collector .* (started|failed)|watchdog started' | tail -20 | sed 's/^/  /'
if echo "$smoke_journal" | grep -qiE 'verifier|failed to load'; then
    echo "SMOKE FAIL: в журнале есть ошибка загрузки/верификатора"
    smoke_fail=1
fi

smoke_health=$(curl -s --max-time 10 -H "Authorization: Bearer $SMOKE_TOKEN" "$SMOKE_API/health" 2>/dev/null)
echo "  /health: $smoke_health"
echo "$smoke_health" | grep -q '"status"' || { echo "SMOKE FAIL: агент не отвечает на /health"; smoke_fail=1; }

smoke_metrics() { curl -s --max-time 10 -H "Authorization: Bearer $SMOKE_TOKEN" "$SMOKE_API/metrics" 2>/dev/null; }
# 5.9.9f (№103): ENVIRON, не -v — то же обоснование, что у run-gate.sh
# sum_metric_delta()/run-all-attacks.sh sum_metric(): -v запускает
# unescaped-sequence разбор строки, и \{ в паттерне печатал предупреждение
# "escape sequence `\{' treated as plain `{'" на stderr при каждом вызове.
# Эта копия smoke_sum() кочевала из run-2.9.6-pipeline.sh в 2.9.7 и в 2.9.8
# без правки — третья непочиненная копия одного и того же дефекта.
smoke_sum() { P="$1" awk -F'} ' '$0 ~ ENVIRON["P"] {s+=$2} END{printf "%.0f", s+0}'; }

smoke_before=$(smoke_metrics)
python3 -c "
import os
p='/tmp/ebpf-guard-smoke-canary'
open(p,'w').close()
for _ in range(20000):
    fd=os.open(p, os.O_RDONLY); os.close(fd)
" || echo "  smoke: генератор не отработал, полагаемся на фоновую активность"
sleep 8
smoke_after=$(smoke_metrics)
rm -f /tmp/ebpf-guard-smoke-canary

for c in syscall network fileaccess; do
    em_a=$(echo "$smoke_before" | smoke_sum "ebpf_guard_events_emitted_kernel_total\{collector=\"$c\"\}")
    em_b=$(echo "$smoke_after"  | smoke_sum "ebpf_guard_events_emitted_kernel_total\{collector=\"$c\"\}")
    rf_present=$(echo "$smoke_after" | grep -c "reason=\"ringbuf_full\".*collector=\"$c\"\|collector=\"$c\".*reason=\"ringbuf_full\"" || true)
    echo "  $c: emitted_kernel $em_a -> $em_b (Δ$((em_b - em_a))), серия ringbuf_full присутствует: $rf_present"
    if [ "$rf_present" -eq 0 ]; then
        echo "SMOKE FAIL: $c — серия events_dropped_total{reason=\"ringbuf_full\"} отсутствует (5.9.6a не доехала до /metrics)"
        smoke_fail=1
    fi
done

fa_a=$(echo "$smoke_before" | smoke_sum 'ebpf_guard_events_emitted_kernel_total\{collector="fileaccess"\}')
fa_b=$(echo "$smoke_after"  | smoke_sum 'ebpf_guard_events_emitted_kernel_total\{collector="fileaccess"\}')
ev_a=$(echo "$smoke_before" | smoke_sum '^ebpf_guard_events_total\{.*type="file"')
ev_b=$(echo "$smoke_after"  | smoke_sum '^ebpf_guard_events_total\{.*type="file"')
echo "  fileaccess: Δemitted_kernel=$((fa_b - fa_a)), Δevents_total{file}=$((ev_b - ev_a))"
[ "$((fa_b - fa_a))" -gt 0 ] || { echo "SMOKE FAIL: emitted_kernel{fileaccess} не вырос под заведомой нагрузкой"; smoke_fail=1; }
[ "$((ev_b - ev_a))" -gt 0 ] || { echo "SMOKE FAIL: events_total{type=file} не вырос — события не доходят до userspace"; smoke_fail=1; }

hb=$(echo "$smoke_after" | grep -c '^ebpf_guard_heartbeat_timestamp_seconds' || true)
echo "  watchdog: серий ebpf_guard_heartbeat_timestamp_seconds = $hb"
if [ "$hb" -eq 0 ]; then
    echo "SMOKE FAIL: heartbeat отсутствует — watchdog.Start не выполнен, bpf_lost_events_total останется нулём (5.9.7b недоказуем)"
    smoke_fail=1
fi

# 5.9.8b: канареечная серия материализована нулём в init() — её отсутствие
# означает старый бинарь, и крит. 20 молча свалился бы в путь с вычетом фона
# (тот же провал, что 5.9.8b и чинит), напечатав SKIP вместо вердикта.
canary_series=$(echo "$smoke_after" | grep -c '^ebpf_guard_counting_canary_total' || true)
echo "  5.9.8b: серий ebpf_guard_counting_canary_total = $canary_series (ожидается 2: events, dropped)"
if [ "$canary_series" -lt 2 ]; then
    echo "SMOKE FAIL: канареечная серия отсутствует или неполна — бинарь старее 5.9.8b, критерий 20 будет считать по старому пути с вычетом фона"
    smoke_fail=1
fi
# Та же логика для нового reason DNS (5.9.8a): материализован нулём в
# RegisterMetrics, отсутствует только у старого бинаря.
bad_header_series=$(echo "$smoke_after" | grep -c 'ebpf_guard_dns_decode_errors_total{reason="bad_header"}' || true)
echo "  5.9.8a: серия dns_decode_errors_total{reason=\"bad_header\"} присутствует: $bad_header_series"
if [ "$bad_header_series" -eq 0 ]; then
    echo "SMOKE FAIL: reason=bad_header отсутствует — бинарь старее 5.9.8a, второй заслон DNS не в прогоне"
    smoke_fail=1
fi

if [ "$smoke_fail" -ne 0 ]; then
    die "SMOKE-гейт красный. Полтора часа на прогон, который не сможет отличить исправную систему от ослепшей, тратить нельзя"
fi
echo "SMOKE OK: коллекторы живы, watchdog запущен, серии волны 5.9.8 на месте. $(date -u +%H:%M:%S) UTC"

echo "=== [7/14] ЖЁСТКИЙ СТОП №4 (НОВЫЙ): оба контроля DNS ВНЕ окна замера (5.9.8a, запрет №6) ==="
# Риск №2 постановки: «0 long-label за idle-час» выглядит одинаково при
# починке и при полностью ослепшем DNS-коллекторе. Отсюда порядок: контроли
# в преflight, idle-час — потом. Слепой коллектор на idle-час не едет.
cd $SETUP/attacks
# 5.9.9g (находка №105, ЭТА ПРАВКА): шаг повторяем до трёх раз. На преflight'е
# №2.9.9 позитивный контроль дал Δdns=7 при N=8 и убил цепочку на 15-й минуте;
# три немедленных повтора подряд дали 8/8, а волна 5.9.9 не трогает ни
# bpf/dns.bpf.c, ни коллектор — то есть остановкой была потеря ОДНОГО UDP-пакета,
# а не ослепление. Различить их можно только повтором: ослепший коллектор даёт
# недосчёт КАЖДЫЙ раз, потерянный пакет — один раз из четырёх. Порог не ослаблен
# (последняя попытка обязана дать Δdns >= N ровно как раньше), ослаблена только
# цена единичного промаха. Повторяются лишь исходы «сценарий не воспроизведён»
# (в их формулировках и раньше стояло «повторить шаг»); Δdns > 0 у негатива —
# это находка №94, она валит цепочку с первой попытки без повторов.
DNS_CTL_ATTEMPTS="${DNS_CTL_ATTEMPTS:-3}"
dns_ctl_ok=0
for dns_try in $(seq 1 "$DNS_CTL_ATTEMPTS"); do
    echo "--- контроли DNS: попытка $dns_try из $DNS_CTL_ATTEMPTS ---"
    bash ./run-all-attacks.sh --dns-fd-reuse-controls 2>&1 | tee /root/dns-controls-2.9.9.F.5-$dns_try.txt
    dns_neg=$(ls -t $SETUP/attacks/attack-results/dns-negative-control-*.txt 2>/dev/null | head -1)
    dns_pos=$(ls -t $SETUP/attacks/attack-results/dns-positive-control-*.txt 2>/dev/null | head -1)
    [ -n "$dns_neg" ] || die "негативный контроль DNS не оставил маркера — 5.9.8a без входа"
    [ -n "$dns_pos" ] || die "позитивный контроль DNS не оставил маркера — 5.9.8a без входа"
    cat "$dns_neg" | sed 's/^/  негативный: /'
    cat "$dns_pos" | sed 's/^/  позитивный: /'
    grep -q '^skipped=1' "$dns_neg" && die "негативный контроль DNS пропущен харнессом — правка dns_socket_map не проверена (запрет №6)"
    grep -q '^skipped=1' "$dns_pos" && die "позитивный контроль DNS пропущен харнессом — правка dns_socket_map не проверена (запрет №6)"

    neg_xthread=$(awk -F= '$1=="cross_thread_close"{print $2+0}' "$dns_neg")
    neg_reused=$(awk -F= '$1=="reused_fd"{print $2+0}' "$dns_neg")
    neg_delta=$(awk -F= '$1=="events_dns_delta"{print $2+0}' "$dns_neg")
    pos_n=$(awk -F= '$1=="n"{print $2+0}' "$dns_pos")
    pos_delta=$(awk -F= '$1=="events_dns_delta"{print $2+0}' "$dns_pos")
    echo "  негативный: cross_thread_close=$neg_xthread reused_fd=$neg_reused Δdns=$neg_delta"
    echo "  позитивный: N=$pos_n Δdns=$pos_delta"

    # Негатив: Δdns > 0 — это сама находка №94, повтор её не исправит.
    [ "${neg_delta:-0}" -eq 0 ] || die "негативный контроль ПРОВАЛЕН: Δevents_total{type=dns}=$neg_delta > 0 — dns_socket_map всё ещё принимает переиспользованный fd за DNS, находка №94 не закрыта"
    # Генератор не отработал вовсе — повтор бессмыслен, вторая половина
    # запрета №6 осталась бы без входа при любом числе попыток.
    [ "${pos_n:-0}" -gt 0 ] || die "позитивный контроль: N=0 — генератор не отработал, вторая половина запрета №6 без входа"

    # Три исхода «сценарий не воспроизведён» — повторяемые.
    if [ "${neg_xthread:-0}" -ne 1 ]; then
        echo "ВНИМАНИЕ: попытка $dns_try: close() с чужого потока не удался — сценарий №94 не воспроизведён, повтор"
    elif [ "${neg_reused:-0}" -ne 1 ]; then
        echo "ВНИМАНИЕ: попытка $dns_try: fd не переиспользован (reused_fd=0) — сценарий №94 не воспроизведён, повтор"
    elif [ "${pos_delta:-0}" -lt "${pos_n:-0}" ]; then
        echo "ВНИМАНИЕ: попытка $dns_try: Δevents_total{type=dns}=$pos_delta < N=$pos_n — межпоточный резолв недосчитан, повтор (стабильный недосчёт остановит цепочку ниже)"
    else
        dns_ctl_ok=1
        [ "$dns_try" -gt 1 ] && echo "ВНИМАНИЕ: контроли DNS сошлись с попытки $dns_try, а не с первой — единичные промахи предыдущих попыток выше в логе"
        break
    fi
    sleep 10
done
[ "$dns_ctl_ok" -eq 1 ] \
    || die "контроли DNS не сошлись за $DNS_CTL_ATTEMPTS попыток (последняя: cross_thread_close=$neg_xthread reused_fd=$neg_reused N=$pos_n Δdns=$pos_delta) — недосчёт устойчив, это ослепление коллектора, а не потеря пакета (риск №2)"
echo "5.9.8a доказан живьём в $(date -u +%H:%M:%S) UTC: TLS по reused fd не даёт DNS-событий, межпоточный резолв даёт"

echo "=== [8/14] контроль счётности вне окна замера: канареечная серия оживает (5.9.8b) ==="
# Второй P0 волны после DNS. Без этого шага канареечная серия впервые
# считается только на минуте ~95 полного замера, внутри окна атак — то есть
# ошибка в ней (серия не растёт, префикс ловит лишнее) находилась бы там же,
# где и раньше находились все ошибки измерителя: после того, как час уже
# потрачен.
#
# ВЕРДИКТА ЗДЕСЬ НЕТ, и это осознанно: остаток считает ОДНА функция
# (counting_control_residual, run-gate.sh, 5.9.8c), переписывать её копию в
# пайплайне — ровно то, что 5.9.8c запретила. Проверяются только два
# инварианта, которым формула не нужна и которые ловят обе слепые ветки:
#   - null: канареечная серия строго 0 (иначе префикс ловит фон стенда);
#   - idle: канареечная серия выросла вообще (иначе счётчик мёртв, и крит. 20
#     на замере дал бы «остаток = -N» с диагнозом «непосчитанная потеря»).
# Маркеры пишутся со своим TIMESTAMP и в вердикт замера не попадают (секция
# 20 ищет их по таймстампу основного прогона) — запрет №3 соблюдён.
cd $SETUP/attacks
bash ./run-all-attacks.sh --counting-control 2>&1 | tee /root/counting-control-2.9.9.F.5.txt
# 5.9.9.F.2a (№123): режимов теперь два, а не три — drop удалён вместе с
# COUNTING_CONTROL_DROP_N. Маркер выбирается по ИМЕНИ (в имени лежит
# YYYYmmdd_HHMMSS), а не `ls -t` по mtime: тем же правилом, что теперь
# пользуется run-gate.sh, иначе пайплайн и гейт могли бы смотреть на разные
# марки одного и того же шага.
cc_null=$(ls -1 $SETUP/attacks/attack-results/counting-control-null-*.txt 2>/dev/null | LC_ALL=C sort | tail -1)
cc_idle=$(ls -1 $SETUP/attacks/attack-results/counting-control-idle-*.txt 2>/dev/null | LC_ALL=C sort | tail -1)
if ls $SETUP/attacks/attack-results/counting-control-drop-*.txt >/dev/null 2>&1; then
    echo "  ВНИМАНИЕ: в attack-results лежат маркеры counting-control-drop-* от прошлых замеров — режим удалён волной 5.9.9.F.2a, гейт их больше не читает"
fi
for m in "$cc_null" "$cc_idle"; do
    [ -n "$m" ] && { echo "  --- $(basename "$m")"; sed 's/^/    /' "$m"; }
done
[ -n "$cc_null" ] || die "контроль счётности: маркер null отсутствует — шаг не исполнен, 5.9.8b без входа"
[ -n "$cc_idle" ] || die "контроль счётности: маркер idle отсутствует — шаг не исполнен, 5.9.8b без входа"
grep -q '^skipped=1' "$cc_null" && die "контроль счётности пропущен харнессом (null) — python3 недоступен?"
grep -q '^skipped=1' "$cc_idle" && die "контроль счётности пропущен харнессом (idle)"

grep -q '^canary_sum=' "$cc_idle"     || die "5.9.8b: маркер без canary_sum — харнесс или бинарь старее 5.9.8b, крит. 20 на замере посчитает по старому пути с вычетом фона"
cc_null_canary=$(awk -F= '$1=="canary_sum"{print $2+0}' "$cc_null")
cc_idle_canary=$(awk -F= '$1=="canary_sum"{print $2+0}' "$cc_idle")
cc_idle_n=$(awk -F= '$1=="n"{print $2+0}' "$cc_idle")
echo "  null: канареечная серия=$cc_null_canary (обязана быть 0)"
echo "  idle: канареечная серия=$cc_idle_canary из N=$cc_idle_n"
[ "${cc_null_canary:-0}" -eq 0 ]     || die "5.9.8b ПРОВАЛЕН: канареечная серия=$cc_null_canary при N=0 — префикс /tmp/ebpf-guard-counting-canary- ловит события за пределами контроля счётности, крит. 20 будет врать в сторону завышения"
[ "${cc_idle_canary:-0}" -gt 0 ]     || die "5.9.8b ПРОВАЛЕН: канареечная серия=0 при N=$cc_idle_n — счётчик мёртв (RecordCountingCanary не вызывается либо FDPath пуст), крит. 20 на замере дал бы остаток -N с ложным диагнозом «непосчитанная потеря»"
# settle_reason проверяется здесь же — 5.9.8f судит его на замере, но
# «ceiling» на всех трёх маркерах означает дефект самого лупа, а не стенда,
# и чинить его дешевле сейчас, чем после idle-часа.
awk -F= '$1=="settle_reason"{print FILENAME": "$2}' "$cc_null" "$cc_idle" | sed 's/^/  5.9.8f: /'
echo "5.9.8b доказан живьём в $(date -u +%H:%M:%S) UTC: null=0, idle растёт"

echo "=== [9/14] ЖЁСТКИЙ СТОП №3: run_ringbuf_overflow ВНЕ окна замера (5.9.7b/5.9.8c) ==="
cd $SETUP/attacks
bash ./run-all-attacks.sh --ringbuf-overflow 2>&1 | tee /root/ringbuf-overflow-2.9.9.F.5.txt
rb_marker=$(ls -1 $SETUP/attacks/attack-results/ringbuf-overflow-*.txt 2>/dev/null | LC_ALL=C sort | tail -1)
[ -n "$rb_marker" ] || die "run_ringbuf_overflow не оставил маркера — шаг не исполнен, 5.9.7b без входа"
cat "$rb_marker" | sed 's/^/  /'
grep -q '^skipped=1' "$rb_marker" && die "run_ringbuf_overflow пропущен харнессом: $(awk -F= '$1=="skip_reason"{$1="";print substr($0,2)}' "$rb_marker")"
rb_full=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$rb_marker")
rb_lost=$(awk -F= '$1=="bpf_lost_delta"{print $2+0}' "$rb_marker")
rb_canary=$(awk -F= '$1=="canary_sum"{print $2+0}' "$rb_marker")
rb_n=$(awk -F= '$1=="n"{print $2+0}' "$rb_marker")
echo "  ringbuf_full=$rb_full bpf_lost_events_total=$rb_lost канарейка=$rb_canary из N=$rb_n"
[ "${rb_full:-0}" -gt 0 ] \
    || die "ringbuf_full=0 даже с замороженным читателем — переполнение не воспроизведено (поднять RINGBUF_OVERFLOW_N)"
[ "${rb_full:-0}" -eq "${rb_lost:-0}" ] \
    || die "ringbuf_full=$rb_full != bpf_lost_events_total=$rb_lost — проводка watchdog (5.9.7b) не подтверждена живьём"
# 5.9.8c: сам вердикт (остаток той же формулой, что крит. 20) считает гейт в
# секции 22 — здесь только печатается вход, чтобы он лежал в логе замера, а
# не восстанавливался потом из маркера.
grep -q '^canary_sum=' "$rb_marker" \
    || echo "ВНИМАНИЕ: маркер без canary_sum — секция 22 посчитает по запасному пути с вычетом фона (5.9.8c не исполнена этим прогоном)"
echo "5.9.7b/5.9.8c доказан живьём в $(date -u +%H:%M:%S) UTC"

echo "=== [9.7/14] ЖЁСТКИЙ СТОП №5 (НОВЫЙ): наведённое CPU-давление с выдержкой ВНЕ окна замера (5.9.9.F.2b, №125) ==="
# Зачем шаг и почему он жёсткий. Критерий 14 («watchdog CPU-давления не
# флапает») три замера подряд давал SKIP: reduce=0 означал не «не флапает», а
# «давление ни разу не поднялось само за окно атак». Ждать, пока оно
# поднимется органически, — это ждать случайности; постановка волны требует
# НАВЕДЁННОГО давления с выдержкой. Шаг стоит ВНЕ окна замера, до baseline,
# рядом с контролями DNS/счётности и переполнением кольца (запрет №3).
#
# Почему стоп жёсткий, хотя сам по себе шаг ничего не детектирует: без его
# маркера крит. 14 остаётся SKIP, а обязательная величина приёмки №1
# (RUN-GATE: SKIP=0) — недостижима. Полтора часа замера, который заведомо не
# может выполнить свой первый пункт приёмки, тратить незачем — тот же довод,
# что у SMOKE-гейта [6/14].
#
# Что здесь НЕ проверяется: вердикт. Пару reduce↔recover судит крит. 14
# (run-gate.sh), читая ЭТОТ маркер; переписывать его логику здесь — ровно то,
# что 5.9.8c запретила для остатка счётности. Проверяются три инварианта,
# которым вердикт не нужен и которые ловят все три известные слепые ветки:
# шаг не пропущен, min_dwell прочитан у АГЕНТА (а не подставлен константой),
# нагрузка снята и не пережила шаг.
cd $SETUP/attacks
CPU_API="http://${VPS_IP:-localhost}:19090"
CPU_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
cpu_metric() { curl -s --max-time 10 -H "Authorization: Bearer $CPU_TOKEN" "$CPU_API/metrics" 2>/dev/null | awk -v m="$1" '$0 ~ "^"m"( |\\{)" {print $NF; exit}'; }

deg_before=$(cpu_metric ebpf_guard_cpu_degraded_fraction)
echo "  cpu_degraded_fraction до шага: ${deg_before:-n/a}"
EBPF_GUARD_API="$CPU_API" EBPF_GUARD_TOKEN="$CPU_TOKEN" \
    bash ./run-all-attacks.sh --cpu-pressure-control 2>&1 | tee /root/cpu-pressure-2.9.9.F.5.txt
cpu_marker=$(ls -1 $SETUP/attacks/attack-results/cpu-pressure-control-*.txt 2>/dev/null | LC_ALL=C sort | tail -1)
[ -n "$cpu_marker" ] || die "5.9.9.F.2b: run_cpu_pressure_control не оставил маркера — шаг не исполнен, крит. 14 останется в SKIP"
sed 's/^/  маркер: /' "$cpu_marker"
grep -q '^skipped=1' "$cpu_marker" \
    && die "5.9.9.F.2b: шаг пропущен харнессом: $(awk -F= '$1=="skip_reason"{$1="";print substr($0,2)}' "$cpu_marker"). Самая вероятная причина — журнальная строка агента 'adaptive load shedding enabled' недоступна (журнал урезан/сервис поднят раньше окна journalctl) либо разбор min_dwell разошёлся с форматом записи. Это дефект входа, а не детекта: крит. 14 без маркера даёт SKIP"

cpu_reduce=$(awk -F= '$1=="reduce"{print $2+0}' "$cpu_marker")
cpu_recover=$(awk -F= '$1=="recover"{print $2+0}' "$cpu_marker")
cpu_dwell=$(awk -F= '$1=="min_dwell_seconds"{print $2+0}' "$cpu_marker")
cpu_rwait=$(awk -F= '$1=="reduce_wait_seconds"{print $2+0}' "$cpu_marker")
cpu_cwait=$(awk -F= '$1=="recover_wait_seconds"{print $2+0}' "$cpu_marker")
cpu_fshed=$(awk -F= '$1=="file_shed_threshold_pct"{print $2}' "$cpu_marker")
cpu_ncpu=$(awk -F= '$1=="num_cpu"{print $2}' "$cpu_marker")
echo "  reduce=$cpu_reduce recover=$cpu_recover; ожидание reduce=${cpu_rwait}с recover=${cpu_cwait}с; min_dwell=${cpu_dwell}с (у агента), file_shed=${cpu_fshed} num_cpu=${cpu_ncpu}"

# (1) min_dwell прочитан у агента. Ноль означает, что разбор журнальной
# записи не сработал (её формат — ЧИСЛО НАНОСЕКУНД, slog.Duration в JSON), и
# шаг ждал бы recovered по константе — ровно то, что постановка запретила.
[ "${cpu_dwell:-0}" -gt 0 ] \
    || die "5.9.9.F.2b: min_dwell_seconds=0 в маркере — журнальная запись агента не разобрана, выдержка ждалась бы вслепую (постановка требует читать величину у агента, а не задавать константой)"
[ -n "$cpu_fshed" ] \
    || die "5.9.9.F.2b: пороги (file_shed/all_shed/recovery) не прочитаны у агента — крит. 14 напечатал бы зашитые «40/70/20» вместо реальных, то есть соврал бы про то, что именно сработало"

# (2) Давление поднялось. Ноль здесь — не «правило молчит», а «рычага нет»:
# генератор файловых событий не заставил агент тратить CPU выше file_shed.
[ "${cpu_reduce:-0}" -eq 1 ] \
    || die "5.9.9.F.2b ПРОВАЛЕН живьём: cpu_pressure_level не дошёл до file_shed за ${CPU_PRESSURE_MAX_REDUCE_WAIT}с непрерывного всплеска (reduce=0). Крит. 14 останется без входа. Поднимать CPU_PRESSURE_MAX_FILES/CPU_PRESSURE_MAX_REDUCE_WAIT — но сперва проверить, что file_shed=${cpu_fshed} pct одного ядра вообще достижим этим генератором на ${cpu_ncpu} ядрах"
# (3) Выдержка отработала: recovered пришёл за 2×min_dwell.
[ "${cpu_recover:-0}" -eq 1 ] \
    || die "5.9.9.F.2b ПРОВАЛЕН живьём: recovered не пришёл за 2×min_dwell=$((cpu_dwell * 2))с после снятия нагрузки (recover=0, ждали ${cpu_cwait}с). Либо нагрузка НЕ снята (проверить, не остались ли живые tar: pgrep -f ebpf-guard-cpu-pressure-filelist), либо watchdog не возвращается в normal — вторая половина крит. 14 («пара reduce↔recover закрыта») недоказуема"

# (4) Нагрузка не пережила шаг. Это не педантизм: шаг идёт ДО baseline, и
# осиротевший tar грузил бы стенд весь оставшийся замер, искажая КАЖДУЮ
# последующую величину, а не только свою (ревизия исполнения волны, Р3).
# ВНИМАНИЕ (находка №130, предпрогон №2.9.9.F.3): `pgrep -fc ... || echo 0`
# здесь не работал. procps-овский `pgrep -c` при нуле совпадений САМ печатает
# "0" и выходит с кодом 1 — то есть `|| echo 0` дописывал ВТОРОЙ ноль, в
# переменной оказывалось "0\n0", и `[ ... -ne 0 ]` падал с
# "integer expression expected" (код 2). `if` читает код 2 как «ложь», и
# инвариант Р3 молча пропускал что угодно, включая настоящий осиротевший tar.
# Код возврата не используется вовсе, а не-число — это «проверку выполнить не
# удалось», и оно обязано останавливать цепочку, а не превращаться в 0.
leftover_burst=$(pgrep -fc 'ebpf-guard-cpu-pressure-filelist' 2>/dev/null | head -1)
[ -n "$leftover_burst" ] || leftover_burst=0
case "$leftover_burst" in
    ''|*[!0-9]*)
        die "5.9.9.F.2b: счётчик живых процессов нагрузки не число ('$leftover_burst') — инвариант «нагрузка не пережила шаг» не проверен ничем (находка №130)" ;;
esac
echo "  живых процессов нагрузки после шага: $leftover_burst (обязан быть 0)"
if [ "$leftover_burst" -ne 0 ]; then
    pgrep -fa 'ebpf-guard-cpu-pressure-filelist' | sed 's/^/    /'
    pkill -f 'ebpf-guard-cpu-pressure-filelist' 2>/dev/null || true
    die "5.9.9.F.2b: после шага остались живые процессы нагрузки — они бы шли фоном через idle-час и окно атак. Убиты здесь, но замер начинать нельзя: стенд уже под искажённым фоном, перезапустить цепочку"
fi
deg_after=$(cpu_metric ebpf_guard_cpu_degraded_fraction)
lvl_after=$(cpu_metric ebpf_guard_cpu_pressure_level)
echo "  cpu_degraded_fraction после шага: ${deg_after:-n/a} (было ${deg_before:-n/a}), cpu_pressure_level=${lvl_after:-n/a}"
[ "${lvl_after:-0}" = "0" ] \
    || die "5.9.9.F.2b: cpu_pressure_level=${lvl_after} после шага — агент остался под шеддингом, idle-час и окно атак мерились бы урезанным сэмплингом"
# Доля кумулятивна с момента старта watcher-а, поэтому «0 за окно замера»
# ею не проверяется — эту половину несёт крит. 14 (естественных переходов в
# окне 0). Здесь печатается вклад САМОГО шага, чтобы на разборе крит. 5.9e
# (порог 0.2) было видно, сколько из доли внесено наведённым давлением, а
# сколько — прогоном.
awk -v a="${deg_before:-0}" -v b="${deg_after:-0}" 'BEGIN{printf "  вклад шага в cpu_degraded_fraction: +%.4f (крит. 5.9e судит итог по final-срезу, порог 0.2)\n", b-a}'
echo "5.9.9.F.2b доказан живьём в $(date -u +%H:%M:%S) UTC: reduce=1 recover=1, min_dwell=${cpu_dwell}с прочитан у агента, нагрузка снята"

echo "=== [9.6/14] ЖЁСТКИЙ СТОП №6 (НОВЫЙ): три пары контролей продуктовых правок ВНЕ окна замера (5.9.9.F.3a/3b/3c) ==="
# ГЛАВНЫЙ ШАГ ЭТОГО ЗАМЕРА. Все три правки волны УМЕНЬШАЮТ число алертов, и
# «правило сузилось» неотличимо от «правило ослепло» по любому счётчику —
# находка №57, повторённая волнами 5.9.7e, 5.9.8g, 5.9.9b, 5.9.9.Fa,
# 5.9.9.F.1b. Поэтому у каждого пункта здесь ДВЕ половины, и обе жёсткие:
#   позитивная — правило обязано остаться ненулевым на настоящем случае;
#   негативная — правило обязано перестать видеть то, ради чего правилось.
# Ноль на позитивной половине — это находка №57, а не успех волны, и полный
# замер объявил бы его регрессом детекта в крит. 6 ПОСЛЕ потраченного
# idle-часа и часа атак.
#
# Шаг стоит ВНЕ окна замера (запрет №3), рядом с контролями DNS, счётности и
# переполнением кольца, и исполняется на ОБОИХ режимах — и на предпрогоне, и
# на полном замере. Это осознанно и отличается от [9.5/14]: там контроль
# внутри full_run() читает крит. 7 по манифесту, а здесь входа в манифесте
# нет, и обязательная величина приёмки №2 («правила ненулевые НА позитивных
# контролях») иначе недостижима на полном замере вовсе.
#
# Следствие, названное заранее: после этого шага оба правленых правила
# получают ненулевой абсолют ДО открытия baseline, и секция 6 гейта пометит
# их «наведено шагом преflight'а». После правки 5.9.9.F.3d это ВЕРНО — они
# действительно сработали вне всех трёх измеряемых окон. Приёмка читает их
# абсолютом по стору, а не дельтой окна.
cd $SETUP/attacks
FP_API="http://${VPS_IP:-localhost}:19090"
FP_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
fp_alerts() { curl -s --max-time 20 -H "Authorization: Bearer $FP_TOKEN" "$FP_API/api/v1/alerts" 2>/dev/null; }
fp_count() { fp_alerts | jq --arg r "$1" '[.[]|select(.rule_id==$r)]|length' 2>/dev/null || echo 0; }

# Загруженность правил — ДО контролей. Без неё «0 за прогон» и «правило не
# загрузилось» неотличимы, и оба дали бы одинаково зелёный крит. 6 через
# реестры (находка №117: путь именно /api/v1/rules, голый /rules отдаёт 404).
fp_rules=$(curl -s --max-time 15 -H "Authorization: Bearer $FP_TOKEN" "$FP_API/api/v1/rules" 2>/dev/null)
fp_rules_n=$(echo "$fp_rules" | jq -e 'if type=="array" then length else empty end' 2>/dev/null) \
    || die "5.9.9.F.3: $FP_API/api/v1/rules не отдал JSON-массив (ответ: $(echo "$fp_rules" | head -c 200)) — это отказ API/токена, а не сужение правил; ни один контроль ниже без реестра не доказуем"
echo "  реестр правил агента: $fp_rules_n правил"
for r in rootkit_hidden_dir_dev privesc_suid_suspicious_path sigma_binary_in_tmp_executed \
         container_escape_mount container_escape_chroot container_escape_unshare_user \
         container_escape_cap_sys_admin privesc_unshare_user_ns cis_5_2_1_privileged_container \
         proc_inject_memfd_create integrity_proc_self_exe_exec sigma_memfd_create_anonymous \
         rootkit_pam_module_added cred_shadow_read drift_new_library_in_system_dir; do
    echo "$fp_rules" | jq -e --arg r "$r" '[.. | objects | select(.id? == $r)] | length > 0' >/dev/null 2>&1 \
        || die "5.9.9.F.3/5.9.9.F.4a: правило $r не найдено в /api/v1/rules — оно не загрузилось, и его ноль на приёмке означал бы битый YAML, а не сужение (проверить синтаксис правки)"
done
echo "  все пятнадцать правых правил загружены агентом (не битый YAML, включая шесть новых 5.9.9.F.4a/№141)"

# ---- 5.9.9.F.3a: rootkit_hidden_dir_dev ---------------------------------
# Позитив: настоящий скрытый каталог под /dev — ровно то, ради чего правило
# написано (T1564.001). Негатив: чтение /dev/urandom, которое дало 10 из 12
# критикалов правила на №2.9.9.F.2.
echo "--- 5.9.9.F.3a: пара контролей rootkit_hidden_dir_dev (№131) ---"
a_before=$(fp_count rootkit_hidden_dir_dev)
mkdir -p "/dev/.${FP_CONTROL_TAG}" 2>/dev/null || die "5.9.9.F.3a: не удалось создать /dev/.${FP_CONTROL_TAG} — позитивный контроль без входа (нужен root и rw на /dev)"
# Ревизия волны (2026-08-26): ОДНОГО mkdir мало, и это не придирка к
# контролю, а прямое следствие исполнения пункта 3a. Предикат «каталог
# создан» оказался невыразим (нет хука на mkdir/mkdirat — bpf/fileaccess.bpf.c
# видит только openat/read/write), поэтому правило переехало на «путь под
# /dev открыт». mkdir не порождает НИ ОДНОГО файлового события, то есть
# контроль в прежнем виде давал Δ=0 на исправном правиле и убивал замер
# сообщением «правило ослеплено». Скрытый путь под /dev поэтому ещё и
# ОТКРЫВАЕТСЯ — ровно то, что правило теперь обещает ловить.
: > "/dev/.${FP_CONTROL_TAG}-canary" 2>/dev/null \
    || die "5.9.9.F.3a: не удалось создать файл /dev/.${FP_CONTROL_TAG}-canary — позитивный контроль без входа (нужен root и rw на /dev)"
head -c 1 "/dev/.${FP_CONTROL_TAG}-canary" >/dev/null 2>&1 || true
sleep 20
a_pos=$(fp_count rootkit_hidden_dir_dev)
echo "  позитивный: скрытый каталог + открытие /dev/.${FP_CONTROL_TAG}-canary -> Δ=$((a_pos - a_before))"
rm -f "/dev/.${FP_CONTROL_TAG}-canary" 2>/dev/null || true
rmdir "/dev/.${FP_CONTROL_TAG}" 2>/dev/null || true
[ "$((a_pos - a_before))" -ge 1 ] \
    || die "5.9.9.F.3a ПРОВАЛЕН живьём: скрытый путь под /dev (каталог + открытый dot-файл) НЕ поднял rootkit_hidden_dir_dev (Δ=0). Якорь ^ вместе с исключением штатных нод ослепил правило целиком — это находка №57, а не сужение. Полный замер потратил бы полтора часа, чтобы напечатать это как «потеряно вне реестров» в крит. 6"
a_neg_before=$(fp_count rootkit_hidden_dir_dev)
for _ in $(seq 1 20); do head -c 32 /dev/urandom > /dev/null 2>&1; done
sleep 20
a_neg_after=$(fp_count rootkit_hidden_dir_dev)
echo "  негативный: 20 чтений /dev/urandom -> Δ=$((a_neg_after - a_neg_before))"
[ "$((a_neg_after - a_neg_before))" -eq 0 ] \
    || die "5.9.9.F.3a ПРОВАЛЕН: /dev/urandom всё ещё поднимает critical rootkit_hidden_dir_dev (Δ$((a_neg_after - a_neg_before))) — regex [a-z]{6,} по-прежнему покрывает штатные ноды либо агент крутит старые правила (проверить, что рестарт [5/14] подхватил новый rules/)"
echo "  5.9.9.F.3a: обе половины сошлись"

# ---- 5.9.9.F.3b: privesc_suid_suspicious_path / sigma_binary_in_tmp_executed
# Позитив: НАСТОЯЩИЙ SUID-бинарь, запущенный из /tmp, — ровно T1548.001.
# Негатив: обычный текстовый файл под /tmp, прочитанный обычным cat. Именно
# такой файл (список для tar шага 5.9.9.F.2b) дал 6 критикалов «SUID binary
# executed» на №2.9.9.F.2.
echo "--- 5.9.9.F.3b: пара контролей семьи /tmp (№132) ---"
b_before=$(fp_count privesc_suid_suspicious_path)
b_sigma_before=$(fp_count sigma_binary_in_tmp_executed)
fp_suid="/tmp/${FP_CONTROL_TAG}-suidcanary"
cp /bin/true "$fp_suid" 2>/dev/null || die "5.9.9.F.3b: не удалось подготовить SUID-канарейку в /tmp — позитивный контроль без входа"
chown root:root "$fp_suid" 2>/dev/null || true
chmod 4755 "$fp_suid" || die "5.9.9.F.3b: chmod 4755 не прошёл — без бита SUID позитивный контроль не проверяет ничего"
"$fp_suid" >/dev/null 2>&1 || true
sleep 20
b_pos=$(fp_count privesc_suid_suspicious_path)
b_sigma_pos=$(fp_count sigma_binary_in_tmp_executed)
echo "  позитивный: SUID-бинарь запущен из /tmp -> Δprivesc_suid=$((b_pos - b_before)) Δsigma_binary_in_tmp=$((b_sigma_pos - b_sigma_before))"
rm -f "$fp_suid"
[ "$((b_pos - b_before))" -ge 1 ] \
    || die "5.9.9.F.3b ПРОВАЛЕН живьём: настоящий SUID-бинарь, запущенный из /tmp, НЕ поднял privesc_suid_suspicious_path (Δ=0). Правило ослеплено, а не сужено (находка №57) — либо предикат SUID читает поле, которого коллектор не отдаёт, и тогда постановка требовала второго исхода (переименование с понижением severity), а не молчащего critical"
[ "$((b_sigma_pos - b_sigma_before))" -ge 1 ] \
    || echo "  ВНИМАНИЕ: sigma_binary_in_tmp_executed не поднялся на запуске ELF из /tmp (Δ=0) — если пункт закрыт переименованием, это ожидаемо; если проверкой ELF/exec, это ослепление"
b_neg_before=$(fp_count privesc_suid_suspicious_path)
b_neg_sigma_before=$(fp_count sigma_binary_in_tmp_executed)
fp_txt="/tmp/${FP_CONTROL_TAG}-filelist.txt"
printf 'harmless\n%s\n' "$FP_CONTROL_TAG" > "$fp_txt"
for _ in $(seq 1 10); do cat "$fp_txt" > /dev/null 2>&1; done
sleep 20
b_neg_after=$(fp_count privesc_suid_suspicious_path)
b_neg_sigma_after=$(fp_count sigma_binary_in_tmp_executed)
echo "  негативный: 10 чтений обычного .txt под /tmp -> Δprivesc_suid=$((b_neg_after - b_neg_before)) Δsigma_binary_in_tmp=$((b_neg_sigma_after - b_neg_sigma_before))"
rm -f "$fp_txt"
[ "$((b_neg_after - b_neg_before))" -eq 0 ] \
    || die "5.9.9.F.3b ПРОВАЛЕН: обычный текстовый файл под /tmp всё ещё поднимает critical privesc_suid_suspicious_path (Δ$((b_neg_after - b_neg_before))) — предикат SUID/exec не добавлен либо severity не понижена. Это ровно те 37 критикалов при нуле истинных, ради которых волна и собрана"
[ "$((b_neg_sigma_after - b_neg_sigma_before))" -eq 0 ] \
    || die "5.9.9.F.3b ПРОВАЛЕН: обычный .txt под /tmp всё ещё поднимает sigma_binary_in_tmp_executed (Δ$((b_neg_sigma_after - b_neg_sigma_before))) — правило с именем «ELF binary executed» по-прежнему голый prefix /tmp/"
echo "  5.9.9.F.3b: обе половины сошлись"

# ---- 5.9.9.F.3c: песочница systemd --------------------------------------
# 5.9.9.F.4b (№142/№143), два изменения относительно отклонённого замера
# №2.9.9.F.3:
#   1. Порядок половин перевёрнут — позитив первым. Провал негатива не
#      имеет права прятать проверку на ослепление (находка №143): именно
#      ослепление, а не ложный ноль негатива, главный риск всей троицы
#      3a/3b/3c и нового 4a.
#   2. Величина негатива больше не Δincident_confirmed_attack за окно —
#      эта глобальная дельта считает фон самого измерителя (находка №142:
#      субъектом отклонённого замера №2.9.9.F.3 оказался не man-db, а
#      инструментарий пайплайна; фон измерителя закрывается отдельно
#      пунктом 4c, смешивать два дефекта в одной величине запрещено
#      постановкой). Вместо неё — число incidents (/api/v1/incidents) с
#      verdict="attack", чей process_chain/comms содержит актора формы
#      "(...)" — считается по актору инцидента, а не глобально.
echo "--- 5.9.9.F.3c: пара контролей песочницы systemd, позитив первым (№133, №142/№143) ---"
fp_incidents() { curl -s --max-time 20 -H "Authorization: Bearer $FP_TOKEN" "$FP_API/api/v1/incidents?limit=500" 2>/dev/null; }
fp_sandbox_actor_attack_incidents() {
    fp_incidents | jq '[.[] | select(.verdict=="attack") | select( ((.process_chain // []) + (.comms // [])) | any(test("^\\(.*\\)$")) )] | length' 2>/dev/null || echo 0
}
c_rules="container_escape_mount container_escape_chroot container_escape_unshare_user container_escape_cap_sys_admin privesc_unshare_user_ns cis_5_2_1_privileged_container"

c_pos_before=0
for r in $c_rules; do c_pos_before=$((c_pos_before + $(fp_count "$r"))); done
# ppid этого процесса — bash пайплайна, не 1: сужение по признаку «ребёнок
# pid 1» не имеет права его погасить. Побег настоящий: новый user+mount ns.
unshare -Urm --propagation private /bin/true >/dev/null 2>&1 || true
sleep 20
c_pos_after=0
for r in $c_rules; do c_pos_after=$((c_pos_after + $(fp_count "$r"))); done
echo "  позитивный: unshare -Urm с ppid!=1 -> Δ(шесть правил побега)=$((c_pos_after - c_pos_before))"
[ "$((c_pos_after - c_pos_before))" -ge 1 ] \
    || die "5.9.9.F.3c ПРОВАЛЕН живьём: настоящий unshare -Urm из процесса с ppid!=1 НЕ поднял ни одного из шести правил (Δ=0). Сужение вышло за границу песочницы systemd и ослепило детект побега целиком — это находка №57 и одновременно нарушение запрета постановки («песочница systemd никогда не интересна» неверно: побег через unshare+mount существует)"
echo "  5.9.9.F.3c: позитивная половина сошлась (обязана исполняться первой — находка №143)"

c_sum_before=0
for r in $c_rules; do c_sum_before=$((c_sum_before + $(fp_count "$r"))); done
c_actor_inc_before=$(fp_sandbox_actor_attack_incidents)
fp_unit="${FP_SANDBOX_UNIT:-man-db.service}"
if systemctl list-unit-files "$fp_unit" >/dev/null 2>&1 && [ -n "$(systemctl list-unit-files --no-legend "$fp_unit" 2>/dev/null)" ]; then
    systemctl start "$fp_unit" 2>&1 | sed 's/^/    /' || true
    # Юнит одноразовый (Type=oneshot) — ждём и его работу, и корреляцию.
    sleep 45
    c_sum_after=0
    for r in $c_rules; do c_sum_after=$((c_sum_after + $(fp_count "$r"))); done
    c_actor_inc_after=$(fp_sandbox_actor_attack_incidents)
    echo "  негативный: systemctl start $fp_unit -> Δ(шесть правил побега)=$((c_sum_after - c_sum_before)) Δ(incidents verdict=attack с актором песочницы в process_chain/comms)=$((c_actor_inc_after - c_actor_inc_before))"
    fp_alerts | jq -r --arg t "$(date -u -d '-2 min' +%Y-%m-%dT%H:%M 2>/dev/null || echo zzz)" \
        '.[]|select(.timestamp >= $t)|"    свежий алерт: \(.rule_id) comm=\(.comm) pid=\(.pid)"' 2>/dev/null | tail -20
    [ "$((c_sum_after - c_sum_before))" -eq 0 ] \
        || die "5.9.9.F.3c ПРОВАЛЕН: старт sandboxed-юнита $fp_unit всё ещё поднимает правила побега из контейнера (Δ$((c_sum_after - c_sum_before))). Признак песочницы не структурный либо не покрыл форму comm '(unit)' — ровно так не обобщилось исключение по comm у находки №111. idle-час замера снова даст verdict=\"attack\" на pid 1, и обязательная величина приёмки №3 недостижима"
    [ "$((c_actor_inc_after - c_actor_inc_before))" -eq 0 ] \
        || die "5.9.9.F.3c ПРОВАЛЕН: старт $fp_unit всё ещё дал incident с verdict=attack, чей process_chain/comms содержит актора формы «(...)» (Δ$((c_actor_inc_after - c_actor_inc_before))) — шесть правил побега замолчали, но корреляция набирает score из оставшихся правил на том же акторе (sensitive_file_read, drift_*, rootkit_hidden_dir_dev). Пункт 3c закрыт наполовину. Если непустой Δ объясняется исключительно фоном самого пайплайна (находка №147, закрывается пунктом 4c) — это отдельная находка, а не провал этого контроля, и должна быть названа явно, а не молчаливо проигнорирована"
else
    die "5.9.9.F.3c: юнит $fp_unit не найден на стенде — негативный контроль без входа. Задать FP_SANDBOX_UNIT= настоящим sandboxed-юнитом (PrivateTmp/PrivateDevices), иначе пункт 3c не проверен ничем, а его ноль на idle-часе неотличим от тихого часа"
fi
echo "  5.9.9.F.3c: обе половины сошлись"

echo "5.9.9.F.3a/3b/3c доказаны живьём в $(date -u +%H:%M:%S) UTC: три правки сузились, ни одна не ослепла"

echo "=== [9.5/14] позитивный контроль cred_proc_maps_mass_read живьём (5.9.9.Fg, находка №112) ==="
# Только на предпрогоне. На полном замере шаг стоит ВНУТРИ full_run() (окно
# атак) — там его читает крит. 7, и второй прогон вне окна дал бы правилу
# ненулевой абсолют ДО idle-часа, то есть включил бы ветку спасения фонового
# правила чужой заслугой и замаскировал бы настоящий регресс в крит. 6.
#
# Смысл шага ровно тот же, что у контролей DNS в [7/14]: сужение
# cred_proc_maps_mass_read до numeric-PID (5.9.9.Fa) правит ПРАВИЛО, и
# «сработает ли оно на живом ядре» офлайн-реплеем не проверяется никак —
# юнит-тест судит матчер, а не путь ядро→коллектор→корреляция→стор.
if [ "${SMOKE_ONLY:-0}" = "1" ]; then
    cd $SETUP/attacks
    CRED_API="http://${VPS_IP:-localhost}:19090"
    CRED_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
    cred_alerts() { curl -s --max-time 15 -H "Authorization: Bearer $CRED_TOKEN" "$CRED_API/api/v1/alerts" 2>/dev/null; }
    cred_count() { cred_alerts | jq --arg r "$1" '[.[]|select(.rule_id==$r)]|length' 2>/dev/null || echo 0; }

    cred_before=$(cred_count cred_proc_maps_mass_read)
    dump_before=$(cred_count sigma_memory_proc_dump)
    echo "  до контроля: cred_proc_maps_mass_read=$cred_before sigma_memory_proc_dump=$dump_before"

    EBPF_GUARD_API="$CRED_API" EBPF_GUARD_TOKEN="$CRED_TOKEN" \
        bash ./run-all-attacks.sh --cred-proc-maps-control 2>&1 | tee /root/cred-proc-maps-2.9.9.F.5.txt
    cred_marker=$(ls -t $SETUP/attacks/attack-results/cred-proc-maps-control-*.txt 2>/dev/null | head -1)
    [ -n "$cred_marker" ] || die "5.9.9.Fa: позитивный контроль не оставил маркера — шаг не исполнен"
    sed 's/^/  маркер: /' "$cred_marker"
    grep -q '^skipped=1' "$cred_marker" && die "5.9.9.Fa: контроль пропущен харнессом: $(awk -F= '$1=="skip_reason"{$1="";print substr($0,2)}' "$cred_marker") — это дефект стенда, не детекта"
    grep -q '^done=1' "$cred_marker" || die "5.9.9.Fa: контроль не дочитал /proc/<pid>/maps (done!=1) — шаг не состоялся"

    # Порог правила — 5 за 10 с; корреляция и запись в стор идут асинхронно.
    sleep 20
    cred_after=$(cred_count cred_proc_maps_mass_read)
    dump_after=$(cred_count sigma_memory_proc_dump)
    echo "  после контроля: cred_proc_maps_mass_read=$cred_after (Δ$((cred_after - cred_before))) sigma_memory_proc_dump=$dump_after (Δ$((dump_after - dump_before)))"
    cred_alerts | jq -r '.[]|select(.rule_id=="cred_proc_maps_mass_read")|"    \(.rule_id) comm=\(.comm) pid=\(.pid) \(.message)"' 2>/dev/null | tail -5

    [ "$((cred_after - cred_before))" -ge 1 ] \
        || die "5.9.9.Fa ПРОВАЛЕН живьём: 8 чтений /proc/<pid>/maps процессом comm=credscrape не дали НИ ОДНОГО алерта cred_proc_maps_mass_read. Сужение до numeric-PID ослепило правило (находка №57) — полный замер объявил бы это регрессом детекта в крит. 6 после потраченного idle-часа"
    # 5.9.9.F.1b (находка №111): на волне 5.9.9.F этот же контроль для
    # sigma_memory_proc_dump был МЯГКИМ («ВНИМАНИЕ ... цепочку не
    # останавливает»), и это было верно ровно до 5.9.9.F.1b. После неё
    # правило потеряло /proc/[0-9]+/cmdline — то есть потеряло единственный
    # источник, который поднимал его на этом стенде без атаки (18 из 19
    # алертов №2.9.9.F: landscape-sysinfo и dbus-daemon). Теперь ЭТИ восемь
    # чтений /proc/<pid>/maps — единственный вход правила за весь прогон.
    # Ноль здесь означает не «отдельную находку», а ровно то, что постановка
    # назвала главным риском волны: правка неотличима от ослепления по
    # счётчику. Полный замер после этого объявил бы правило потерянным в
    # крит. 6 — после потраченного idle-часа и часа атак.
    [ "$((dump_after - dump_before))" -ge 1 ] \
        || die "5.9.9.F.1b ПРОВАЛЕН живьём: sigma_memory_proc_dump не поднялся на 8 чтениях чужого /proc/<pid>/maps (Δ=0). После снятия предиката cmdline это ЕДИНСТВЕННЫЙ вход правила на стенде — ноль означает ослепление (находка №57), а не тишину. Полный замер потратил бы 1.5 часа, чтобы напечатать это же как регресс детекта в крит. 6"
    echo "5.9.9.Fa/5.9.9.F.1b доказаны живьём в $(date -u +%H:%M:%S) UTC: оба правила видят чтение чужого /proc/<pid>/maps"
    rm -f /tmp/credscrape

    # --- Негативные контроли обеих правок волны 5.9.9.F.1 ------------------
    # Позитивная половина выше доказывает, что правила не ослепли. Негативная
    # половина ниже доказывает, что они СУЗИЛИСЬ — то есть что ожидаемые нули
    # приёмки (19 -> 1 и 10 -> 0) получены правкой условия, а не поломкой
    # загрузки правил. Без неё «0 за прогон» и «правило не загрузилось»
    # неотличимы, и оба дали бы одинаково зелёный крит. 6 через реестры.
    # Путь именно /api/v1/rules (internal/exporter/api.go:40). Голый /rules
    # отдаёт «404 page not found», и до 5.9.9.F.1d проверка ниже читала эту
    # строку как «правило не загрузилось» и валила смок с диагнозом «битый
    # YAML» при исправных правилах (находка №117).
    rules_json=$(curl -s --max-time 15 -H "Authorization: Bearer $CRED_TOKEN" "$CRED_API/api/v1/rules" 2>/dev/null)
    # Сначала — что ответ вообще реестр правил. Иначе любой отказ API
    # (404, пустое тело, отвалившийся токен) неотличим от «правило не
    # загрузилось», а именно на этом различии стоит весь смысл контроля.
    rules_total=$(echo "$rules_json" | jq -e 'if type=="array" then length else empty end' 2>/dev/null) \
        || die "5.9.9.F.1: $CRED_API/api/v1/rules не отдал JSON-массив правил (ответ: $(echo "$rules_json" | head -c 200)) — это отказ API/токена, а не сужение правил; негативные контроли ниже без реестра недоказуемы"
    [ "${rules_total:-0}" -gt 0 ] || die "5.9.9.F.1: реестр /api/v1/rules пуст — агент не загрузил ни одного правила"
    echo "  реестр правил агента: $rules_total правил"
    for r in sigma_memory_proc_dump web_sql_injection_files; do
        echo "$rules_json" | jq -e --arg r "$r" '[.. | objects | select(.id? == $r)] | length > 0' >/dev/null 2>&1 \
            || die "5.9.9.F.1: правило $r не найдено в /api/v1/rules — оно не загрузилось, и его ноль на приёмке означал бы битый YAML, а не сужение (проверить синтаксис правки)"
    done
    echo "  оба правленых правила загружены агентом (не битый YAML)"

    # Негативный контроль 5.9.9.F.1b: чтение чужого cmdline. До правки это
    # поднимало critical (landscape-sysinfo, dbus-daemon, 18 алертов за
    # №2.9.9.F), после — не обязано.
    cp /bin/cat /tmp/cmdlinescan 2>/dev/null || die "не удалось подготовить comm=cmdlinescan для негативного контроля 5.9.9.F.1b"
    dump_neg_before=$(cred_count sigma_memory_proc_dump)
    for _ in $(seq 1 20); do /tmp/cmdlinescan /proc/1/cmdline > /dev/null 2>&1; done
    sleep 20
    dump_neg_after=$(cred_count sigma_memory_proc_dump)
    echo "  негативный 5.9.9.F.1b: 20 чтений /proc/1/cmdline под comm=cmdlinescan -> Δsigma_memory_proc_dump=$((dump_neg_after - dump_neg_before))"
    [ "$((dump_neg_after - dump_neg_before))" -eq 0 ] \
        || die "5.9.9.F.1b ПРОВАЛЕН: чтение /proc/1/cmdline всё ещё поднимает sigma_memory_proc_dump (Δ$((dump_neg_after - dump_neg_before))) — предикат cmdline не убран либо агент крутит старые правила (проверить, что рестарт [5/14] подхватил новый rules/)"
    rm -f /tmp/cmdlinescan

    # Негативный контроль 5.9.9.F.1c: имена файлов с "--", "#", ";". Это
    # ровно те формы, что дали 10 критикалов на №2.9.9.F (session-файлы
    # systemd-logind и man-page git). Ни одна из них больше не SQL-инъекция.
    sql_neg_before=$(cred_count web_sql_injection_files)
    sql_dir=$(mktemp -d)
    for f in 'git-mergetool--lib.1.gz' '.#114376ChHzY' 'report;final.csv' 'libfoo--dev_1.2.3.deb'; do
        printf 'x' > "$sql_dir/$f" 2>/dev/null && cat "$sql_dir/$f" > /dev/null 2>&1
    done
    sleep 20
    sql_neg_after=$(cred_count web_sql_injection_files)
    echo "  негативный 5.9.9.F.1c: 4 имени файла с --/#/; -> Δweb_sql_injection_files=$((sql_neg_after - sql_neg_before))"
    [ "$((sql_neg_after - sql_neg_before))" -eq 0 ] \
        || die "5.9.9.F.1c ПРОВАЛЕН: имя файла с голым --/#/; всё ещё поднимает critical web_sql_injection_files (Δ$((sql_neg_after - sql_neg_before))) — паттерны не убраны либо агент крутит старые правила"
    rm -rf "$sql_dir"
    echo "5.9.9.F.1b/5.9.9.F.1c: негативные контроли пройдены в $(date -u +%H:%M:%S) UTC — сужение доказано, не поломка загрузки"
else
    echo "  пропущено: на полном замере шаг исполняется внутри full_run() (окно атак), крит. 7"
fi

# Наведённые контроли позади — дальше снова чистый инструментарий (пауза,
# idle-run.sh со своим, гораздо более узким корнем, гейт, отчёт), и дерево
# пайплайна снова исключается. Граница окна замера [11/14] снимает его ещё
# раз явно, как и требует 4c.
register_pipeline_observer_root

# SMOKE_ONLY=1 — короткий прогон «сборка + живые доказательства», без
# idle-часа и атак (~20 минут вместо ~2ч: наведённое CPU-давление добавляет
# к предпрогону до 3 минут ожидания reduce и до 2×min_dwell ожидания
# recovered). Именно здесь его место: всё, что выше, проверяется машинно и
# способно провалиться, а всё, что ниже, — это время.
#
# ПРЕДПРОГОН ОБЯЗАТЕЛЕН, и роль у него в этой волне третья по счёту, отличная
# от обеих предыдущих. На №2.9.9.F.1 он ловил ослепление продуктовых правок;
# на №2.9.9.F.2 — критерий, разучившийся падать; здесь обязаны исполниться
# ОБА класса сразу, потому что волна и продуктовая, и измерительная.
#
# Продуктовая половина — шаг [9.6/14], три пары контролей, каждая с жёстким
# стопом на ОБЕИХ половинах: позитивная (правило не ослепло) и негативная
# (правило сузилось). Это единственное место, где ослепление ловится ДО
# траты полутора часов; крит. 6 назвал бы его регрессом детекта после.
#
# Измерительная половина — шаг [1/14], реплеи 13/14 и 14/14: фаза idle не
# поглощается меткой преflight'а И четвёртая фаза при этом сохранена (3d);
# SKIP=0 достигается на архиве без правки самих критериев И счётчик
# неисполнившихся веток при этом умеет расти (3e). Второй исход у каждого
# обязателен: механизм, печатающий 0 всегда, вернул бы 0 и здесь — ровно
# этим была находка №124.
#
# Пункт волны, у которого отрицательный исход не исполнился, считается
# неисполненным, и цепочка останавливается там же.
#
# Приёмкой волны такой прогон НЕ является: величины 1, 3, 4, 6 приёмки
# (SKIP=0/FAIL=0, idle-час, реестр акторов, фазы прироста) имеют входом
# только idle-час и полный гейт.
if [ "${SMOKE_ONLY:-0}" = "1" ]; then
    echo "=== SMOKE_ONLY=1: сборка, SMOKE, оба контроля DNS, контроль счётности, переполнение кольца, наведённое CPU-давление (5.9.9.F.2b), ТРИ ПАРЫ КОНТРОЛЕЙ ПРОДУКТОВЫХ ПРАВОК (5.9.9.F.3a/3b/3c), позитивный контроль cred_proc_maps и пары 5.9.9.F.1b/5.9.9.F.1c пройдены ==="
    echo "=== 14/14 реплеев пройдены, включая оба отрицательных исхода волны 5.9.9.F.3 (реплеи 13-14) ==="
    echo "=== idle-час, атаки и гейт НЕ запускались — это не приёмка волны 5.9.9.F.3 ==="
    echo "=== ПРЕДПРОГОН №2.9.9.F.5 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC ==="
    # 5.9.9.F.4c: предпрогон не доходит до idle-часа, поэтому границы окна
    # замера [11/14] не существует — регистрация снимается здесь же, чтобы
    # не оставлять observer-root-pid указывающим на процесс, который вот-вот
    # завершится.
    release_pipeline_observer_root
    touch /root/PIPELINE-2.9.9.F.5-DONE
    exit 0
fi

echo "=== [10/14] пауза 660с: рестарт, smoke, контроли DNS и переполнение кольца выходят за окно журнала idle-run ==="
sleep 660

echo "=== [11/14] idle-час, NO_RESTART=1 (5.9.1c) — сокращать нельзя ==="
# 5.9.9.F.4c (№147): граница окна замера — дерево ПАЙПЛАЙНА обнуляется
# явно здесь, ДО старта idle-run.sh, а не полагается на то, что
# idle-run.sh перезапишет файл своим $$ (это тоже произойдёт, но неявная
# зависимость от порядка записи — не гарантия: постановка 4c требует
# явного обнуления на границе, не переиспользования чужого побочного
# эффекта). idle-run.sh регистрирует СВОЙ, гораздо более узкий корень
# (только собственный поллинг curl) сразу вслед за этим.
release_pipeline_observer_root
# Час — не запас прочности: FP grafana наблюдался ровно один раз за idle-час
# (период резолва порядка часа, не измерен). Окно короче застало бы «0
# long-label» отсутствием, а не починкой — тот PASS отсутствием, который
# 5.9.6i запретила.
cd $SETUP
OUT_DIR=$IDLE_OUT DURATION=3600 INTERVAL=300 NO_RESTART=1 bash ./idle-run.sh
echo "idle завершён в $(date -u +%H:%M:%S) UTC"

echo "=== [12/14] атаки — без разрыва цепочки, сразу за idle, без ssh между ними ==="
export IDLE_METRICS_START=$IDLE_OUT/metrics-start.txt
export IDLE_STATE_END=$IDLE_OUT/state-end.json
cd $SETUP/attacks
bash ./run-all-attacks.sh || echo "run-all-attacks.sh вернул $? — гейт всё равно считаем"
echo "атаки завершены в $(date -u +%H:%M:%S) UTC"
ls -t $SETUP/attacks/attack-results/attack-window-*.txt 2>/dev/null | head -1 | xargs -r cat | sed 's/^/  окно атаки (5.9.7d): /'

# 5.9.9.F.4c (продолжение): окно замера ЗАКРЫТО (idle-час [11/14] + атаки
# [12/14] позади), а всё, что идёт дальше, — снова инструментарий: сам гейт
# (сотни вызовов curl/jq/grep/awk), блок приёмки и наблюдение [14.1/14].
# Без повторной регистрации эти вызовы попадают в СНИМОК аптайма, по которому
# считается обязательная величина 8 («доля алертов измерителя < 5%») — то
# есть измеритель снова мерил бы сам себя, только на другом конце прогона.
# Регистрация здесь не может «спрятать» ничего из измеряемого: baseline,
# idle-час и окно атак уже сняты idle-run.sh и run-all-attacks.sh.
register_pipeline_observer_root

echo "=== [13/14] гейт, один вызов ==="
export IDLE_METRICS_END=$IDLE_OUT/metrics-end.txt
export IDLE_ALERTS_END=$IDLE_OUT/alerts-end.json
export IDLE_ALERTS_START=$IDLE_OUT/alerts-start.json
export AGENT_START_FILE=/root/agent-start-2.9.9.F.5.txt
bash ./run-gate.sh 2>&1 | tee /root/gate-2.9.9.F.5.txt
GATE_RC=${PIPESTATUS[0]}
echo "гейт вернул $GATE_RC"
# Пункты 1-14 постановки №2.9.9.F.5 не подлежат толкованию — вытаскиваем их
# строки отдельно, чтобы приёмка волны читалась без листания всего гейта.
echo "--- унаследованные величины (счётность, кольцо, DNS, темп, реестры) ---"
grep -E '=== (19|20|22)\.|5\.9\.8a\.|негативный|позитивный|канарейка|null:|idle:|ringbuf_full|bpf_lost_events_total|events_drain_offset|excluded\{observer_tree\}' \
    /root/gate-2.9.9.F.5.txt | sed 's/^/  /'
grep -E 'окно атаки, 5\.9\.7d|темп алертов|settle_reason|дерева измерителя|фон вне дерева|непокрытых пунктов|база брошена|потеряно вне реестров|dns\.qname|recall' \
    /root/gate-2.9.9.F.5.txt | sed 's/^/  /'

# --- ПРИЁМКА ВОЛНЫ 5.9.9.F.3: шесть величин, названных постановкой заранее -
#
# Здесь НЕТ die ни у одной проверки, и это осознанно — но причина другая,
# чем на №2.9.9.F.2. Там все правки делали критерии строже, и FAIL был
# успехом волны. Здесь три правки продуктовые, и их живые доказательства уже
# отработали жёсткими стопами на шаге [9.6/14], ДО траты idle-часа. Всё, что
# может сказать этот блок, — величины по итогу; ослепление сюда дойти не
# может, оно остановлено выше.
echo ""
echo "=== ПРИЁМКА ВОЛНЫ 5.9.9.F.3 — шесть величин постановки ==="
acc() { printf '  %-2s %s\n' "$1" "$2"; }
ACC_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
ACC_API="http://${VPS_IP:-localhost}:19090"
acc_alerts=$(curl -s --max-time 20 -H "Authorization: Bearer $ACC_TOKEN" "$ACC_API/api/v1/alerts" 2>/dev/null)
acc_rule() { echo "$acc_alerts" | jq --arg r "$1" '[.[]|select(.rule_id==$r)]|length' 2>/dev/null || echo '?'; }
acc_rule_crit() { echo "$acc_alerts" | jq --arg r "$1" '[.[]|select(.rule_id==$r and .severity=="critical")]|length' 2>/dev/null || echo '?'; }

# (1) SKIP=0 И FAIL=0 — перенесена с №2.9.9.F.2 неисполненной.
acc_line=$(grep -E '^RUN-GATE: PASS=' /root/gate-2.9.9.F.5.txt | tail -1)
acc_skip=$(echo "$acc_line" | sed -E 's/.*SKIP=([0-9]+).*/\1/')
acc_verdict=$(grep -cE '^\[FAIL\]|\[0;31m\[FAIL\]' /root/gate-2.9.9.F.5.txt || true)
if [ "${acc_skip:-99}" = "0" ] && [ "$GATE_RC" -eq 0 ]; then
    acc "1." "SKIP=0 и FAIL=0 ДОСТИГНУТЫ — $acc_line"
else
    acc "1." "SKIP=${acc_skip:-?}, вердикт гейта $GATE_RC, строк FAIL=$acc_verdict (ожидалось SKIP=0 и FAIL=0) — $acc_line"
    grep -E '\[SKIP\]|\[FAIL\]' /root/gate-2.9.9.F.5.txt | sed 's/^/       /'
    grep -E 'чья ветка не исполнилась' /root/gate-2.9.9.F.5.txt | sed 's/^/       /'
fi

# (2) Оба правленых правила: 0 критикалов ВНЕ позитивных контролей и
# ненулевые НА них. Абсолют по стору, а не дельта окна: контроли шага
# [9.6/14] стоят до baseline, и дельта окна их не видит по построению.
acc_a=$(acc_rule rootkit_hidden_dir_dev);        acc_a_c=$(acc_rule_crit rootkit_hidden_dir_dev)
acc_b=$(acc_rule privesc_suid_suspicious_path);  acc_b_c=$(acc_rule_crit privesc_suid_suspicious_path)
acc_bs=$(acc_rule sigma_binary_in_tmp_executed)
acc "2." "правленые правила за аптайм: rootkit_hidden_dir_dev=$acc_a (critical $acc_a_c, было 12/12), privesc_suid_suspicious_path=$acc_b (critical $acc_b_c, было 37/37), sigma_binary_in_tmp_executed=$acc_bs"
acc "  " "ожидание: у каждого >=1 (позитивные контроли шага [9.6/14]) и НИ ОДНОГО срабатывания вне них. Состав поимённо:"
echo "$acc_alerts" | jq -r '.[]|select(.rule_id=="rootkit_hidden_dir_dev" or .rule_id=="privesc_suid_suspicious_path")|"       \(.rule_id) \(.severity) comm=\(.comm) \(.details["file.path"] // "")"' 2>/dev/null | sort | uniq -c | sort -rn | head -20
if [ "${acc_a:-0}" = "0" ] || [ "${acc_b:-0}" = "0" ]; then
    acc "  " "ВНИМАНИЕ: правило с нулём за весь аптайм при исполнившемся позитивном контроле — это находка №57 (ослепление), а не сужение. Проверить маркеры шага [9.6/14] в логе выше"
fi
if echo "$acc_alerts" | jq -e '[.[]|select(.rule_id=="rootkit_hidden_dir_dev" and (.details["file.path"] // "" | test("urandom|random|console")))]|length > 0' >/dev/null 2>&1; then
    acc "  " "ВНИМАНИЕ: rootkit_hidden_dir_dev снова сработал на штатной ноде /dev — правка 3a откачена либо агент крутит старые правила"
fi

# (3) verdict="attack" за idle-час = 0 ПРИ НЕПУСТОМ idle-часе. Ноль на тихом
# часе не засчитывается: он неотличим от отсутствия входа (запрет 5.9.6i,
# PASS отсутствием события).
acc "3." "idle-час (verdict=\"attack\" = 0 при непустом часе, 5.9.9.F.3c):"
grep -E 'verdict="attack" за idle-час|алертов за idle-час|состав промоушенов по comm|промоушенов verdict=attack в журнале' /root/gate-2.9.9.F.5.txt | sed 's/^/       /'
# 5.9.9.F.5b/№153: журнал агента — независимый источник состава промоушенов
# (см. run-gate.sh, "correlator: incident promoted"), а не только снимок
# алертов. Печатается отдельно, чтобы при FAIL было видно, каким источником
# назван актор — алертами или журналом.
grep -E 'по журналу \(5\.9\.9\.F\.5b\)' /root/gate-2.9.9.F.5.txt | sed 's/^/       /'
acc_idle_alerts=$(grep -oE 'алертов за idle-час: [0-9]+' /root/gate-2.9.9.F.5.txt | tail -1 | grep -oE '[0-9]+$')
acc_idle_att=$(grep -oE 'verdict="attack" за idle-час: [0-9]+ -> [0-9]+, дельта = [0-9-]+' /root/gate-2.9.9.F.5.txt | tail -1 | grep -oE '[0-9-]+$')
if [ "${acc_idle_alerts:-0}" -eq 0 ] 2>/dev/null; then
    acc "  " "ВНИМАНИЕ: idle-час ПУСТ (0 алертов) — ноль по verdict=\"attack\" получен тишиной стенда, а не починкой 3c, и величиной приёмки НЕ является (запрет 5.9.6i). Замер обязан быть повторён в час, когда стартует хотя бы один sandboxed-юнит systemd"
elif [ "${acc_idle_att:-1}" = "0" ]; then
    acc "  " "ДОСТИГНУТО: verdict=\"attack\" = 0 при непустом idle-часе ($acc_idle_alerts алертов) — 3c закрыта величиной, которой нельзя достичь тишиной"
else
    acc "  " "НЕ ДОСТИГНУТО: verdict=\"attack\" за idle-час = ${acc_idle_att:-?} при $acc_idle_alerts алертах — состав промоушенов выше называет, кто именно; если это снова песочница systemd, пункт 3c закрыт наполовину"
fi

# (4) Новых акторов = 0 БЕЗ дописывания mandb/find/install в реестр.
# Второе проверяется преflight'ом жёстко; здесь печатается результат.
acc "4." "состав idle-часа против idle-actors.txt (5.9.9.F.2d/№118, реестр НЕ пополнялся):"
grep -E 'новые акторы idle-часа вне idle-actors|новых акторов 0|состав ВСЕХ новых алертов idle-часа' /root/gate-2.9.9.F.5.txt | sed 's/^/       /'
if grep -q 'новый(е) актор(ы) idle-часа вне idle-actors.txt' /root/gate-2.9.9.F.5.txt; then
    acc "  " "ВНИМАНИЕ: новые акторы есть. Если среди них mandb/find/install — правки 3a/3b/3c не сняли пакет systemd, и чинить это дописыванием в реестр ЗАПРЕЩЕНО постановкой. Если акторы другие — это новое окно суток, и оно пополняет реестр законно, отдельной записью в plan.md"
fi

# (5) Регресс правок волн 5.9.9.F/F.1 на месте.
acc_dump=$(acc_rule sigma_memory_proc_dump)
acc_sql=$(acc_rule web_sql_injection_files)
acc_cred=$(acc_rule cred_proc_maps_mass_read)
acc "5." "регресс прошлых волн: sigma_memory_proc_dump=$acc_dump (ожидается >=1), web_sql_injection_files=$acc_sql (ожидается 0), cred_proc_maps_mass_read=$acc_cred (ожидается >=1)"
[ "${acc_dump:-0}" = "0" ] && acc "  " "ВНИМАНИЕ: sigma_memory_proc_dump=0 — находка №57 на правке 5.9.9.F.1b"
[ "${acc_sql:-0}" != "0" ] && acc "  " "ВНИМАНИЕ: web_sql_injection_files=$acc_sql != 0 — правка 5.9.9.F.1c откачена"
[ "${acc_cred:-0}" = "0" ] && acc "  " "ВНИМАНИЕ: cred_proc_maps_mass_read=0 — находка №57 на правке 5.9.9.Fa"

# (6) 5.9.9.F.5c/№157: порог по СМЫСЛУ, не по константе 4, унаследованной
# с №2.9.9.F.2 (преflight этой волны вырос на пять жёстких стопов —
# константа больше ничего не защищает от). FAIL только если среди типов,
# напечатанных с меткой «наведено преflight-шагом» (то есть НЕ получивших
# композитную "phase+induced" метку — run-gate.sh:1113-1160), находится
# хотя бы один, чей рост НЕЗАВИСИМО подтверждается ростом
# ebpf_guard_alerts_total{rule_id=...} между IDLE_METRICS_START/END: если
# он растёт там — композитная метка была ОБЯЗАНА сработать (5.9.9.F.3d) и
# не сработала, то есть находка №134 вернулась. Идентична по данным
# add_idle_list из run-gate.sh, но вычисляется ЗАНОВО из тех же файлов
# снимков — это регресс-страховка на случай, если порядок веток в
# run-gate.sh снова переставят неверно, а не переиспользование того же
# результата под другим именем.
acc "6." "фазы прироста состава детекта (5.9.9.F.3d/№134, порог по смыслу — 5.9.9.F.5c/№157):"
grep -E 'добавлено по фазам|наведено шагом преflight' /root/gate-2.9.9.F.5.txt | head -14 | sed 's/^/       /'
acc_induced=$(grep -oE 'наведено преflight-шагом=[0-9]+' /root/gate-2.9.9.F.5.txt | tail -1 | grep -oE '[0-9]+$')
acc_induced_ids=$(awk '/наведено шагом преflight.*вне измеряемых окон/{f=1; next} f && /^    \* /{sub(/^    \* /,""); print; next} f && !/^    \* /{exit}' /root/gate-2.9.9.F.5.txt)
acc_induced_absorbed=""
if [ -n "$acc_induced_ids" ] && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
    idle_grown_rules_5c=$(awk -F'[{}", ]+' -v metric="ebpf_guard_alerts_total" -v startfile="$IDLE_METRICS_START" '
        function rule_id(   i, rid) { rid=""; for (i=1;i<=NF;i++) { if ($i ~ /^rule_id=?$/) { rid=$(i+1); break } }; return rid }
        { gsub(/\r/, "") }
        index($0, metric "{") != 1 { next }
        { rid = rule_id(); if (rid == "") next
          if (FILENAME == startfile) { start[rid] += $NF; next }
          end[rid] += $NF; seen[rid] = 1 }
        END { for (r in seen) if (end[r] - (start[r]+0) > 0) print r }
    ' "$IDLE_METRICS_START" "$IDLE_METRICS_END" 2>/dev/null)
    while IFS= read -r rid; do
        [ -z "$rid" ] && continue
        if echo "$idle_grown_rules_5c" | grep -qx "$rid"; then
            acc_induced_absorbed="$acc_induced_absorbed$rid"$'\n'
        fi
    done <<< "$acc_induced_ids"
fi
acc_induced_absorbed=$(echo "$acc_induced_absorbed" | grep -v '^$' || true)
if [ -n "$acc_induced_absorbed" ]; then
    acc "  " "НЕ ДОСТИГНУТО: тип(ы) $(echo "$acc_induced_absorbed" | tr '\n' ' ') напечатаны с плоской меткой «наведено преflight-шагом», но независимо от gate.txt растут в ebpf_guard_alerts_total между IDLE_METRICS_START/END — композитная idle+induced метка обязана была сработать (5.9.9.F.3d) и не сработала. Находка №134 вернулась"
elif [ -n "$acc_induced_ids" ]; then
    acc "  " "ДОСТИГНУТО: наведено преflight-шагом=${acc_induced:-?} тип(ов) ($(echo "$acc_induced_ids" | tr '\n' ' ')), ни один независимо не растёт в idle-окне — поглощение idle меткой преflight'а не воспроизводится. Величина оценивается ПО СМЫСЛУ, а не порогом (5.9.9.F.5c/№157: число 4, унаследованное с №2.9.9.F.2, снято)"
else
    acc "  " "ДОСТИГНУТО: наведено преflight-шагом=0 — нечего поглощать по построению"
fi
acc "  " "ГРАНИЦА (5.9.9.F.5c): независимая проверка охватывает только idle-окно (IDLE_METRICS_START/END доступны пайплайну напрямую); окно атак опирается на собственный инвариант run-gate.sh (attack/idle/gap проверяются ДО induced, 5.9.9.F.3d) без второй, независимо вычисленной, копии — своих снимков baseline/final metrics у пайплайна нет"

# --- Новые величины волны 5.9.9.F.4: 7-12. Все пункты волны исполнены в
# дереве (4a-4h) плюс перенос 4i, поэтому печатаются ВСЕ шесть новых величин,
# а не подмножество. Величина без печати не является величиной приёмки —
# ровно так 5.9.9.F.2c/2g прошли замер незаведёнными (№138). ---

# (7) 5.9.9.F.4a/4b/№141/№142: ни одного инцидента verdict=attack, чья цепочка
# содержит актора вида (...) при ppid==1 — за ВЕСЬ аптайм (idle-час + окно
# атак). Считается по актору инцидента (пункт 4b), а не глобальной дельтой:
# ровно на этой подмене сторож №2.9.9.F.3 назвал субъектом man-db вместо фона
# самого измерителя.
acc_sandbox_inc=$(fp_sandbox_actor_attack_incidents 2>/dev/null || echo "?")
acc "7." "инцидентов verdict=attack с актором песочницы «(...)»/ppid==1 в цепочке (5.9.9.F.4a/4b): ${acc_sandbox_inc}"
if [ "${acc_sandbox_inc:-?}" = "0" ]; then
    acc "  " "ДОСТИГНУТО: 0 — двенадцать правил (5.9.9.F.4a) сняли класс актора целиком, и корреляция больше не набирает score на нём из остальных правил"
elif [ "${acc_sandbox_inc:-?}" = "?" ]; then
    acc "  " "SKIP: /api/v1/incidents недоступен — величина 7 не посчитана (не PASS)"
else
    acc "  " "НЕ ДОСТИГНУТО: ${acc_sandbox_inc} инцидент(ов) — состав:"
    fp_incidents 2>/dev/null | jq -r '.[]|select(.verdict=="attack")|select(((.process_chain // []) + (.comms // [])) | any(test("^\\(.*\\)$")))|"       incident \(.id // "-") comm=\(.comm // "-") rules=\((.rule_ids // []) | join(","))"' 2>/dev/null | head -10
    acc "  " "читать так: если правила инцидента — НЕ двенадцать правил 4a, класс актора поднимают ЕЩЁ какие-то правила, и список №141 неполон так же, как был неполон список 3c (это находка следующего замера, а не провал 4a); если правила ИЗ списка 4a — исключение не применилось, правка не в дереве или агент крутит старые правила"
fi

# (8) 5.9.9.F.4c/№147, пересчитано 5.9.9.F.5e/№155: доля алертов от акторов
# измерителя и сборки СЧИТАЕТСЯ ПО ОКНАМ ОТДЕЛЬНО (преflight / idle-час / окно
# атак), а не одной цифрой за весь аптайм. Одна цифра (было: acc_alerts —
# снимок с рестарта [5/14] до этого момента) складывала три разных
# утверждения: 131/475 (преflight, единственное окно, на которое влияет
# пункт 4c), 1/607 (idle-час, атак ещё не было) и 89/866 (окно атак, где
# curl/jq/grep — это ОРУЖИЕ манифеста, а не фон измерителя: 20 срабатываний
# lateral_tool_transfer_wget и один incident_confirmed_attack оказались
# погашены только потому, что их comm совпал с именем из списка). Список
# harness-comm — поимённо из постановки волны (не восстанавливается по
# коду): curl, jq, grep, go, ld, clang, llvm-strip, bpf2go, *.test,
# cmdlinescan. `*.test` матчится суффиксом (go test компилирует бинарь вида
# pkgname.test), остальные — точным именем comm.
acc_harness_comms='["curl","jq","grep","go","ld","clang","llvm-strip","bpf2go","cmdlinescan"]'
# ГРАНИЦА (5.9.9.F.5e): постановка требует отделять curl измерителя от curl
# манифеста «по предку (дерево пайплайна против дерева run-all-attacks.sh),
# а не по имени» и ссылается на process_chain/root_comm алерта. У алерта
# (/api/v1/alerts) этих полей НЕТ — они существуют только на инциденте
# (pkg/types/incident.go: RootComm/ProcessChain, см. память
# alerts-api-has-no-process-chain.md); у алерта есть `process_tree`
# (pkg/types/event.go: []ProcessNode{pid,ppid,comm}, от старейшего предка к
# сработавшему процессу). Использован он: root_comm = .process_tree[0].comm.
# Это ловит один реальный класс — comm из списка, запущенный НЕ через shell
# (например, сервисом напрямую), — но НЕ различает пайплайн и
# run-all-attacks.sh МЕЖДУ СОБОЙ: оба — `bash script.sh`, kernel даёт им
# одинаковый comm="bash" на каждом уровне дерева (comm ставится по
# исполняемому файлу — /bin/bash, — а не по имени скрипта в argv; тот же
# класс дефекта, что shebang-control-comm-is-interpreter.md, только для
# уровня "оболочка", а не "интерпретатор"). Различить curl пайплайна от curl
# манифеста ВНУТРИ одного bash-дерева этим полем нельзя — открытый вопрос,
# не решённый этим заходом (см. итог ниже), и ровно поэтому порог <5%
# применяется ТОЛЬКО к преflight-окну (см. постановку 5.9.9.F.5e): там
# манифест ещё не запущен, и любой harness-comm по построению — это
# инструментарий, а не атака.
acc_harness_root_ok='(((.process_tree // [])[0].comm // "bash") as $rc | ($rc == "bash" or $rc == "sh" or $rc == "dash"))'
acc_harness_filter="((.comm // \"\") as \$c | (\$hc | index(\$c)) or (\$c | test(\"\\\\.test\$\"))) and $acc_harness_root_ok"

acc_win_stats() {
    # $1 = alerts JSON (массив). Печатает "harness total pct" одной строкой.
    local json="$1" total harness pct
    total=$(echo "$json" | jq 'length' 2>/dev/null)
    harness=$(echo "$json" | jq --argjson hc "$acc_harness_comms" "[.[] | select($acc_harness_filter)] | length" 2>/dev/null)
    if [ "${total:-0}" -gt 0 ] 2>/dev/null; then
        pct=$(awk -v h="${harness:-0}" -v t="$total" 'BEGIN{printf "%.1f", 100*h/t}')
    else
        pct="n/a"
    fi
    echo "${harness:-?} ${total:-0} ${pct}"
}
acc_win_breakdown() {
    # $1 = alerts JSON. Печатает состав по паре (comm, rule_id) — 5.9.9.F.5f.
    echo "$1" | jq --argjson hc "$acc_harness_comms" -r \
        "[.[] | select($acc_harness_filter)] | group_by([.comm, .rule_id]) | map({c: (.[0].comm), r: (.[0].rule_id), n: length}) | sort_by(-.n) | .[] | \"       \(.n)\t\(.c)\t\(.r)\"" \
        2>/dev/null | head -20
}

# Окно преflight'а: снимок IDLE_ALERTS_START (idle-run.sh пишет его ДО первого
# тика idle-часа) — единственный доступный пайплайну снимок границы
# преflight/idle-час. Взят как есть (все алерты в файле), а не диффом от
# нулевой точки: агент перезапущен на [9/14], и допущение — что стор пуст на
# рестарте — не проверено живым замером (записано открытым вопросом ниже).
acc_pf_json='[]'
[ -s "$IDLE_ALERTS_START" ] && acc_pf_json=$(cat "$IDLE_ALERTS_START" 2>/dev/null || echo '[]')

# Окно idle-часа: новые по id алерты между IDLE_ALERTS_START и IDLE_ALERTS_END
# — та же пара снимков, что уже использует run-gate.sh (критерий 16/величина
# 3), диф вычисляется здесь заново, а не переиспользуется под другим именем.
acc_idle_json='[]'
acc_idle_have=0
if [ -s "$IDLE_ALERTS_START" ] && [ -s "$IDLE_ALERTS_END" ]; then
    acc_idle_json=$(jq -n --slurpfile a "$IDLE_ALERTS_START" --slurpfile b "$IDLE_ALERTS_END" \
        '($a[0]|map(.id)) as $seen | ($b[0]|map(select(.id as $i | ($seen|index($i))|not)))' 2>/dev/null)
    [ -n "$acc_idle_json" ] && acc_idle_have=1
fi

# Окно атак: новые по id алерты между baseline-alerts-*.json и
# final-alerts-*.json последнего вызова run-all-attacks.sh (пишет их сам
# контроль, $SETUP/attacks/attack-results/, тот же источник, что читает
# run-gate.sh под именами baseline_alerts/final_alerts своего TIMESTAMP).
# Берётся САМЫЙ ПОЗДНИЙ по имени файл — тот же приём, что latest_marker() в
# run-gate.sh: в имени лежит YYYYmmdd_HHMMSS, и это вызов [12/14], последний
# по времени среди всех вызовов run-all-attacks.sh пайплайна (DNS/ringbuf/
# cpu-pressure/cred-proc-maps контроли исполняются раньше, каждый со своим
# TIMESTAMP).
acc_attack_dir="$SETUP/attacks/attack-results"
acc_attack_baseline_file=$(ls -1 "$acc_attack_dir"/baseline-alerts-*.json 2>/dev/null | LC_ALL=C sort | tail -1)
acc_attack_final_file=$(ls -1 "$acc_attack_dir"/final-alerts-*.json 2>/dev/null | LC_ALL=C sort | tail -1)
acc_attack_json='[]'
acc_attack_have=0
if [ -s "$acc_attack_baseline_file" ] && [ -s "$acc_attack_final_file" ]; then
    acc_attack_json=$(jq -n --slurpfile a "$acc_attack_baseline_file" --slurpfile b "$acc_attack_final_file" \
        '($a[0]|map(.id)) as $seen | ($b[0]|map(select(.id as $i | ($seen|index($i))|not)))' 2>/dev/null)
    [ -n "$acc_attack_json" ] && acc_attack_have=1
fi

read -r acc_pf_h acc_pf_t acc_pf_pct <<< "$(acc_win_stats "$acc_pf_json")"
acc "8." "доля алертов от акторов измерителя и сборки, по окнам (5.9.9.F.4c/5.9.9.F.5e/№147/№155):"
acc "  " "преflight: $acc_pf_h из $acc_pf_t (${acc_pf_pct}%) — единственное окно с порогом < 5% (было 55% на отклонённом №2.9.9.F.3, 27.6% на №2.9.9.F.4)"
if [ "${acc_pf_t:-0}" -gt 0 ] 2>/dev/null; then
    if awk -v p="$acc_pf_pct" 'BEGIN{exit !(p < 5)}'; then
        acc "  " "ДОСТИГНУТО: преflight < 5%"
    else
        acc "  " "НЕ ДОСТИГНУТО: преflight >= 5% — состав по (comm, rule_id):"
        acc_win_breakdown "$acc_pf_json"
    fi
else
    acc "  " "SKIP: IDLE_ALERTS_START пуст или недоступен — преflight-доля не посчитана"
fi

if [ "$acc_idle_have" -eq 1 ]; then
    read -r acc_idle_h acc_idle_t acc_idle_pct <<< "$(acc_win_stats "$acc_idle_json")"
    acc "  " "idle-час: $acc_idle_h из $acc_idle_t (${acc_idle_pct}%) — наблюдение без порога (постановка 5.9.9.F.5e трогает только преflight); ненулевое здесь — атаки ещё не запущены, харнесс-comm может быть только утечкой поллинга idle-run.sh"
    [ "${acc_idle_h:-0}" -gt 0 ] 2>/dev/null && acc_win_breakdown "$acc_idle_json"
else
    acc "  " "idle-час: SKIP — IDLE_ALERTS_START/END недоступны, доля не посчитана"
fi

if [ "$acc_attack_have" -eq 1 ]; then
    read -r acc_atk_h acc_atk_t acc_atk_pct <<< "$(acc_win_stats "$acc_attack_json")"
    acc "  " "окно атак: $acc_atk_h из $acc_atk_t (${acc_atk_pct}%) — наблюдение без порога; ЧИСЛО НЕ ОЧИЩЕНО от кривой манифеста: curl/jq здесь могут быть как оркестровкой run-all-attacks.sh (настоящий фон), так и полезной нагрузкой атаки (lateral_tool_transfer_wget через curl и т.п.) — root_comm их не различает (оба дерева = bash, см. ГРАНИЦА выше), состав ниже — единственный способ разобрать это глазами"
    [ "${acc_atk_h:-0}" -gt 0 ] 2>/dev/null && acc_win_breakdown "$acc_attack_json"
else
    acc "  " "окно атак: SKIP — baseline/final-alerts-*.json последнего run-all-attacks.sh не найдены в $acc_attack_dir"
fi
# (8, "Учёт" п.2 постановки 4c) systemctl/journalctl говорят с pid 1 по
# dbus — pid 1 потомком дерева пайплайна не является ни при каком root_pid
# (config-test.yaml, комментарий 5.9.5f/находка №68), поэтому регистрация
# выше их не ловит по построению. Устранить эти вызовы из окна пайплайн не
# может (systemctl start/stop/show нужны шагу [5/14], journalctl — шагу
# [6/14], оба — преflight) — постановка требует напечатать остаток отдельной
# величиной наблюдения, а не списывать его молча на 4c. Считается по
# преflight-окну (acc_pf_json), а не по всему аптайму — pid1-акторы этих двух
# шагов физически не могут появиться в idle-часе/окне атак.
acc_pid1_actors='["systemd","systemd-logind","dbus-daemon","polkitd","journald","systemd-journal","systemd-udevd"]'
acc_pid1_alerts=$(echo "$acc_pf_json" | jq --argjson pc "$acc_pid1_actors" '[.[] | select((.comm // "") as $c | $pc | index($c))] | length' 2>/dev/null)
acc "  " "наблюдение без порога: алертов преflight'а от акторов, наведённых pid 1 (systemctl/journalctl самого пайплайна, дерево-исключение их не ловит) = ${acc_pid1_alerts:-0}"
acc_excl_obs=$(grep -oE 'excluded\{observer_tree\}[^:]*: [0-9]+' /root/gate-2.9.9.F.5.txt | tail -1 | grep -oE '[0-9]+$')
if [ "${acc_excl_obs:-0}" -gt 0 ] 2>/dev/null; then
    acc "  " "ДОСТИГНУТО: events_excluded_total{reason=\"observer_tree\"} = $acc_excl_obs (не ноль — исключение действительно сработало, доля не упала по другой причине)"
else
    acc "  " "ВНИМАНИЕ: events_excluded_total{reason=\"observer_tree\"} = ${acc_excl_obs:-0} — если доля выше при этом упала, падение объяснить нечем (пункт 4c регистрации не сработал), значение пункта 8 под вопросом"
fi

# (9) 5.9.9.F.4d/№144: owasp_path_traversal + web_path_traversal_extended —
# 0 критикалов вне позитивного контроля, ненулевые НА нём. Абсолют по
# стору, тем же приёмом, что величина 2.
acc_pt1=$(acc_rule owasp_path_traversal); acc_pt1_c=$(acc_rule_crit owasp_path_traversal)
acc_pt2=$(acc_rule web_path_traversal_extended); acc_pt2_c=$(acc_rule_crit web_path_traversal_extended)
acc "9." "path traversal за аптайм (5.9.9.F.4d/№144): owasp_path_traversal=$acc_pt1 (critical $acc_pt1_c, было 18+7+3+1+1=30 ложных), web_path_traversal_extended=$acc_pt2 (critical $acc_pt2_c, было столько же ложных)"
echo "$acc_alerts" | jq -r '.[]|select(.rule_id=="owasp_path_traversal" or .rule_id=="web_path_traversal_extended")|"       \(.rule_id) \(.severity) comm=\(.comm)"' 2>/dev/null | sort | uniq -c | sort -rn | head -20
acc_pt_offcomm=$(echo "$acc_alerts" | jq '[.[]|select((.rule_id=="owasp_path_traversal" or .rule_id=="web_path_traversal_extended") and ((.comm // "") as $c | (["nginx","apache2","httpd","php-fpm","node","python","gunicorn","uwsgi","java","tomcat"] | index($c)) | not))] | length' 2>/dev/null)
if [ "${acc_pt_offcomm:-0}" != "0" ]; then
    acc "  " "ВНИМАНИЕ: $acc_pt_offcomm срабатывание(й) с comm вне списка веб-воркера — сужение (5.9.9.F.4d) неполно, правило грузит старую версию, либо в reports попал comm, который стоит добавить в список"
fi
# Маркер контроля читается из attack-manifest.json (category), туда его пишет
# run_path_traversal_positive_control — без этого «0 за аптайм» неотличим от
# «контроль не исполнился», и величина 9 не читается вовсе.
acc_pt_pos=$(jq '[.[]|select(.category=="path_traversal_positive_control")]|length' $SETUP/attacks/attack-manifest.json 2>/dev/null || echo 0)
acc "  " "маркеров позитивного контроля 5.9.9.F.4d в attack-manifest.json: ${acc_pt_pos:-0}"
if [ "${acc_pt1:-0}" = "0" ] && [ "${acc_pt2:-0}" = "0" ]; then
    if [ "${acc_pt_pos:-0}" = "0" ]; then
        acc "  " "ВНИМАНИЕ: оба правила = 0 за аптайм И контроль не исполнился (маркера нет) — ноль без входа, величина 9 НЕ засчитывается"
    else
        acc "  " "НЕ ДОСТИГНУТО: оба правила = 0 за аптайм ПРИ исполнившемся контроле — это находка №57 (ослепление), а не сужение 5.9.9.F.4d"
    fi
elif [ "${acc_pt_pos:-0}" != "0" ] && [ "${acc_pt_offcomm:-0}" = "0" ]; then
    acc "  " "ДОСТИГНУТО: срабатывания есть, все с comm веб-воркера, контроль исполнился"
fi

# (10) 5.9.9.F.4e/№145: exfil_archive_to_network_pipe. Негатив (одиночный
# curl без архиватора-родителя) исполняется десятками вызовов манифеста по
# построению; позитив — run_exfil_archive_parent_positive_control.
# ГРАНИЦА: правка выражает только РОДИТЕЛЬСКУЮ форму (tar -> curl). Дословная
# формулировка величины постановки («Δ≥1 на tar | curl») описывает
# sibling-форму классического пайпа, которой движок не видит вовсе — она
# остаётся невыполненной до stateful-корреляции братьев, и это записано
# заранее (plan.md, 4e), а не объясняется задним числом нулём в этой строке.
acc_exfil=$(acc_rule exfil_archive_to_network_pipe)
# Маркер контроля лежит В МАНИФЕСТЕ (attack-manifest.json, category), а не
# отдельным файлом в attack-results/ — так его пишет
# run_exfil_archive_parent_positive_control. 5.9.9.F.5a/№152: маркер сам по
# себе больше не доказывает форму — контроль раньше исполнялся и писал
# маркер, создавая ПОДРАЖАТЕЛЯ comm=bash (интерпретатор шебанг-скрипта), а
# не comm=tar. Поле comm_verified — это то, что сторож самого контроля
# (/proc/self/comm) подтвердил ДО записи в манифест.
acc_exfil_pos=$(jq '[.[]|select(.category=="exfil_archive_parent_positive_control")]|length' $SETUP/attacks/attack-manifest.json 2>/dev/null || echo 0)
acc_exfil_comm_ok=$(jq '[.[]|select(.category=="exfil_archive_parent_positive_control" and .comm_verified==true)]|length' $SETUP/attacks/attack-manifest.json 2>/dev/null || echo 0)
acc "10." "exfil_archive_to_network_pipe за аптайм (5.9.9.F.5a/№152, было 5.9.9.F.4e/№145): $acc_exfil (было 96 — первое место по объёму), маркеров позитивного контроля: $acc_exfil_pos, из них comm=tar подтверждён: $acc_exfil_comm_ok"
echo "$acc_alerts" | jq -r '.[]|select(.rule_id=="exfil_archive_to_network_pipe")|"       comm=\(.comm) parent=\(.details["proc.parent_comm"] // "-")"' 2>/dev/null | sort | uniq -c | sort -rn | head -10
if [ "${acc_exfil_pos:-0}" = "0" ]; then
    acc "  " "ВНИМАНИЕ: позитивный контроль не исполнился (маркера нет) — любое значение этой строки неотличимо от ослепления (находка №57), величина 10 НЕ засчитывается"
elif [ "${acc_exfil_comm_ok:-0}" = "0" ]; then
    acc "  " "FAIL(сторож 5.9.9.F.5a): маркер контроля есть, но comm_verified не true — архиватор-родитель не подтвердил comm=tar через /proc/self/comm (та же болезнь, что у №145/№152 на отклонённой форме), величина 10 НЕ засчитывается ни одной стороной"
elif [ "${acc_exfil:-0}" = "0" ]; then
    acc "  " "НЕ ДОСТИГНУТО: контроль исполнился и подтвердил comm=tar, а правило дало 0 — родительская форма tar->curl не поднимает правило вовсе (ослепление либо comm архиватора не доходит до proc.parent_comm)"
else
    acc "  " "ДОСТИГНУТО (в границе пункта): ненулевое на родительской форме под подтверждённым comm=tar; строки с parent вне списка архиваторов означали бы, что сужение не применилось"
fi

# (11) 5.9.9.F.4f/№146: drift_new_exec_critical. Предикат переведён с op==open
# на факт exec, поэтому «0 критикалов на open() без exec» достигается по
# построению; смысл имеет ВТОРАЯ половина — ненулевое на настоящем exec из
# манифеста. Отдельного контроля именно под эту величину в манифесте нет
# (записано открытым вопросом в plan.md, 4f), поэтому опорой служит состав.
acc_drift=$(acc_rule drift_new_exec_critical); acc_drift_c=$(acc_rule_crit drift_new_exec_critical)
acc "11." "drift_new_exec_critical за аптайм (5.9.9.F.4f/№146): $acc_drift (critical $acc_drift_c, было 44 критикала на op==open)"
acc_drift_file_ev=$(echo "$acc_alerts" | jq '[.[]|select(.rule_id=="drift_new_exec_critical" and ((.details["file.path"] // "") != "") and ((.details["proc.args"] // "") == ""))]|length' 2>/dev/null)
if [ "${acc_drift_file_ev:-0}" != "0" ]; then
    acc "  " "ВНИМАНИЕ: ${acc_drift_file_ev} срабатывание(й) без proc.args — правило по-прежнему матчится на файловом событии, то есть агент крутит СТАРУЮ версию правила (правка 4f не доехала)"
fi
if [ "${acc_drift:-0}" = "0" ]; then
    acc "  " "ВНИМАНИЕ: 0 за весь аптайм при исполнившемся манифесте атак — правило ослеплено переводом на proc.args (argv[0] дропнутых бинарей манифеста, видимо, не абсолютный путь под /bin|/usr/bin), это находка №57, а не успех сужения"
else
    acc "  " "состав (кто исполнялся):"
    echo "$acc_alerts" | jq -r '.[]|select(.rule_id=="drift_new_exec_critical")|"       \(.severity)\tcomm=\(.comm)\t\(.details["proc.args"] // .details["file.path"] // "-")"' 2>/dev/null | sort | uniq -c | sort -rn | head -15
fi

# (12) 5.9.9.F.4h/№150: 0 пар «dns: no new events» / «dns: collector
# recovered» за idle-час при живом DNS-детекте. Считается по счётчику
# stale_transitions (гейт печатает его дельту за прогон, крит. 5.9.6g) — тот
# же приём, что у самого гейта: журнал построчно здесь не парсится.
acc_stale=$(grep -oE 'stale_transitions за прогон: [0-9]+' /root/gate-2.9.9.F.5.txt | tail -1 | grep -oE '[0-9]+$')
acc "12." "пар dns stale/recovered за прогон (5.9.9.F.4h/№150, порог поднят 5м -> 10м): ${acc_stale:-?}"
if [ "${acc_stale:-1}" = "0" ]; then
    acc "  " "ДОСТИГНУТО: 0 — порог выше межвсплескового интервала тихого стенда (312с наблюдённых на №2.9.9.F.3, где пар было 59)"
elif [ -z "$acc_stale" ]; then
    acc "  " "SKIP: гейт не напечатал stale_transitions — величина 12 не посчитана (не PASS)"
else
    acc "  " "НЕ ДОСТИГНУТО: ${acc_stale} — либо межвсплесковый интервал этого стенда длиннее 10 минут (тогда порог поднимается снова либо «тихо» и «слепо» разделяются двумя исходами, как предлагала постановка), либо коллектор ДЕЙСТВИТЕЛЬНО слеп: различать по крит. 2 гейта (events_total{dns} растёт между срезами или нет)"
fi
[ -f "$SETUP/attacks/dns-idle-fp.txt" ] && acc "  " "позитивный контроль DNS (5.9.8a) — исход в шаге [7/14] выше; ноль пар при КРАСНОМ контроле величиной не является"

echo "=== конец приёмки волн 5.9.9.F.3 (перенос 4i) + 5.9.9.F.4 (вердикт гейта: $GATE_RC) ==="
echo ""

echo "=== [14/14] сводка idle-части + отчёт сверх гейта ==="
cat $IDLE_OUT/SUMMARY.txt 2>/dev/null
# 5.9.9f (№104): REPORT_LABEL передаётся явно в обоих ветках — раньше
# run-2.9.5-report.sh печатал "ОТЧЁТ №2.9.5" литералом независимо от того,
# какой замер его в действительности вызвал (фолбэк использовался на
# №2.9.6…№2.9.8 тоже). REPORT_LABEL=2.9.9.F.5 чинит это для report-2.9.9.F.5.txt;
# если когда-нибудь появится собственный run-2.9.9.F.5-report.sh, ему тоже
# следует читать REPORT_LABEL, а не зашивать номер.
if [ -f "$SETUP/run-2.9.9.F.5-report.sh" ]; then
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.9.F.5.txt REPORT_LABEL=2.9.9.F.5 \
        bash $SETUP/run-2.9.9.F.5-report.sh 2>&1 | tee /root/report-2.9.9.F.5.txt
else
    echo "ВНИМАНИЕ: run-2.9.9.F.5-report.sh отсутствует — считаем отчётом (сверх гейта) фолбэком run-2.9.5-report.sh."
    echo "ВНИМАНИЕ: п.10 (idle-алерты на метках срезов) он посчитает, величины"
    echo "ВНИМАНИЕ: постановки №2.9.9.F.5 (пп.1-14) — нет; они только в гейте."
    IDLE_OUT=$IDLE_OUT AGENT_START_FILE=/root/agent-start-2.9.9.F.5.txt REPORT_LABEL=2.9.9.F.5 \
        bash $SETUP/run-2.9.5-report.sh 2>&1 | tee /root/report-2.9.9.F.5.txt
fi

echo "=== [14.1/14] наблюдение без порога: состав drift_new_exec_critical (долг «намеренно НЕ входит») ==="
# Пункт постановки замера, добавленный 2026-08-26 (см. plan.md, «Наблюдение без
# порога» в приёмке №2.9.9.F.3). drift_new_exec_critical — первое место по
# критикалам аптайма (44 на №2.9.9.F.2, больше, чем №131 и №132 вместе), и до
# сих пор он не находка только потому, что его состав никто не смотрел:
# правило дрейфа ОБЯЗАНО расти в окне атаки, и без разбора «сколько из 44
# пришло из окна атак, а сколько с фонового open() под /usr/bin» отличить
# законный рост от четвёртого экземпляра класса «правило шире своего имени»
# нечем. Шаг ничего не проверяет и НЕ влияет на вердикт: он печатает величину
# и складывает её в артефакт, чтобы волна 6 входила в разбор с числами, а не
# с «44 и первое место».
#
# Почему здесь, а не в run-gate.sh: у наблюдения нет порога, а всё, что гейт
# печатает через pass()/fail()/skip(), обязано иметь строку в
# criteria-index.txt и достижимый исход. Наблюдение без порога, заведённое
# критерием, стало бы либо вечным PASS (критерий без достижимого FAIL —
# №123/№124), либо SKIP-ом бухгалтерии (№135/№136/№137). Поэтому — шаг
# пайплайна, после гейта, на тех же снимках.
drift_out=/root/drift-composition-2.9.9.F.5.txt
{
    echo "=== состав drift_new_exec_critical за аптайм, замер №2.9.9.F.5, $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    # FP_API/FP_TOKEN заданы шагом [9.6/14] в этом же shell; перевычисляются
    # на случай, если шаг был пропущен режимом прогона.
    FP_API="${FP_API:-http://${VPS_IP:-localhost}:19090}"
    FP_TOKEN="${FP_TOKEN:-${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}}"
    drift_json=$(curl -s --max-time 30 -H "Authorization: Bearer $FP_TOKEN" "$FP_API/api/v1/alerts" 2>/dev/null \
        | jq '[.[]|select(.rule_id=="drift_new_exec_critical")]' 2>/dev/null)
    if [ -z "$drift_json" ] || [ "$drift_json" = "null" ]; then
        echo "НЕ ПОЛУЧЕНО: /api/v1/alerts не отдал массив (токен/агент/jq). Наблюдение пропущено — на вердикт не влияет."
    else
        echo "-- записей в сторе: $(echo "$drift_json" | jq 'length')"
        echo "-- срабатываний с учётом дедупликации (сумма count): $(echo "$drift_json" | jq '[.[]|(.count // 1)]|add // 0')"
        echo "-- окно: $(echo "$drift_json" | jq -r '[.[].timestamp]|sort|(first // "-")+" .. "+(last // "-")')"
        echo "-- по severity:"
        echo "$drift_json" | jq -r 'group_by(.severity)[]|"     \(length)\t\(.[0].severity)"' | sort -rn
        echo "-- по comm (кто открывал):"
        echo "$drift_json" | jq -r 'group_by(.comm)[]|"     \(length)\t\(.[0].comm)"' | sort -rn
        echo "-- по file.path (что открывалось):"
        echo "$drift_json" | jq -r 'group_by(.details["file.path"])[]|"     \(length)\t\(.[0].details["file.path"] // "-")"' | sort -rn
        echo "-- пары comm × file.path (для разметки «окно атаки» против фона):"
        echo "$drift_json" | jq -r 'group_by([.comm, .details["file.path"]])[]|"     \(length)\t\(.[0].comm)\t\(.[0].details["file.path"] // "-")"' | sort -rn
        echo ""
        echo "КАК ЧИТАТЬ (postanovka 2026-08-26). Строки, чей comm — шаг манифеста атак"
        echo "(curl/wget/python3/nc/dropper из run-all-attacks.sh), — законный рост правила"
        echo "дрейфа в окне атаки. Строки, чей comm — фоновый демон стенда, а file.path —"
        echo "штатная утилита (/usr/bin/dpkg, /usr/bin/find, /usr/bin/mandb и т.п.), — тот же"
        echo "класс, что №131/№132: правило шире своего имени. Разметка и решение —"
        echo "волна 6, не этот замер. Порог здесь НЕ назначается (запрет 5.9.6)."
    fi
} 2>&1 | tee "$drift_out"
echo "  наблюдение сложено в $drift_out (собирается вместе с /root/report-2.9.9.F.5.txt)"

echo "=== ПАЙПЛАЙН №2.9.9.F.5 ЗАВЕРШЁН $(date -u +%H:%M:%S) UTC, гейт=$GATE_RC ==="
touch /root/PIPELINE-2.9.9.F.5-DONE
