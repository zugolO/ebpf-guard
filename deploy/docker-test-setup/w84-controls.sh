#!/bin/bash
# w84-controls.sh <OUT> — контроли 8.4.2: легитимная остановка из maintainer-скрипта под dpkg (алерта НЕТ) и
# спуфы (алерт ЕСТЬ) против impact_systemd_service_disabled. Работает против ЛЮБОГО агента: API/TOKEN.
#   API (умолч. http://localhost:19090), TOKEN, W84_APT_PKG (пакет для apt-get-сценария, умолч. irqbalance).
# По сценарию — каталог OUT/NN-имя/: expect (silent|alert), alerts.json (алерты окна), m0.txt/m1.txt (метрики),
# witness.txt (bpftrace: systemctl с родословной ЯДРА — класс предъявлен), note. Вердикт — w84-close-report.sh.
# Рабочий агент и пакеты стенда не трогаются, кроме тестового пакета w84svc и (apt-сценарий) переустановки W84_APT_PKG.
set -u
OUT=${1:?usage: w84-controls.sh <OUT>}
API=${API:-http://localhost:19090}; TOKEN=${TOKEN:?TOKEN}
HERE=$(cd "$(dirname "$0")" && pwd)
APTPKG=${W84_APT_PKG:-irqbalance}
W=/var/tmp/w84; WIN=${W84_SETTLE:-10}
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
A() { curl -s --max-time 60 -H "Authorization: Bearer $TOKEN" "$API/api/v1/alerts?since=$1s&limit=20000"; }
rm -rf "$OUT" "$W"; mkdir -p "$OUT" "$W"
exec > "$OUT/driver.log" 2>&1
echo "[$(date -u +%FT%TZ)] w84-controls: API=$API"
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
command -v bpftrace > /dev/null || die "нет bpftrace — свидетель родословной недоступен"
[ -x /usr/bin/deb-systemd-invoke ] || die "нет /usr/bin/deb-systemd-invoke"

# тестовый пакет: сервис + postinst start / prerm stop через deb-systemd-invoke (как у настоящих пакетов)
mkpkg() {
    local d=$W/pkg; rm -rf "$d"; mkdir -p "$d/DEBIAN" "$d/lib/systemd/system"
    printf '[Unit]\nDescription=w84 test service\n[Service]\nExecStart=/bin/sleep 100000\n[Install]\nWantedBy=multi-user.target\n' > "$d/lib/systemd/system/w84svc.service"
    printf 'Package: w84svc\nVersion: 1\nArchitecture: all\nMaintainer: w84 <w84@localhost>\nDescription: w84 test package\n' > "$d/DEBIAN/control"
    printf '#!/bin/sh\nset -e\nsystemctl daemon-reload >/dev/null 2>&1 || true\ndeb-systemd-invoke start w84svc.service >/dev/null 2>&1 || true\nexit 0\n' > "$d/DEBIAN/postinst"
    printf '#!/bin/sh\nset -e\ndeb-systemd-invoke stop w84svc.service >/dev/null 2>&1 || true\nexit 0\n' > "$d/DEBIAN/prerm"
    chmod 0755 "$d/DEBIAN/postinst" "$d/DEBIAN/prerm"
    dpkg-deb --build "$d" "$W/w84svc.deb" > /dev/null
}
mkpkg || die "не собран тестовый пакет"
cleanup() { dpkg -r w84svc > /dev/null 2>&1; dpkg -P w84svc > /dev/null 2>&1; rm -f /var/lib/dpkg/info/w84x.prerm; systemctl reset-failed w84svc.service > /dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
start_svc() { systemd-run --quiet --unit=w84svc-run /bin/sleep 100000 > /dev/null 2>&1; }

# bpftrace гасится SIGINT (штатный выход с печатью карт) и добивается -9 через 5 с: на одном из прогонов SIGTERM
# оставил его висеть в ep_poll, а «wait» держал весь контроль 19 минут.
stop_bt() {
    local p=$1 i
    kill -INT "$p" 2> /dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$p" 2> /dev/null || break; sleep 0.5; done
    kill -9 "$p" 2> /dev/null
    wait "$p" 2> /dev/null
    return 0
}

N=0
# scenario <имя> <silent|alert> <заметка> <команда…> — окно: свидетель → команда → пауза → алерты и метрики
scenario() {
    local name=$1 expect=$2 note=$3; shift 3
    N=$((N + 1)); local D; D=$OUT/$(printf '%02d' $N)-$name; mkdir -p "$D"
    echo "$expect" > "$D/expect"; echo "$note" > "$D/note"
    bpftrace "$HERE/w84-chain-witness.bt" > "$D/witness.txt" 2>&1 &
    local BT=$!
    # «Attaching N probe» bpftrace печатает после компиляции (холодный первый сценарий — разбор BTF дольше 3 с: репетиция
    # ночи 9 — 0 systemctl у dpkg -r при живом prerm); ждём строку, затем 2 с на подключение пробы
    local k; for k in $(seq 1 60); do grep -q '^Attaching' "$D/witness.txt" 2> /dev/null && break; sleep 0.5; done
    sleep 2
    M > "$D/m0.txt"; local t0; t0=$(date +%s); echo "$t0" > "$D/t0"
    ( "$@" ) > "$D/cmd.log" 2>&1; echo "rc=$?" >> "$D/cmd.log"
    sleep "$WIN"
    M > "$D/m1.txt"
    # снимок берётся с запасом 5 с назад, а эмиттер отбрасывает алерты старше t0: чужие systemctl до окна (уборка
    # прошлого сценария, пробы смока) в сценарий не входят
    A $(( $(date +%s) - t0 + 5 )) > "$D/alerts.json"
    stop_bt "$BT"
    echo "[$(date -u +%T)] $D: $(grep -c '^SYSTEMCTL' "$D/witness.txt") systemctl в окне, expect=$expect"
}

# L1: dpkg -r → prerm → deb-systemd-invoke stop (настоящая остановка, сервис запущен postinst'ом)
dpkg -i "$W/w84svc.deb" > "$OUT/install.log" 2>&1 || die "dpkg -i тестового пакета: $(tail -3 "$OUT/install.log")"
systemctl is-active w84svc.service > /dev/null 2>&1 || { systemctl start w84svc.service > /dev/null 2>&1; }
systemctl is-active w84svc.service > /dev/null 2>&1 || die "сервис w84svc не запустился — остановка не будет настоящей"
scenario L1-dpkg-remove silent "dpkg -r пакета с prerm → deb-systemd-invoke stop" sh -c 'dpkg -r w84svc; echo "dpkg -r rc=$?"'

# L2: apt-get install пакета с сервисом (prerm у существующего пакета) — без ложных
if dpkg -s "$APTPKG" > /dev/null 2>&1; then
    scenario L2-apt-reinstall silent "dpkg -r $APTPKG && apt-get install $APTPKG" sh -c "dpkg -r $APTPKG; apt-get install -y $APTPKG"
else
    N=$((N + 1)); D=$OUT/$(printf '%02d' $N)-L2-apt-reinstall; mkdir -p "$D"; echo "skip" > "$D/expect"; echo "пакет $APTPKG не установлен — сценарий не исполнен" > "$D/note"
fi
dpkg -i "$W/w84svc.deb" > /dev/null 2>&1; systemctl start w84svc.service > /dev/null 2>&1

# X1: dpkg --pre-invoke='systemctl stop …' — dpkg выше, но maintainer-скрипта между ним и systemctl нет
scenario X1-pre-invoke alert "dpkg --pre-invoke='systemctl stop w84svc'" sh -c "dpkg --pre-invoke='systemctl stop w84svc.service' -i $W/w84svc.deb"
systemctl start w84svc.service > /dev/null 2>&1

# X2: копия perl-скрипта deb-systemd-invoke вне /usr/bin — прямой запуск и под dpkg --pre-invoke
cp /usr/bin/deb-systemd-invoke "$W/deb-systemd-invoke"
scenario X2-copy-perl-script alert "копия deb-systemd-invoke вне /usr/bin: прямой запуск и под dpkg --pre-invoke" \
    sh -c "$W/deb-systemd-invoke stop w84svc.service; systemctl start w84svc.service; dpkg --pre-invoke='$W/deb-systemd-invoke stop w84svc.service' -i $W/w84svc.deb"
systemctl start w84svc.service > /dev/null 2>&1

# X3: скрипт *.prerm вне /var/lib/dpkg/info под dpkg --pre-invoke
printf '#!/bin/sh\nsystemctl stop w84svc.service\n' > "$W/x.prerm"; chmod 0755 "$W/x.prerm"
scenario X3-prerm-outside-info alert "dpkg --pre-invoke=$W/x.prerm (скрипт вне /var/lib/dpkg/info)" sh -c "dpkg --pre-invoke=$W/x.prerm -i $W/w84svc.deb"
systemctl start w84svc.service > /dev/null 2>&1

# X4: подделка имени dpkg: exec -a dpkg и prctl(PR_SET_NAME); скрипт — в maintainer-формы имени, но вне info
printf '#!/bin/sh\nsystemctl stop w84svc.service\n' > "$W/pkg.prerm"; chmod 0755 "$W/pkg.prerm"
scenario X4-name-spoof alert "exec -a dpkg и prctl(PR_SET_NAME=dpkg) над скриптом pkg.prerm вне info" \
    sh -c "bash -c 'exec -a dpkg $W/pkg.prerm'; systemctl start w84svc.service; python3 -c 'import ctypes,os; ctypes.CDLL(None).prctl(15,b\"dpkg\",0,0,0); os.system(\"$W/pkg.prerm\")'"
systemctl start w84svc.service > /dev/null 2>&1

# X5: реюз pid родителя: настоящий путь /var/lib/dpkg/info/*.prerm, но предок pid занят позже другим процессом (dpkg)
cp "$W/pkg.prerm" /var/lib/dpkg/info/w84x.prerm
scenario X5-pid-reuse alert "pid родителя переиспользован процессом /usr/bin/dpkg (ns_last_pid) — цепочка рвётся" python3 "$HERE/w84-pidreuse.py" /var/lib/dpkg/info/w84x.prerm
rm -f /var/lib/dpkg/info/w84x.prerm

echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
