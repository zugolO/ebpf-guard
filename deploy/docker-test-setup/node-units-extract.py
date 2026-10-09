#!/usr/bin/env python3
"""node-units-extract.py — старты юнитов systemd ноды из журнала PID 1 (№549, 3.P1-19).

Вход (stdin): `journalctl _PID=1 -o json --since … --until …`.
Выход (stdout): TSV `start_epoch<TAB>end_epoch<TAB>unit`, по строке на запуск.

Событие юнита начинается первым сообщением задания (Starting… или, если его нет,
Started — так пишутся scope сессий) и кончается завершением задания старта:
у oneshot это Finished (после деактивации), у демона — Started. Хвост демона
(fwupd.service в ночь H2 висел 2 ч до выхода по простою) событием не считается:
работа демона после старта приходит от клиента, у которого свой юнит
(fwupd-refresh). Деактивация или отказ до завершения задания тоже закрывают
событие. Сообщения закрытого события (Finished после Deactivated у oneshot)
второго события не открывают — первая версия печатала каждый oneshot дважды.

Ничего не фильтруется по имени, кроме самого агента: незнакомый юнит в часе
делает час НЕ фоновым — это осторожная сторона для величины «объём фоновых часов» ([[gate-unit-replaced-by-price-per-node-event]]).

Свой рестарт агента исключён: его цена — прогрев, а не событие ноды.
"""
import json
import sys

STARTING = "7d4958e842da4a758f6c1cdc7b36dcc5"   # Starting <unit>…
JOB_DONE = "39f53479d3a045ac8e11786248231fbf"   # Started/Finished <unit>
DEACT = "7ad2d189f7e94e70a38c781354912448"      # <unit>: Deactivated successfully
FAILED = "be02cf6855d2428ba40df7e9d022f03d"     # <unit>: Failed with result …
SELF_PREFIX = ("ebpf-guard",)
TAIL_S = 10                                       # хвост закрытого события, с


def main() -> int:
    open_ev = {}   # unit -> start
    closed = {}    # unit -> время закрытия последнего события
    out = []
    bad = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except ValueError:
            bad += 1
            continue
        mid = j.get("MESSAGE_ID")
        unit = j.get("UNIT")
        if not unit or mid not in (STARTING, JOB_DONE, DEACT, FAILED):
            continue
        if unit.startswith(SELF_PREFIX):
            continue
        try:
            t = int(j["__REALTIME_TIMESTAMP"]) / 1e6
        except (KeyError, ValueError):
            bad += 1
            continue
        if mid == STARTING:
            if unit in open_ev:          # повторный Starting без завершения
                out.append((open_ev[unit], t, unit))
            open_ev[unit] = t
        elif unit in open_ev:            # JOB_DONE / DEACT / FAILED закрывают
            out.append((open_ev.pop(unit), t, unit))
            closed[unit] = t
        elif mid == JOB_DONE and t - closed.get(unit, -1e18) > TAIL_S:
            out.append((t, t, unit))     # scope сессии: только Started
            closed[unit] = t
    for unit, s in open_ev.items():
        out.append((s, s, unit))
    for s, e, u in sorted(out):
        print(f"{s:.0f}\t{e:.0f}\t{u}")
    if bad:
        print(f"node-units-extract: нечитаемых строк журнала {bad}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
