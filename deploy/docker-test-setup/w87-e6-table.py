#!/usr/bin/env python3
"""w87-e6-table.py <OUT> — заход Е6 волны 8.7: таблица ступенчатого нагрузочного смока (w87-e6-load.sh).

По каждой ступени (окно a→b — сама ступень, b→c — слив после неё):
  поданные операции генератора и его CPU; события агента в секунду по типам; события на операцию сверх фона
  (фон — ступень 0); потери по причинам (events_dropped_total, event_queue_dropped_total); возраст события при
  взятии воркером p50/p99 по классам (гистограмма ingest_event_age_seconds, дельта бакетов); CPU агента (ядер и
  мкс на событие); CPU хоста; RSS и heap_inuse на конце ступени; алерты за ступень; слив: события и потери за паузу.
Вердиктов не даёт. Режим attack печатает те же величины по окну пакета.
"""
import json
import os
import re
import sys

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LAB = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def prom(path):
    out = []
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return out
    for ln in f:
        if ln.startswith("#"):
            continue
        m = LINE.match(ln)
        if not m:
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue
        out.append((m.group(1), dict(LAB.findall(m.group(2) or "")), v))
    return out


def ssum(rows, name, **flt):
    return sum(v for n, l, v in rows if n == name and all(l.get(k) == x for k, x in flt.items()))


def group(rows, name, key):
    d = {}
    for n, l, v in rows:
        if n == name:
            d[l.get(key, "")] = d.get(l.get(key, ""), 0) + v
    return d


def rd(path, conv=float):
    try:
        return conv(open(path).read().split()[0])
    except (OSError, IndexError, ValueError):
        return None


def cpu_busy(path):
    try:
        f = [int(x) for x in open(path).read().split()[1:]]
    except (OSError, ValueError):
        return None
    idle = f[3] + f[4]
    return sum(f), idle


def quant(a, b, cls, q):
    """квантиль возраста из дельты бакетов гистограммы; верхняя граница бакета."""
    def buckets(rows):
        d = {}
        for n, l, v in rows:
            if n == "ebpf_guard_ingest_event_age_seconds_bucket" and l.get("class") == cls:
                d[l["le"]] = v
        return d
    ba, bb = buckets(a), buckets(b)
    les = sorted(bb, key=lambda x: float("inf") if x == "+Inf" else float(x))
    tot = bb.get("+Inf", 0) - ba.get("+Inf", 0)
    if tot <= 0:
        return None, 0
    for le in les:
        if bb[le] - ba.get(le, 0) >= q * tot:
            return le, tot
    return "+Inf", tot


def fmt_le(le):
    if le is None:
        return "—"
    if le == "+Inf":
        return ">10с"
    x = float(le)
    return "≤%gмс" % (x * 1000) if x < 1 else "≤%gс" % x


def window(d, t0, t1):
    a, b = prom(f"{d}/{t0}.prom"), prom(f"{d}/{t1}.prom")
    ta, tb = rd(f"{d}/{t0}.t"), rd(f"{d}/{t1}.t")
    if not a or not b or ta is None or tb is None:
        return None
    dt = tb - ta
    r = {"dt": dt}
    ea, eb = group(a, "ebpf_guard_events_total", "type"), group(b, "ebpf_guard_events_total", "type")
    r["ev"] = {k: (eb.get(k, 0) - ea.get(k, 0)) / dt for k in eb}
    r["ev_total"] = sum(eb.values()) - sum(ea.values())
    da, db = {}, {}
    for n, l, v in a:
        if n == "ebpf_guard_events_dropped_total":
            da[(l.get("collector"), l.get("reason"))] = v
    for n, l, v in b:
        if n == "ebpf_guard_events_dropped_total":
            db[(l.get("collector"), l.get("reason"))] = v
    r["drops"] = {k: db[k] - da.get(k, 0) for k in db if db[k] - da.get(k, 0) > 0}
    r["qdrop"] = ssum(b, "ebpf_guard_event_queue_dropped_total") - ssum(a, "ebpf_guard_event_queue_dropped_total")
    r["qdrop_by"] = ssum(b, "ebpf_guard_events_dropped_by_queue_total") - ssum(a, "ebpf_guard_events_dropped_by_queue_total")
    r["qdepth"] = ssum(b, "ebpf_guard_event_queue_depth")
    r["qfill"] = ssum(b, "ebpf_guard_event_queue_fill_ratio")
    r["alerts"] = ssum(b, "ebpf_guard_alerts_total") - ssum(a, "ebpf_guard_alerts_total")
    for cls in ("protected", "bulk"):
        r[f"p50_{cls}"], r[f"n_{cls}"] = quant(a, b, cls, 0.5)
        r[f"p99_{cls}"], _ = quant(a, b, cls, 0.99)
    k0, k1 = rd(f"{d}/{t0}.ticks"), rd(f"{d}/{t1}.ticks")
    r["cores"] = (k1 - k0) / 100 / dt if k0 is not None and k1 is not None else None
    r["us_ev"] = (k1 - k0) * 1e4 / r["ev_total"] if r["cores"] is not None and r["ev_total"] > 0 else None
    c0, c1 = cpu_busy(f"{d}/{t0}.cpu"), cpu_busy(f"{d}/{t1}.cpu")
    if c0 and c1:
        tot, idle = c1[0] - c0[0], c1[1] - c0[1]
        r["host_busy"] = 100 * (tot - idle) / tot if tot else None
    # горячий шард: секунды ожидания диспетчера на канале воркера (pid & mask) за окно, по воркерам; пик очередей
    ba = {(l.get("class"), l.get("worker")): v for n, l, v in a if n == "ebpf_guard_ingest_worker_blocked_seconds_total"}
    r["blocked"] = {}
    for n, l, v in b:
        if n == "ebpf_guard_ingest_worker_blocked_seconds_total":
            k = (l.get("class"), l.get("worker"))
            if v - ba.get(k, 0) > 0.001:
                r["blocked"][k] = v - ba.get(k, 0)
    cap = {l.get("queue"): v for n, l, v in b if n == "ebpf_guard_queue_capacity"}
    r["hwm"] = {l.get("queue"): (v, cap.get(l.get("queue"))) for n, l, v in b if n == "ebpf_guard_queue_depth_hwm"}
    r["rss"] = (rd(f"{d}/{t1}.rss") or 0) / 1024
    r["heap"] = ssum(b, "go_memstats_heap_inuse_bytes") / 1048576
    return r


def gen(d):
    """итог генератора: gen.json (один процесс, ранние прогоны) или сумма gen.json.<p> по процессам."""
    import glob
    files = sorted(f for f in glob.glob(f"{d}/gen.json*") if not f.endswith(".err"))
    gs = []
    for f in files:
        try:
            gs.append(json.load(open(f)))
        except (OSError, ValueError):
            pass
    if not gs:
        return None
    t = {"procs": len(gs), "elapsed_s": max(g["elapsed_s"] for g in gs), "ops": {}, "errors": {}}
    for k in ("ops_total", "cpu_self_s", "cpu_children_s"):
        t[k] = sum(g[k] for g in gs)
    for k in ("ops", "errors"):
        for g in gs:
            for op, v in g[k].items():
                t[k][op] = t[k].get(op, 0) + v
    t["ops_per_s"] = t["ops_total"] / t["elapsed_s"]
    return t


def stages(d):
    """доли стадий из cpu.pprof — через w87-e1-table.sh (go tool pprof)."""
    p = f"{d}/cpu.pprof"
    if not os.path.exists(p) or os.path.getsize(p) < 200:
        return None
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.popen(f"bash {here}/w87-e1-table.sh - x {p} 2>/dev/null").read()
    st = {}
    for ln in out.splitlines():
        m = re.match(r"^(\S+(?: \S+)?)\s+([0-9.]+) с\s+([0-9.]+)%", ln)
        if m:
            st[m.group(1)] = float(m.group(3))
    return st


GROUPS = [
    ("правила", ["rules"]),
    ("коллектор", ["collector", "collector_route"]),
    ("роутер", ["router_enrich", "router_metrics", "router_ingest", "router_loop", "router_drift", "router_log"]),
    ("воркер", ["anomaly", "ingest_loop", "ingest_pre", "ingest_post"]),
    ("алерт", ["rego", "rego_loop", "incident", "pending_flush", "dispatch_metrics", "dispatch_agg", "dispatch_enforce",
               "dispatch_store", "dispatch_alertmanager", "dispatch_notify", "dispatch_gossip", "enforcer"]),
    ("http", ["http_api", "http_metrics"]),
    ("без метки", ["(без метки)"]),
]


def main():
    out = sys.argv[1]
    steps = sorted(x for x in os.listdir(out) if x.startswith("step-"))
    meta = open(f"{out}/driver.log", encoding="utf-8", errors="replace").readline().strip() if os.path.exists(f"{out}/driver.log") else ""
    print(f"# {out}\n# {meta}\n")
    rows = []
    for s in steps:
        d = f"{out}/{s}"
        rows.append((s.split("-", 2)[2], d, window(d, "a", "b"), window(d, "b", "c"), gen(d)))
    bg = None
    for name, d, w, wc, g in rows:
        if name == "0" and w:
            bg = w["ev_total"] / w["dt"]
    print("| ступень | ops/s подано | CPU ген., ядер | событий/с подано (обработ.+потери) | событий/с обработано | file | syscall | network | соб./оп. сверх фона | "
          "потери (окно) | p50/p99 protected | p50/p99 bulk | CPU агента, ядер | мкс/соб. | CPU хоста | RSS МиБ | heap МиБ | алерты | слив: соб./потери/очередь |")
    print("|" + "---|" * 19)
    for name, d, w, wc, g in rows:
        if not w:
            print(f"| {name} | нет срезов |")
            continue
        ops = g["ops_per_s"] if g else 0
        gcpu = (g["cpu_self_s"] + g["cpu_children_s"]) / g["elapsed_s"] if g else 0
        evs = w["ev_total"] / w["dt"]
        epo = (evs - bg) / ops if g and bg is not None and ops > 0 else None
        losses = sum(w["drops"].values()) + w["qdrop"]
        drain = f"{wc['ev_total'] / wc['dt']:.0f}/с / {sum(wc['drops'].values()) + wc['qdrop']:.0f} / {wc['qdepth']:.0f}" if wc else "—"
        print(f"| {name} | {ops:,.0f} | {gcpu:.2f} | {evs + losses / w['dt']:,.0f} | {evs:,.0f} | {w['ev'].get('file', 0):,.0f} | {w['ev'].get('syscall', 0):,.0f} | "
              f"{w['ev'].get('network', 0):,.0f} | {'—' if epo is None else f'{epo:.2f}'} | {losses:,.0f} | "
              f"{fmt_le(w['p50_protected'])} / {fmt_le(w['p99_protected'])} | {fmt_le(w['p50_bulk'])} / {fmt_le(w['p99_bulk'])} | "
              f"{w['cores']:.2f} | {w['us_ev']:.1f} | {w.get('host_busy', 0):.0f}% | {w['rss']:.0f} | {w['heap']:.0f} | {w['alerts']:.0f} | {drain} |"
              .replace(",", " "))
    print("\nПотери по причинам (окно ступени), только ненулевые:")
    for name, d, w, wc, g in rows:
        if w and (w["drops"] or w["qdrop"]):
            parts = [f"{c}/{r}={v:.0f}" for (c, r), v in sorted(w["drops"].items())]
            if w["qdrop"]:
                parts.append(f"event_queue_dropped={w['qdrop']:.0f}")
            print(f"  {name}: " + ", ".join(parts))
    print("\nГорячий шард: ожидание диспетчера на канале воркера (с за окно ступени) и пик очередей (заполн./ёмкость):")
    for name, d, w, wc, g in rows:
        if not w:
            continue
        bl = ", ".join(f"{c}/w{wk}={v:.1f}с" for (c, wk), v in sorted(w["blocked"].items())) or "нет"
        hw = ", ".join(f"{q}={v:.0f}/{c:.0f}" for q, (v, c) in sorted(w["hwm"].items()) if c and v >= 0.5 * c) or "все < 50%"
        print(f"  {name}: блок {bl}; очереди ≥50%: {hw}")
    print("\nОперации генератора (на ступень) и ошибки:")
    for name, d, w, wc, g in rows:
        if g:
            print(f"  {name}: ops={g['ops']} errors={ {k: v for k, v in g['errors'].items() if v} } elapsed={g['elapsed_s']:.1f}s")
    print("\nCPU по стадиям (профиль 30 с в середине ступени), % всех сэмплов:")
    print("| ступень | " + " | ".join(gname for gname, _ in GROUPS) + " | топ-3 стадии |")
    print("|" + "---|" * (len(GROUPS) + 2))
    for name, d, w, wc, g in rows:
        st = stages(d)
        if not st:
            print(f"| {name} | профиля нет |")
            continue
        cells = [f"{sum(st.get(x, 0) for x in xs):.1f}" for _, xs in GROUPS]
        top = sorted(((v, k) for k, v in st.items() if k != "(без метки)"), reverse=True)[:3]
        print(f"| {name} | " + " | ".join(cells) + " | " + ", ".join(f"{k} {v:.1f}" for v, k in top) + " |")
    if os.path.isdir(f"{out}/attack"):
        d = f"{out}/attack"
        w, g = window(d, "g", "b"), gen(d)
        print("\nПакет атак под нагрузкой (окно пакета):")
        if w:
            print(f"  подано {g['ops_per_s']:,.0f} ops/s; событий {w['ev_total'] / w['dt']:,.0f}/с; потери "
                  f"{sum(w['drops'].values()) + w['qdrop']:.0f} {dict((f'{c}/{r}', v) for (c, r), v in w['drops'].items())}; "
                  f"CPU агента {w['cores']:.2f} ядра, {w['us_ev']:.1f} мкс/соб.; p99 protected {fmt_le(w['p99_protected'])}; алерты {w['alerts']:.0f}"
                  .replace(",", " ") if g else "")
        try:
            print("  " + open(f"{d}/recall.txt").read().strip())
        except OSError:
            print("  recall: нет файла")


if __name__ == "__main__":
    main()
