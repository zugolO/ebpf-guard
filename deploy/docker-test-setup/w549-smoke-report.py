#!/usr/bin/env python3
"""Отчёт смока w549-smoke.sh (№549 (б)/(в), 09.10.2026).

Usage: w549-smoke-report.py <OUT dir fetched from the stand>

F — fwupd-refresh форсированно: исполнилось ли событие (холодный старт демона
    внутри окна E), семь read-only правил по трём слоям E − C, подавления
    fwupd-hardware-probe, вердикт инцидентов дерева fwupd. Инциденты с корнем
    измерителя (sh/systemctl/systemd-run/systemd форсирования) печатаются
    отдельно и в вердикт события не входят.
P — копия cat под именем fwupd: три правила обязаны сработать.
A — apt-daily натурально: штамп сдвинут и после окна новее его начала, корни
    дерева apt-get/gpgv/apt-key есть в журнале exec свидетеля; цена по правилам;
    пути записи в /tmp по образам (свидетель bpftrace) — вход решения об оси.
Все вердикты выносятся по содержимому окна, не по метке фазы.
"""
import importlib.util
import json
import os
import re
import sys

_spec = importlib.util.spec_from_file_location(
    'w549price', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'w549-node-price-report.py'))
_p = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_p)
load, per_rule, total, alerts, ts, LAYERS = _p.load, _p.per_rule, _p.total, _p.alerts, _p.ts, _p.LAYERS

RECON7 = ['container_escape_kmem_access', 'sigma_dev_mem_access', 'rootkit_kcore_access',
          'rootkit_proc_modules_read', 'mitre_vm_detect_dmi_read', 'sigma_kernel_version_read',
          'sigma_cpu_info_access']
FWUPD_TREE = re.compile(r'^\(?(fwupd|fwupdmgr|gmain|gdbus|pool-fwupd|pool-fwupdmgr|GUsbEventThread)\)?$')
APT_TREE = re.compile(r'^\(?(apt\.systemd\.dai|apt-helper|apt-get|apt-config|http|https|gpgv|apt-key|store|'
                      r'mirror|cp|gpgconf|gpg|python3|apt-esm-hook|esm-cache|apt-news|ubuntu-advantage)\)?$')
MEASURER = re.compile(r'^\(?(sh|bash|systemctl|systemd-run|systemd)\)?$')
P_RULES = ['mitre_vm_detect_dmi_read', 'rootkit_proc_modules_read', 'sigma_kernel_version_read']
FAIL = []


def rd(d, f, default=''):
    try:
        return open(os.path.join(d, f)).read().strip()
    except OSError:
        return default


def layers(d, a0, a1, b0, b1):
    """{rule: {layer: E − C}} по трём слоям."""
    c0, c1, e0, e1 = (load(os.path.join(d, f)) for f in (a0, a1, b0, b1))
    rows = {}
    for layer, name in LAYERS:
        c, e = per_rule(c0, c1, name), per_rule(e0, e1, name)
        for rid in set(c) | set(e):
            rows.setdefault(rid, {})[layer] = int(e.get(rid, 0) - c.get(rid, 0))
    return rows, (c0, c1, e0, e1)


def exc_delta(m0, m1, name):
    out = {}
    for (n, l), v in m1.items():
        if n != 'ebpf_guard_rule_exceptions_total':
            continue
        dl = dict(l)
        if dl.get('exception_name') != name:
            continue
        d = int(v - m0.get((n, l), 0.0))
        if d:
            out[dl.get('rule_id')] = out.get(dl.get('rule_id'), 0) + d
    return out


def root_comm(a):
    pt = a.get('process_tree') or []
    return pt[0].get('comm') if pt else (a.get('comm') or '')


def incidents_in(d, t0, t1):
    return [i for i in alerts(os.path.join(d, 'incidents.json'))
            if t0 <= ts(i.get('first_seen') or '1970-01-01T00:00:00Z') <= t1 + 1]


def print_incidents(inc, own_re, label):
    own, meas, other = [], [], []
    for i in inc:
        rc = i.get('root_comm') or ''
        unit = i.get('root_unit') or ''
        if own_re.match(rc) or any(own_re.match(c or '') for c in (i.get('process_chain') or [])[:1]):
            own.append(i)
        elif MEASURER.match(rc) and (unit.startswith('session-') or unit.startswith('w549s-force') or unit == ''):
            meas.append(i)
        else:
            other.append(i)
    for name, lst in ((f'дерево {label}', own), ('измеритель (вне вердикта события)', meas), ('прочие', other)):
        print(f'  инциденты — {name}: {len(lst)}')
        for i in lst:
            print(f'    {i.get("first_seen", "")[11:19]} verdict={i.get("verdict")} score={round(i.get("score") or 0, 1)} '
                  f'корень={i.get("root_comm")} unit={i.get("root_unit")} rules={sorted(set(i.get("rule_ids") or []))}')
    return own


def phase_f(d):
    print('\n=== F: fwupd-refresh форсированно ===')
    tE0, tE1 = int(rd(d, 'tE0')), int(rd(d, 'tE1'))
    unit = rd(d, 'fwupd-unit.txt')
    print('  ' + unit.replace('\n', '\n  '))
    print(f'  образ демона: {rd(d, "fwupd-exe.txt", "не снят")}')
    m = re.search(r'ExecMainStartTimestamp=\S+ (\S+ \S+)', unit)
    rows, (c0, c1, e0, e1) = layers(d, 'mC0.txt', 'mC1.txt', 'mE0.txt', 'mE1.txt')
    al = [a for a in alerts(os.path.join(d, 'alerts-CE.json')) if tE0 <= ts(a['timestamp']) <= tE1 + 1]
    tree = [a for a in al if FWUPD_TREE.match(root_comm(a)) or FWUPD_TREE.match(a.get('comm') or '')]
    executed = len(tree) > 0
    print(f'  событие исполнилось: {"ДА" if executed else "НЕТ"} (алертов дерева fwupd в окне E: {len(tree)}; старт демона {m.group(1) if m else "?"})')
    if not executed:
        FAIL.append('F: событие не исполнилось — вердикт по исключению невозможен')
    exc = exc_delta(e0, e1, 'fwupd-hardware-probe')
    print('  семь read-only правил, E − C (выпущено/дедуп/лимитер), подавлено fwupd-hardware-probe в E:')
    bad = 0
    for r in RECON7:
        v = rows.get(r, {})
        s = sum(v.values())
        in_tree = sum(1 for a in tree if a['rule_id'] == r)
        print(f'    {r:34s} {v.get("emitted", 0):+4d}/{v.get("dedup", 0):+4d}/{v.get("limiter", 0):+4d}  в дереве fwupd {in_tree}  подавлено {exc.get(r, 0)}')
        bad += in_tree
    if bad:
        FAIL.append(f'F: семь правил дали {bad} алертов в дереве fwupd')
    if sum(exc.values()) == 0:
        FAIL.append('F: fwupd-hardware-probe не подавил ничего — исключение не проверено живьём')
    by_rule = {}
    for a in tree:
        by_rule[a['rule_id']] = by_rule.get(a['rule_id'], 0) + 1
    print(f'  цена дерева fwupd (выпущено в сторе): {len(tree)} — ' + ', '.join(f'{k} {v}' for k, v in sorted(by_rule.items(), key=lambda kv: -kv[1])))
    own = print_incidents(incidents_in(d, tE0, tE1), FWUPD_TREE, 'fwupd')
    att = [i for i in own if i.get('verdict') == 'attack']
    if att:
        FAIL.append(f'F: инцидент дерева fwupd attack ({len(att)})')
    print(f'  ИТОГ F: {"OK" if executed and not bad and not att and sum(exc.values()) else "FAIL"}')


def phase_p(d):
    print('\n=== P: копия cat под именем fwupd из /var/tmp ===')
    print('  ' + rd(d, 'reads.txt').replace('\n', '\n  '))
    t0, t1 = int(rd(d, 't0')), int(rd(d, 't1'))
    m0, m1 = load(os.path.join(d, 'm0.txt')), load(os.path.join(d, 'm1.txt'))
    al = [a for a in alerts(os.path.join(d, 'alerts.json')) if t0 <= ts(a['timestamp']) <= t1 + 1 and (a.get('comm') == 'fwupd')]
    ok = True
    for r in P_RULES:
        lay = sum(per_rule(m0, m1, name).get(r, 0) for _, name in LAYERS)
        st = sum(1 for a in al if a['rule_id'] == r)
        print(f'    {r:34s} три слоя {int(lay):+d}  в сторе comm=fwupd {st}')
        ok &= lay > 0
    exc = exc_delta(m0, m1, 'fwupd-hardware-probe')
    print(f'  подавлено fwupd-hardware-probe за P: {sum(exc.values())} (обязано быть 0)')
    ok &= sum(exc.values()) == 0
    if not ok:
        FAIL.append('P: спуф-контроль не сработал на всех трёх правилах или получил исключение')
    print(f'  ИТОГ P: {"OK" if ok else "FAIL"}')


def phase_a(d):
    print('\n=== A: apt-daily натурально (штамп сдвинут) ===')
    tE0, tE1 = int(rd(d, 'tE0')), int(rd(d, 'tE1'))
    before = dict(l.split() for l in rd(d, 'stamps-before.txt').splitlines() if l.strip())
    after = dict(l.split() for l in rd(d, 'stamps-after.txt').splitlines() if l.strip())
    restored = dict(l.split() for l in rd(d, 'stamps-restored.txt').splitlines() if l.strip())
    orig = dict(l.split() for l in rd(os.path.dirname(d), 'stamps-orig.txt').splitlines() if l.strip())
    for s in sorted(after):
        print(f'  {s}: до окна {before.get(s)} после {after.get(s)} (окно E с {tE0}) возвращён {restored.get(s)} (исходный {orig.get(s)})')
    upd = '/var/lib/apt/periodic/update-stamp'
    stamp_moved = int(after.get(upd, 0)) >= tE0
    execs = [l.split(None, 3) for l in rd(d, 'bpf.txt').splitlines() if l.startswith('X ')]
    exe_paths = {}
    for x in execs:
        if len(x) == 4:
            exe_paths[x[3]] = exe_paths.get(x[3], 0) + 1
    want = {k: [p for p in exe_paths if p.endswith(k)] for k in ('/apt-get', '/gpgv', '/apt-key')}
    roots_ok = all(want.values())
    print(f'  штамп update сдвинут событием: {"ДА" if stamp_moved else "НЕТ"}; exec свидетеля: ' +
          ', '.join(f'{k} → {sorted(v) or "НЕТ"}' for k, v in want.items()))
    executed = stamp_moved and roots_ok
    print(f'  событие исполнилось (apt-get update): {"ДА" if executed else "НЕТ"}')
    if not executed:
        FAIL.append('A: apt-get update не исполнился — натуральная цена не снята')
    if all(restored.get(s) == orig.get(s) for s in orig):
        print('  исходные mtime штампов возвращены — натуральный тик ночи решает по прежнему штампу')
    else:
        FAIL.append('A: штампы не возвращены к исходным mtime')
    rows, (c0, c1, e0, e1) = layers(d, 'mC0.txt', 'mC1.txt', 'mE0.txt', 'mE1.txt')
    tot = {layer: sum(v.get(layer, 0) for v in rows.values()) for layer, _ in LAYERS}
    print(f'  E − C по трём слоям: выпущено {tot["emitted"]} / дедуп {tot["dedup"]} / лимитер {tot["limiter"]}')
    price = {r: sum(v.values()) for r, v in rows.items()}
    for r in sorted(price, key=lambda r: -price[r])[:15]:
        if price[r] <= 0:
            continue
        v = rows[r]
        print(f'    {price[r]:+7d}  {v.get("emitted", 0):+6d}/{v.get("dedup", 0):+6d}/{v.get("limiter", 0):+6d}  {r}')
    # Пути записи в /tmp по образам — вход решения об оси исключения.
    opens = {}
    for l in rd(d, 'bpf.txt').splitlines():
        if not l.startswith('O '):
            continue
        parts = l.split(None, 4)
        if len(parts) < 5:
            continue
        _, pid, comm, flags, path = parts
        if not re.match(r'^/(tmp|var/tmp|dev/shm|run/user)/', path):
            continue
        norm = re.sub(r'\.[A-Za-z0-9]{6,}', '.XXXXXX', path)
        key = (comm, norm)
        opens[key] = opens.get(key, 0) + 1
    print('  открытия на запись в /tmp, /var/tmp, /dev/shm, /run/user (свидетель bpftrace), по образу comm и пути:')
    for (comm, p), k in sorted(opens.items(), key=lambda kv: -kv[1])[:30]:
        print(f'    {k:6d}  {comm:16s} {p}')
    al = [a for a in alerts(os.path.join(d, 'alerts-CE.json')) if tE0 <= ts(a['timestamp']) <= tE1 + 1]
    hid = {}
    for a in al:
        if a['rule_id'] != 'evasion_hidden_elf_in_tmp':
            continue
        k = (a.get('comm'), '>'.join(x.get('comm', '') for x in (a.get('process_tree') or [])))
        hid[k] = hid.get(k, 0) + 1
    print('  evasion_hidden_elf_in_tmp в сторе окна E по comm и дереву:')
    for (c, t), k in sorted(hid.items(), key=lambda kv: -kv[1]):
        print(f'    {k:5d}  {c}  {t}')
    print_incidents(incidents_in(d, tE0, tE1), APT_TREE, 'apt-daily')
    print(f'  ИТОГ A (измерение): {"OK — событие снято" if executed else "FAIL"}')


def main():
    d = sys.argv[1]
    ident = dict(l.strip().split('=', 1) for l in open(os.path.join(d, 'binary-identity.txt')) if '=' in l)
    print(f"бинарь: файл {ident.get('sha256', '?')[:12]} процесс {ident.get('sha256_proc', '?')[:12]}")
    if ident.get('sha256') != ident.get('sha256_proc'):
        FAIL.append('измеряется не тот бинарь')
    if os.path.isdir(os.path.join(d, 'F')):
        phase_f(os.path.join(d, 'F'))
    if os.path.isdir(os.path.join(d, 'P')):
        phase_p(os.path.join(d, 'P'))
    if os.path.isdir(os.path.join(d, 'A')):
        phase_a(os.path.join(d, 'A'))
    print('\nИТОГ: ' + ('OK' if not FAIL else 'FAIL — ' + '; '.join(FAIL)))
    return 0 if not FAIL else 1


if __name__ == '__main__':
    sys.exit(main())
