#!/usr/bin/env python3
"""Wave 8.1, №543 — verdicts for a w81-dpkg-smoke.sh archive.

Usage: w81-dpkg-smoke-report.py <OUT dir fetched from the stand>

Three layers per rule (emitted / dedup-dropped / rate-limited) are counted over
the rule's own id AND every id Rego renamed it to (ebpf_guard_alert_rule_id_
renamed_total{base_rule_id}): container_escape_module_access is published as
kernel_module_access, and a zero under one name only is an instrument zero.
Exit code 0 only when every verdict is OK.
"""
import datetime
import json
import os
import re
import sys

SER = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LBL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

TARGET = ['container_escape_module_access', 'impact_mass_file_deletion_critical',
          'evasion_log_clear', 'defense_evasion_journald_log_clear', 'ransomware_log_wipe']
LOG4 = TARGET[1:]


def load(path):
    out = {}
    for line in open(path, errors='replace'):
        if line.startswith('#'):
            continue
        m = SER.match(line)
        if not m:
            continue
        try:
            v = float(m.group(3))
        except ValueError:
            continue
        out[(m.group(1), tuple(sorted(LBL.findall(m.group(2) or ''))))] = v
    return out


def delta(a, b, name, where):
    tot = 0.0
    for (n, l), v in b.items():
        if n == name and where(dict(l)):
            tot += v - a.get((n, l), 0.0)
    return tot


def names_of(final, rule):
    ids = {rule}
    for (n, l), _ in final.items():
        d = dict(l)
        if n == 'ebpf_guard_alert_rule_id_renamed_total' and d.get('base_rule_id') == rule:
            ids.add(d['rule_id'])
    return ids


def layers(a, b, ids):
    em = delta(a, b, 'ebpf_guard_alerts_total', lambda d: d.get('rule_id') in ids)
    dd = delta(a, b, 'ebpf_guard_alerts_dedup_dropped_by_rule_total', lambda d: d.get('rule_id') in ids)
    rl = delta(a, b, 'ebpf_guard_alerts_ratelimited_by_rule_total', lambda d: d.get('rule_id') in ids)
    return int(em), int(dd), int(rl)


def alerts(path, lo=None, hi=None):
    """Store dump of a phase, cut to the phase window [lo, hi] (files t*).

    The API's since= hands back alerts older than the window (run 08.10.2026:
    the M-phase dump carried the preparation `head > b.ko` 70 s before tM0),
    so every verdict reads only alerts stamped inside the window.
    """
    try:
        data = json.load(open(path))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict):
        data = data.get('alerts') or data.get('items') or []
    if lo is None:
        return data
    d = os.path.dirname(path)
    t0 = int(open(os.path.join(d, lo)).read())
    t1 = int(open(os.path.join(d, hi)).read())

    def ts(a):
        x = a.get('timestamp', '').rstrip('Z')
        if '.' in x:
            h, f = x.split('.', 1)
            x = h + '.' + f[:6]
        try:
            return datetime.datetime.fromisoformat(x).replace(tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            return None
    return [a for a in data if ts(a) is not None and t0 <= ts(a) <= t1 + 1]


RT = 'integrity_container_runtime_modified'
IMPACT = TARGET[1]


def exc(a, b, rule, name):
    return int(delta(a, b, 'ebpf_guard_rule_exceptions_total',
                     lambda x: x.get('rule_id') == rule and x.get('exception_name') == name))


def phase_c(d, verdict):
    """Долги 8.1 (08.10.2026): №550 .pre-conffile и №547 рантайм контейнеров."""
    if not os.path.exists(os.path.join(d, 'mC0.txt')):
        print('\n[C] фазы нет в архиве (смок старше долгов №547/№550)')
        return
    mC = [load(os.path.join(d, f'mC{i}.txt')) for i in range(3)]
    final = mC[2]

    print('\n[C1] dpkg-цикл: w81-conf (.pre-conffile, №550) и w81-rt (/usr/bin/containerd-w81test, №547)')
    print(open(os.path.join(d, 'control-C1.txt')).read().rstrip())
    for r in (IMPACT, RT):
        ids = names_of(final, r)
        em, dd, rl = layers(mC[0], mC[1], ids)
        verdict(em + dd + rl == 0, f'{r} {sorted(ids)}: выпущено {em} / дедуп {dd} / лимитер {rl} — ожидалось 0')
    ta = exc(mC[0], mC[1], IMPACT, 'package-transient-artifact')
    verdict(ta > 0, f'{IMPACT}: package-transient-artifact за окно {ta} — ожидалось > 0 (rm .pre-conffile дошёл и подавлен)')
    pm = exc(mC[0], mC[1], RT, 'package-manager')
    verdict(pm > 0, f'{RT}: package-manager за окно {pm} — ожидалось > 0 (dpkg писал/переименовывал бинарь)')
    al = alerts(os.path.join(d, 'alerts-C1.json'), 'tC0', 'tC1')
    verdict(al is not None, 'стор окна C1 прочитан')
    pre = [a for a in (al or []) if (a.get('details') or {}).get('file.path', '').endswith('.pre-conffile')]
    verdict(not pre, f'алертов на *.pre-conffile в сторе C1: {len(pre)} {sorted({a.get("rule_id") for a in pre})}')

    print('\n[C2] положительные контроли и спуф (root shell)')
    print(open(os.path.join(d, 'control-C2.txt')).read().rstrip())
    al = alerts(os.path.join(d, 'alerts-C2.json'), 'tC1', 'tC2')
    verdict(al is not None, 'стор окна C2 прочитан')
    al = al or []

    def rules_on(comm, paths):
        got = set()
        for a in al:
            p = (a.get('details') or {}).get('file.path', '')
            if a.get('comm') == comm and p in paths:
                got.add(a.get('rule_id'))
        return got

    def has(got, rule):
        return bool(names_of(final, rule) & got)

    got = rules_on('rm', {'/etc/w81c-victim.conf'})
    verdict(has(got, IMPACT), f'rm /etc/w81c-victim.conf → {IMPACT}: {sorted(got)}')
    got = rules_on('rm', {'/var/log/w81c.log.pre-conffile'})
    verdict(has(got, IMPACT) and has(got, 'evasion_log_clear'),
            f'приманка /var/log/*.pre-conffile → {IMPACT} и evasion_log_clear: {sorted(got)}')
    for who, comm, base in (('mv от root shell', 'mv', '/usr/bin/containerd-w81ctl'),
                            ('спуф: копия mv под именем dpkg', 'dpkg', '/usr/bin/containerd-w81spoof'),
                            ('mv под dpkg --pre-invoke', 'mv', '/usr/bin/containerd-w81pre')):
        got = rules_on(comm, {base, base + '.tmp'})
        verdict(has(got, RT), f'{who} → {RT}: {sorted(got)}')


def main():
    d = sys.argv[1]
    m = [load(os.path.join(d, f'm{i}.txt')) for i in range(4)]
    final = m[3]
    bad = 0

    def verdict(ok, text):
        nonlocal bad
        bad += 0 if ok else 1
        print(('OK    ' if ok else 'FAIL  ') + text)

    ident = dict(l.split('=', 1) for l in open(os.path.join(d, 'binary-identity.txt')) if '=' in l)
    verdict(ident.get('sha256') == ident.get('sha256_proc'),
            f"тождество бинаря: файл {ident.get('sha256', '?')[:12]} процесс {ident.get('sha256_proc', '?')[:12]}")

    mM = [load(os.path.join(d, f'mM{i}.txt')) for i in range(3)]
    print('\n[M] только мутации в /lib/modules (root shell)')
    print(open(os.path.join(d, 'control-M.txt')).read().rstrip())
    mops = {op: int(delta(mM[0], mM[1], 'ebpf_guard_file_events_by_op_total', lambda x, o=op: x.get('op') == o))
            for op in ('unlink', 'rename', 'rmdir', 'truncate')}
    print('  file_events_by_op за окно:', mops)
    verdict(all(v > 0 for v in mops.values()), 'все четыре мутации дошли до агента')
    ids = names_of(final, TARGET[0])
    em, dd, rl = layers(mM[0], mM[1], ids)
    r545 = os.path.exists(os.path.join(d, 'rules-545.txt')) and open(os.path.join(d, 'rules-545.txt')).read().strip() == '1'
    if not r545:
        verdict(em + dd + rl == 0, f'{TARGET[0]} {sorted(ids)} на мутациях: выпущено {em} / дедуп {dd} / лимитер {rl} — ожидалось 0')
    else:
        # №545: rename a.ko → a2.ko от root shell — посадка (ветка B), правило
        # обязано сработать; truncate/unlink b.ko и rmdir — нет. Op в сторе нет,
        # поэтому судим по путям: b.ko и каталоги переименованием не трогались.
        print(f'  {TARGET[0]} {sorted(ids)} за окно M: выпущено {em} / дедуп {dd} / лимитер {rl} (правила №545)')
        alm = alerts(os.path.join(d, 'alerts-M.json'), 'tM0', 'tM1')
        verdict(alm is not None, 'стор окна M прочитан')
        paths = {}
        for a in alm or []:
            if a.get('rule_id') in ids:
                p = (a.get('details') or {}).get('file.path', '')
                paths[p] = paths.get(p, 0) + 1
        mm = '/lib/modules/w81-mut'
        renamed = {mm + '/a.ko', mm + '/a2.ko'}
        other = {mm + '/b.ko', mm + '/sub', mm}
        verdict(any(paths.get(p) for p in renamed), f'rename от root shell → {TARGET[0]} (ветка посадки): {paths}')
        verdict(not any(paths.get(p) for p in other), f'truncate/unlink/rmdir → {TARGET[0]} 0: {paths}')
    em, dd, rl = layers(mM[0], mM[1], {TARGET[1]})
    verdict(em + dd + rl > 0, f'{TARGET[1]} (называет op) на rm/rmdir в /lib/modules: {em}/{dd}/{rl} — ожидалось > 0')
    em, dd, rl = layers(mM[1], mM[2], ids)
    what = ('запись c.ko от root shell (ветка посадки №545; open хоста правило больше не видит)'
            if r545 else 'open-контроле')
    verdict(em + dd + rl > 0, f'{TARGET[0]} на {what}: {em}/{dd}/{rl} — ожидалось > 0 (правило живо)')

    print('\n[D] dpkg-контроль')
    print(open(os.path.join(d, 'control-D.txt')).read().rstrip())
    ops = {op: int(delta(m[0], m[1], 'ebpf_guard_file_events_by_op_total', lambda x, o=op: x.get('op') == o))
           for op in ('unlink', 'rename', 'rmdir', 'truncate', 'open')}
    print('  file_events_by_op за фазу:', ops)
    verdict(all(ops[o] > 0 for o in ('unlink', 'rename', 'rmdir')), 'мутации dpkg видны (unlink/rename/rmdir > 0)')
    for r in TARGET:
        ids = names_of(final, r)
        em, dd, rl = layers(m[0], m[1], ids)
        if r == TARGET[0] and not r545:
            # dpkg делает в /lib/modules и open(.dpkg-new), и chmod каталога —
            # op 0 и 3, класс до item 7 (№545); op в сторе нет, поэтому здесь
            # величина печатается, а судит её фаза M.
            print(f'  {r} {sorted(ids)}: выпущено {em} / дедуп {dd} / лимитер {rl} — open/chmod dpkg, №545; мутации судит фаза M')
            continue
        # С правилами №545 dpkg в /lib/modules (open/chmod хоста, write/rename
        # от /usr/bin/dpkg) — 0 и для module_access: это и есть его шум ночей.
        verdict(em + dd + rl == 0, f'{r} {sorted(ids)}: выпущено {em} / дедуп {dd} / лимитер {rl} — ожидалось 0')
    pm = {r: int(delta(m[0], m[1], 'ebpf_guard_rule_exceptions_total',
                       lambda x, r=r: x.get('rule_id') == r and x.get('exception_name') == 'package-manager'))
          for r in LOG4}
    print('  package-manager за фазу:', pm)
    verdict(sum(pm.values()) > 0, 'исключение package-manager считается в rule_exceptions_total')
    ad = delta(m[0], m[1], 'ebpf_guard_rule_exceptions_total', lambda x: x.get('exception_name') == 'apt-planner-dump')
    print(f'  apt-planner-dump за фазу: {int(ad)} (ноль допустим, если apt не пересоздал дамп — см. eipp_inode)')

    print('\n[P] положительный контроль item 7 (root shell)')
    print(open(os.path.join(d, 'control-P.txt')).read().rstrip())
    fired = 0
    for r in LOG4:
        em, dd, rl = layers(m[1], m[2], names_of(final, r))
        print(f'  {r}: выпущено {em} / дедуп {dd} / лимитер {rl}')
        fired += 1 if em + dd + rl > 0 else 0
    verdict(fired == 4, f'лог-правил сработало {fired}/4')

    print('\n[S] спуф образа и потомок dpkg')
    print(open(os.path.join(d, 'control-S.txt')).read().rstrip())
    al = alerts(os.path.join(d, 'alerts-S.json'), 't2', 't3')
    verdict(al is not None, 'стор фазы S прочитан')
    al = al or []
    for who, comm, path in (('спуф /var/tmp/w81spoof/dpkg', 'dpkg', '/var/log/w81spoof.log'),
                            ('rm под dpkg --pre-invoke', 'rm', '/var/log/w81pre.log')):
        got = set()
        for a in al:
            p = (a.get('details') or {}).get('file.path', '')
            if a.get('comm') == comm and p == path:
                got.add(a.get('rule_id'))
        hit = [r for r in LOG4 if names_of(final, r) & got]
        verdict(len(hit) == 4, f'{who}: сработало {len(hit)}/4 лог-правил {sorted(got)}')

    phase_c(d, verdict)

    print(f"\nИТОГ: {'OK' if bad == 0 else f'FAIL ({bad})'}")
    sys.exit(0 if bad == 0 else 1)


if __name__ == '__main__':
    main()
