#!/usr/bin/env python3
"""w85-o1-cfg.py <config.yaml> <SRC> — патч конфига второго агента для пары O1 (роль берётся из W85_O1_ROLE=A|B).
A: список ядерного allowlist номеров по умолчанию (в нём socket(41) УЖЕ открыт порцией 4 волны 7, clone(56) нет),
   F1 включён, кандидаты [9,10,158].
B: тот же список + 56 (clone), F1 включён, кандидаты [9,10,158,41,56] — чтобы метрика состояния показала,
   что F1 для 41 и 56 предиката не выводит (блокеры).
Единственная разница ролей — открытие clone(56) (и кандидаты F1)."""
import os, re, sys
cfg, src = sys.argv[1], sys.argv[2]
role = os.environ['W85_O1_ROLE']
assert role in ('A', 'B'), role
body = open(os.path.join(src, 'internal/bpf/sampling.go'), encoding='utf-8').read()
fn = body[body.index('func DefaultMonitoredSyscalls()'):]
fn = fn[:fn.index('\n}\n')]
nrs = [int(m) for m in re.findall(r'^\t\t(\d+),', fn, re.M)]
assert 59 in nrs and 321 in nrs and 41 in nrs and len(nrs) > 30, nrs
if role == 'B':
    assert 56 not in nrs
    nrs.append(56)
cand = [9, 10, 158] + ([41, 56] if role == 'B' else [])
s = open(cfg, encoding='utf-8').read()
old = 'kernel_filter:\n    enabled: true\n'
assert s.count(old) == 1
new = old + '    monitored_syscalls: [%s]\n    arg_predicates:\n      enabled: true\n      nrs: [%s]\n      counters_interval: 2s\n' % (
    ', '.join(map(str, nrs)), ', '.join(map(str, cand)))
s = s.replace(old, new)
open(cfg, 'w', encoding='utf-8').write(s)
print('role %s: %d allowlisted nrs, F1 candidates %s' % (role, len(nrs), cand))
