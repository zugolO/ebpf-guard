#!/bin/bash
# w81-debt-chain.sh — долги 8.1 (08.10.2026), второй заход: смок dpkg на
# правилах №545 (фазы M/D/P/S/C), затем пакет атак + гейт (№545), затем
# цена события ноды по таймерам (№549, только замер). Каждое
# звено со своим рестартом и чистым стором; провал смока не отменяет пакет —
# это независимые вердикты. Маркер конца — /var/lib/w81-debt-chain.DONE.
set -u
SETUP=/opt/ebpf-guard/deploy/docker-test-setup
rm -f /var/lib/w81-debt-chain.DONE
OUT=/var/lib/w81-smoke-545 bash $SETUP/w81-dpkg-smoke.sh; echo "smoke rc=$?" > /var/lib/w81-debt-chain.log
sleep 60
OUT=/var/lib/w81-545-attacks bash $SETUP/w81-545-attacks.sh; echo "attacks rc=$?" >> /var/lib/w81-debt-chain.log
sleep 60
OUT=/var/lib/w549-price bash $SETUP/w549-node-price.sh; echo "w549 rc=$?" >> /var/lib/w81-debt-chain.log
date -u +%FT%TZ > /var/lib/w81-debt-chain.DONE
