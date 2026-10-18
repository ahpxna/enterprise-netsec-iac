#!/usr/bin/env bash
# Fail-closed attack replay: enforce -> detect -> fail over -> emit JSON.
set -euo pipefail

LAB="companyxyz"
EV="${EVIDENCE_DIR:-evidence/runs/adhoc}"
export EVIDENCE_DIR="$EV"
mkdir -p "$EV"

n() { printf 'clab-%s-%s' "$LAB" "$1"; }
utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

nft_packets() {
  local node="$1" table="$2" counter="$3"
  docker exec "$(n "$node")" nft list counter inet "$table" "$counter" \
    | awk '/packets/ {for (i=1; i<=NF; i++) if ($i == "packets") {print $(i+1); exit}}'
}

wazuh_alert_count() {
  local rule_id="$1"
  docker compose exec -T wazuh.manager sh -c \
    "grep -Ec '\"id\"[[:space:]]*:[[:space:]]*\"${rule_id}\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true" \
    | tr -d '\r' | tail -n 1
}

record() {
  python3 -m compliance.record_evidence "$@"
}

step2_scan_detected() {
  local started before after alert_before alert_after result
  started="$(utc_now)"
  before="$(nft_packets fw-core cxyz det01_scan_drop)"
  alert_before="$(wazuh_alert_count 100201)"
  alert_before="${alert_before:-0}"

  docker exec "$(n pc1)" nmap -sS -Pn -p 22,23,80 172.16.50.1 \
    -oN "/tmp/cxyz-det01-nmap.txt" >/dev/null
  docker exec "$(n pc1)" cat /tmp/cxyz-det01-nmap.txt > "$EV/step2_nmap.txt"

  after="$(nft_packets fw-core cxyz det01_scan_drop)"
  alert_after="$alert_before"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    alert_after="$(wazuh_alert_count 100201)"
    alert_after="${alert_after:-0}"
    if (( alert_after > alert_before )); then
      break
    fi
    sleep 2
  done

  result="FAIL"
  if (( after > before && alert_after > alert_before )); then
    result="PASS"
  fi
  record \
    --test-id "attack_chain.sh::step2_scan_detected" \
    --control DET-01 --result "$result" \
    --assertion "scan increments fw-core deny counter and creates Wazuh rule 100201 alert" \
    --enforcement-node fw-core \
    --counter-before "$before" --counter-after "$after" \
    --started-at "$started" \
    --observed "firewall_counter_delta=$((after - before))" \
    --observed "wazuh_alert_delta=$((alert_after - alert_before))"
  [[ "$result" == PASS ]]
}

restore_vrrp_master() {
  docker exec "$(n dist1)" vtysh \
    -c "configure terminal" -c "interface eth1" -c "no shutdown" >/dev/null 2>&1 || true
}

vrrp_bootstrap_ready() {
  local node="$1" vrid="$2" vip="$3"
  docker exec "$(n "$node")" sh -c \
    "device=\$(ip -o link show | awk -F': ' '\$2 ~ /^vrrp4-[0-9]+-${vrid}(@.*)?$/ {print \$2; exit}' | cut -d@ -f1); test -n \"\$device\" && ip -4 addr show dev \"\$device\" | grep -Fq '$vip'"
}

vrrp_advertisements_seen() {
  local output="$1"
  python3 - "$output" <<'PY'
import json
import re
import sys

text = sys.argv[1]
try:
    values = json.loads(text)
except json.JSONDecodeError:
    raise SystemExit(1)

# Per IPv4 VRRP group: the Master must be sending advertisements and the Backup
# receiving them. The unused IPv6 instance and the Backup's own (zero) transmit
# counter say nothing about VRRP health, so they are not part of the check.
groups = values if isinstance(values, list) else [values]
checked = 0
for group in groups:
    v4 = (group or {}).get("v4") or {}
    stats = v4.get("stats") or {}
    counter = {"Master": "adverTx", "Backup": "adverRx"}.get(v4.get("status"))
    if counter is None or not stats.get(counter, 0) > 0:
        raise SystemExit(1)
    checked += 1
raise SystemExit(0 if checked else 1)
PY
}

step5_vrrp_failover() {
  local started d1_state d2_state d1_json d2_json d2_failover_state bootstrap_ready advertisements_ready result ping_file
  local failover_at restored_at failover failover_ok
  started="$(utc_now)"
  ping_file="$EV/step5_vrrp_failover.txt"
  d1_state="$(docker exec "$(n dist1)" vtysh -c "show vrrp" 2>/dev/null || true)"
  d2_state="$(docker exec "$(n dist2)" vtysh -c "show vrrp" 2>/dev/null || true)"
  d1_json="$(docker exec "$(n dist1)" vtysh -c "show vrrp json" 2>/dev/null || true)"
  d2_json="$(docker exec "$(n dist2)" vtysh -c "show vrrp json" 2>/dev/null || true)"
  bootstrap_ready=false
  if vrrp_bootstrap_ready dist1 10 192.168.10.254/24 \
      && vrrp_bootstrap_ready dist1 40 192.168.40.254/24 \
      && vrrp_bootstrap_ready dist2 10 192.168.10.254/24 \
      && vrrp_bootstrap_ready dist2 40 192.168.40.254/24; then
    bootstrap_ready=true
  fi
  advertisements_ready=false
  if vrrp_advertisements_seen "$d1_json" && vrrp_advertisements_seen "$d2_json"; then
    advertisements_ready=true
  fi

  trap restore_vrrp_master EXIT
  docker exec "$(n pc1)" sh -c \
    "ping -D -i 0.1 -c 170 198.10.10.1 > /tmp/cxyz-ha01-ping.txt 2>&1 &"
  sleep 1
  failover_at="$(python3 -c 'import time; print(f"{time.time():.6f}")')"
  docker exec "$(n dist1)" vtysh \
    -c "configure terminal" -c "interface eth1" -c "shutdown" >/dev/null
  sleep 5
  d2_failover_state="$(docker exec "$(n dist2)" vtysh -c "show vrrp" 2>/dev/null || true)"
  sleep 1
  restored_at="$(python3 -c 'import time; print(f"{time.time():.6f}")')"
  restore_vrrp_master
  trap - EXIT
  sleep 10
  docker exec "$(n pc1)" cat /tmp/cxyz-ha01-ping.txt > "$ping_file"

  # Traffic must keep flowing while dist1 is down, not merely have flowed before it went down.
  failover_ok=false
  if failover="$(python3 scripts/vrrp_failover_check.py "$ping_file" "$failover_at" "$restored_at")"; then
    failover_ok=true
  fi

  result="FAIL"
  if [[ "$bootstrap_ready" == true && "$advertisements_ready" == true ]] \
      && grep -qi master <<<"$d1_state" \
      && grep -qi backup <<<"$d2_state" \
      && grep -qi master <<<"$d2_failover_state" \
      && [[ "$failover_ok" == true ]]; then
    result="PASS"
  fi
  record \
    --test-id "attack_chain.sh::step5_vrrp_failover" \
    --control HA-01 --result "$result" \
    --assertion "VRRP state is healthy and routed user traffic keeps flowing through the backup gateway while the master is down (no interruption of 5 seconds or more)" \
    --enforcement-node dist1,dist2 \
    --started-at "$started" \
    --observed "dist1_master=$(grep -qi master <<<"$d1_state" && echo true || echo false)" \
    --observed "dist2_backup=$(grep -qi backup <<<"$d2_state" && echo true || echo false)" \
    --observed "dist2_took_master_after_vlan10_failure=$(grep -qi master <<<"$d2_failover_state" && echo true || echo false)" \
    --observed "macvlan_bootstrap_ready=$bootstrap_ready" \
    --observed "vrrp_advertisements_seen=$advertisements_ready" \
    --observed "failover_traffic=${failover:-none}"
  [[ "$result" == PASS ]]
}

failures=0
if ! step2_scan_detected; then
  echo "FAIL[DET-01]: enforcement-to-Wazuh correlation failed" >&2
  failures=$((failures + 1))
fi
if ! step5_vrrp_failover; then
  echo "FAIL[HA-01]: measured VRRP failover objective failed" >&2
  failures=$((failures + 1))
fi

echo "attack replay complete: $failures critical failure(s); evidence=$EV"
exit "$failures"
