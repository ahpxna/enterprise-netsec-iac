#!/usr/bin/env python3
"""End-to-end check of the honeypot path: attacker session -> Cowrie -> Logstash -> SIEM -> decision signal.

1. A real Telnet session against the Cowrie honeypot, from an attacker container (default: pc1, so the
   traffic crosses fw-core and fw-dmz): login with a unique, deliberately awkward password, run a marker command.
2. That session reaches ``soc-alerts-*`` as dataset ``cowrie.honeypot`` with the expected actions and severities.
3. The password appears NOWHERE: not in the normalized documents, not in the raw copy in ``soc-raw-*``.
4. The decision runner's own evidence query turns the source into exactly one ``honeypot`` signal.

Read-only towards the lab apart from the one honeypot session; needs the SOC plane (make soc-up) and the
honeypot (make dmzlab-up). Elasticsearch is queried through ``docker compose exec`` as soc_smoke.py does.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Runs inside the attacker container with its own python3 (pc1 installs it). Paced like a person typing:
# Cowrie's Telnet server discards input sent before it asks for it.
CLIENT = r"""
import os, socket, time
s = socket.create_connection((os.environ["HP_TARGET"], int(os.environ["HP_PORT"])), timeout=10)
def read(wait=2.0):
    s.settimeout(wait); data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data
def send(line):
    s.sendall(line.encode() + b"\r\n"); time.sleep(0.8)
banner = read()
send(os.environ["HP_USER"]); prompt = read()
send(os.environ["HP_PASSWORD"]); shell = read()
send("echo " + os.environ["HP_MARKER"]); echoed = read()
send("exit"); s.close()
print("login-prompt" if b"ogin" in banner else "no-login-prompt", "password-prompt" if b"assword" in prompt else "no-password-prompt",
      "marker-echoed" if os.environ["HP_MARKER"].encode() in echoed else "marker-not-echoed")
"""

EXPECTED_SEVERITY = {"cowrie.session.connect": 3, "cowrie.login.success": 8, "cowrie.command.input": 9}


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ComposeElastic:
    """The decision runner's ElasticClient.search contract, served through `docker compose exec`."""

    def search(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        done = subprocess.run(
            ["docker", "compose", "exec", "-T", "elasticsearch", "bash", "-ec",
             'curl --silent --show-error --fail --cacert config/certs/ca.crt --user "elastic:${ELASTIC_PASSWORD}" '
             '-H "content-type: application/json" --data-binary @- '
             '"https://localhost:9200/$0/_search?allow_no_indices=true&ignore_unavailable=true"', index],
            input=json.dumps(body), cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"Elasticsearch query on {index} failed: {done.stderr.strip()[:300]}")
        return json.loads(done.stdout)["hits"]["hits"]


def strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from strings(item, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item, path)
    elif isinstance(value, str):
        yield path, value


def attack(client: str, target: str, port: int, user: str, password: str, marker: str) -> str:
    env = {"HP_TARGET": target, "HP_PORT": str(port), "HP_USER": user, "HP_PASSWORD": password, "HP_MARKER": marker}
    flags = [item for key, value in env.items() for item in ("-e", f"{key}={value}")]
    done = subprocess.run(["docker", "exec", "-i", *flags, client, "python3", "-I", "-"], input=CLIENT,
                          capture_output=True, text=True, timeout=60, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"the session from {client} to {target}:{port} failed: {(done.stderr or done.stdout).strip()[-300:]}")
    return done.stdout.strip()


def honeypot_signals(elastic: Any, source: str, start: datetime, end: datetime) -> list[dict]:
    """The decision runner's own evidence gathering for one source address (no engine, no state, observe)."""

    from response.service.decision_runner import DecisionRunner

    runner = DecisionRunner(elastic=elastic, engine=None, state=None, mode="observe", send_command=None)
    return [s for s in runner._signals({"type": "ip", "value": source}, start, end) if s["type"] == "honeypot"]


def protected(source: str) -> bool:
    policy = yaml.safe_load((ROOT / "response/policies/default.yaml").read_text())
    networks = policy["defaults"]["protections"]["protected_networks"]
    return any(ipaddress.ip_address(source) in ipaddress.ip_network(net) for net in networks)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--client", default="clab-companyxyz-pc1", help="attacker container with python3 (default: pc1)")
    parser.add_argument("--target", default="195.1.1.161", help="honeypot address (default: dmz-web)")
    parser.add_argument("--port", type=int, default=2223, help="Cowrie Telnet port")
    parser.add_argument("--timeout", type=int, default=120, help="seconds to wait for the events in Elasticsearch")
    args = parser.parse_args(argv)

    run = uuid.uuid4().hex[:10]
    marker = f"cxyz-honeypot-e2e-{run}"
    secret = f"hp-{run}/x] failed\"q\\z"        # a slash, a fake "] failed", a quote and a backslash
    start = datetime.now(timezone.utc) - timedelta(seconds=30)
    print(f"[1/4] Telnet session {args.client} -> {args.target}:{args.port} (marker {marker})")
    print("      client:", attack(args.client, args.target, args.port, "root", secret, marker))

    elastic, deadline = ComposeElastic(), time.monotonic() + args.timeout
    window = {"range": {"@timestamp": {"gte": rfc3339(start)}}}
    session_docs: list[dict] = []
    alerts: list[dict] = []
    while time.monotonic() < deadline:
        alerts = [h["_source"] for h in elastic.search("soc-alerts-*", {"size": 1000, "query": {"bool": {"filter": [
            {"term": {"event.dataset": "cowrie.honeypot"}}, window]}}})]
        sessions = {d.get("cxyz", {}).get("honeypot_session") for d in alerts
                    if marker in str(d.get("process", {}).get("command_line", ""))}
        session_docs = [d for d in alerts if d.get("cxyz", {}).get("honeypot_session") in sessions - {None}]
        if {d.get("event", {}).get("action") for d in session_docs} >= set(EXPECTED_SEVERITY):
            break
        time.sleep(5)
    failures: list[str] = []
    actions = {d["event"]["action"]: d for d in session_docs}
    print(f"[2/4] SIEM: {len(session_docs)} cowrie.honeypot events for the session: {sorted(actions)}")
    for action, severity in EXPECTED_SEVERITY.items():
        if action not in actions:
            failures.append(f"no {action} event in soc-alerts-* within {args.timeout}s "
                            "(check: make dmzlab-status; docker compose logs logstash; the honeypot volume mount)")
        elif actions[action].get("event", {}).get("severity") != severity:
            failures.append(f"{action} has severity {actions[action]['event'].get('severity')}, expected {severity}")
    login = actions.get("cowrie.login.success", {})
    if login and (login.get("user", {}).get("name") != "root" or login.get("event", {}).get("outcome") != "success"):
        failures.append("the login event lost user.name/event.outcome")

    # The session keeps logging after the marker (exit, close): let it settle, then scan everything it wrote.
    time.sleep(10)
    alerts = [h["_source"] for h in elastic.search("soc-alerts-*", {"size": 1000, "query": {"bool": {"filter": [
        {"term": {"event.dataset": "cowrie.honeypot"}}, window]}}})]
    raw = [h["_source"] for h in elastic.search("soc-raw-*", {"size": 1000, "query": {"bool": {"filter": [
        {"term": {"event.dataset": "cowrie.raw"}}, window]}}})]
    session_ids = {d["cxyz"]["honeypot_session"] for d in session_docs}
    raw_session = [d for d in raw if any(sid in str(d.get("message", "")) for sid in session_ids)]
    leaks = [(where, path) for where, docs in (("soc-alerts", alerts), ("soc-raw", raw))
             for doc in docs for path, text in strings(doc) if f"hp-{run}" in text]
    print(f"[3/4] Redaction: scanned {len(alerts)} normalized + {len(raw)} raw honeypot documents "
          f"({len(raw_session)} raw for this session); password occurrences: {len(leaks)}")
    if not raw_session:
        failures.append("no raw copy of the session in soc-raw-*: the redaction scan would prove nothing")
    if leaks:
        failures.append(f"ATTACKER PASSWORD INDEXED in {sorted(set(leaks))[:5]}")

    source = next((d.get("source", {}).get("ip") for d in session_docs if d.get("source", {}).get("ip")), None)
    if source:
        signals = honeypot_signals(elastic, source, start, datetime.now(timezone.utc))
        print(f"[4/4] Decision evidence for {source}: {[(s['severity'], s['count']) for s in signals]} "
              f"({'protected network: never contained, by design' if protected(source) else 'containable if an AI anomaly corroborates'})")
        if len(signals) != 1:
            failures.append(f"expected exactly one honeypot signal for {source}, got {len(signals)}")
        elif signals[0]["severity"] < 9:
            failures.append(f"the honeypot signal kept severity {signals[0]['severity']}, expected the worst event (9)")
    else:
        failures.append("no source.ip on the honeypot events: the decision engine cannot attribute them")

    for failure in failures:
        print("FAIL:", failure)
    if failures:
        return 1
    print("PASS: honeypot session -> SIEM (cowrie.honeypot) -> password redacted (normalized + raw) -> one decision signal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
