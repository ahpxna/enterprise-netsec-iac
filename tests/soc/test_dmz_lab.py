"""DMZ deception lab: the vulnerable app and the honeypot must stay contained and observable."""

import json
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
LAB = ("dmz-vuln", "dmz-honeypot")


def forward_rules(config: str) -> list[str]:
    """Logical rules of fw-dmz's forward chain (continuation lines joined, comments dropped)."""

    body = config.split("chain forward", 1)[1]
    joined = re.sub(r"\\\n\s*", " ", body)
    return [re.sub(r"\s+", " ", line.strip()) for line in joined.splitlines() if line.strip() and not line.strip().startswith("#")]


def test_lab_services_are_isolated_disposable_and_share_the_dmz_web_namespace():
    for name in LAB:
        service = SERVICES[name]
        assert service["profiles"] == ["dmzlab"], name
        assert service["network_mode"] == "container:clab-companyxyz-dmz-web" and "networks" not in service
        assert not service.get("ports") and not service.get("privileged") and not service.get("volumes_from")
        assert service["cap_drop"] == ["ALL"] and "no-new-privileges:true" in service["security_opt"]
        assert "@sha256:" in service["image"] and service.get("pids_limit") and service.get("mem_limit")
        assert "docker.sock" not in json.dumps(service)
    assert SERVICES["dmz-honeypot"]["read_only"] is True      # the attacker-facing one has an immutable root filesystem


def test_the_lab_is_only_reachable_through_dedicated_logged_rules_that_precede_the_default_drop():
    rules = forward_rules((ROOT / "clab/configs/fw-dmz.nft").read_text())
    index = lambda text: next(i for i, r in enumerate(rules) if text in r)          # noqa: E731
    pivot, vuln, honeypot = index("dmz_pivot_drop"), index("dmzlab_vuln_hit"), index("dmzlab_honeypot_hit")
    egress, default_drop = index("iifname \"eth2\" oifname \"eth1\" ip saddr @web accept"), index("forward_default_drop")
    assert pivot < vuln < honeypot < egress < default_drop
    assert rules[vuln].startswith('iifname "eth1" oifname "eth2" ip daddr @web tcp dport 3000 ct state new ')
    assert 'tcp dport { 2222, 2223 } ct state new' in rules[honeypot]
    for rule in (rules[vuln], rules[honeypot]):
        assert rule.endswith("accept") and 'log prefix "CXYZ-DMZLAB-' in rule and "counter name" in rule
    # nothing else was opened toward the web host, and the pivot deny still covers every internal destination
    opened = [r for r in rules if 'oifname "eth2" ip daddr @web' in r and r.endswith("accept")]
    assert len(opened) == 4                                                     # 80/443, DNS, lab web, lab honeypot
    assert "172.16.0.0/16, 192.168.0.0/16" in rules[pivot] and rules[pivot].endswith("drop")


def test_the_honeypot_log_path_is_consistent_between_compose_logstash_and_the_pipeline():
    cowrie_volume = next(v for v in SERVICES["dmz-honeypot"]["volumes"])
    volume, mount = cowrie_volume.split(":")[:2]
    assert mount == "/cowrie/cowrie-git/var" and volume in COMPOSE["volumes"]
    logstash_mount = next(v for v in SERVICES["logstash"]["volumes"] if v.startswith(volume + ":"))
    assert logstash_mount.endswith(":ro")                                      # Logstash can read, never write, the honeypot's data
    pipeline = (ROOT / "soc/logstash/pipelines/45-cowrie.conf").read_text()
    container_path = logstash_mount.split(":")[1] + "/log/cowrie/cowrie.json"   # Cowrie writes var/log/cowrie/cowrie.json
    assert container_path in pipeline and '"[@metadata][source_authentication]" => "read_only_volume"' in pipeline


def test_normalization_maps_honeypot_fields_and_never_indexes_attacker_passwords():
    normalize = (ROOT / "soc/logstash/pipelines/70-normalize-ecs.conf").read_text()
    branch = normalize.split('} else if [@metadata][source_type] == "cowrie"', 1)[1].split('} else {\n      if [@metadata][source_type] == "network_syslog"', 1)[0]
    assert 'remove_field => ["password"]' in branch
    for token in ('"src_ip" => "[source][ip]"', '"dst_port" => "[destination][port]"', '"username" => "[user][name]"',
                  '"[event][dataset]" => "cowrie.honeypot"', '"[@metadata][index_family]" => "alerts"', "cowrie.login.success", "file_(download|upload)"):
        assert token in branch, token
    assert "[password]" not in branch.replace('remove_field => ["password"]', "")       # never renamed or copied elsewhere


def cowrie_redactions() -> tuple[str, list[tuple[re.Pattern, str]]]:
    """The gsub pairs the pipeline applies to Cowrie's received line (Ruby and Python agree on these regexes)."""

    normalize = (ROOT / "soc/logstash/pipelines/70-normalize-ecs.conf").read_text()
    block = normalize.split("filter {", 1)[1].split('if [@metadata][source_type] == "cowrie" {', 1)[1].split("\n  }\n", 1)[0]
    gsub = re.search(r"gsub => \[(.*?)\n\s*\]", block, flags=re.S).group(1)
    return normalize, [(re.compile(pattern), replacement) for pattern, replacement in re.findall(r"\"message\", '(.*?)', '(.*?)'", gsub)]


def test_attacker_passwords_are_redacted_in_the_received_line_before_it_is_preserved_or_cloned():
    normalize, redactions = cowrie_redactions()
    assert len(redactions) == 2
    # Before event.original is copied and before the raw clone: soc-raw-* must not keep the secret either.
    assert normalize.index("gsub => [") < normalize.index('copy => { "message" => "[event][original]" }') < normalize.index("clone {")
    secret = 'p/w] failed"x\\y'                       # a slash, a fake "] failed", a quote and a backslash
    for event in ("cowrie.login.success", "cowrie.login.failed"):
        outcome = event.rsplit(".", 1)[1].replace("success", "succeeded")
        line = json.dumps({"eventid": event, "username": "root", "password": secret, "src_ip": "198.51.100.7",
                           "message": f"login attempt [root/{secret}] {outcome}", "session": "4e1258b56dbd"})
        for pattern, replacement in redactions:
            line = pattern.sub(replacement, line)
        parsed = json.loads(line)                     # still valid JSON for the json filter
        assert parsed["password"] == "[REDACTED]" and parsed["message"] == f"login attempt [REDACTED] {outcome}"
        assert "p/w" not in line and parsed["username"] == "root" and parsed["src_ip"] == "198.51.100.7"
    command = json.dumps({"eventid": "cowrie.command.input", "input": "uname -a", "message": "CMD: uname -a"})
    assert all(pattern.sub(replacement, command) == command for pattern, replacement in redactions)


def test_the_new_images_are_in_the_audited_lock_with_both_platforms():
    lock = yaml.safe_load((ROOT / "supply-chain/images.lock.yml").read_text())["images"]
    for key, image in (("juice-shop", SERVICES["dmz-vuln"]["image"]), ("cowrie", SERVICES["dmz-honeypot"]["image"])):
        assert lock[key]["pinned_ref"] == image and lock[key]["scopes"] == ["compose"]
        assert {"linux/amd64", "linux/arm64"} <= set(lock[key]["required_platforms"])


def test_attack_script_has_a_fixed_target_and_checks_isolation():
    script = (ROOT / "scripts/dmzlab_attack.sh").read_text()
    assert "TARGET=195.1.1.161" in script
    outside_probe = [line for line in script.splitlines() if not line.startswith("probe()")]
    assert not any(re.search(r"\$(\{?[1-9@*]|\{@)", line) for line in outside_probe)        # no script argument or environment-chosen host
    assert "dmz-web cannot reach" in script and "pivot deny is not working" in script
