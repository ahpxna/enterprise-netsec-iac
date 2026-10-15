"""Shipped deployment files must satisfy the closed service schemas and share safeguards."""

from pathlib import Path

import pytest
import yaml

from response.policy import PolicyCatalog
from response.service.config import ConfigError, parse_decision_service, parse_response_service

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("path", ["path-a", "path-b"])
def test_shipped_service_configs_parse_and_default_to_observe(path):
    response = parse_response_service(yaml.safe_load((ROOT / f"response/deployments/{path}/response.yaml").read_text()), {})
    decision = parse_decision_service(yaml.safe_load((ROOT / f"response/deployments/{path}/decision.yaml").read_text()), {})
    assert response["mode"] == "observe" and decision["mode"] == "observe"
    assert response["firewall"]["backend"] == {"path-a": "nftables", "path-b": "vyos"}[path]
    for text in ((ROOT / f"response/deployments/{path}").glob("*.yaml")):
        body = text.read_text().lower()
        assert "password:" not in body and "secret:" not in body       # names files, never secrets


@pytest.mark.parametrize("kind, parse", [("response", parse_response_service), ("decision", parse_decision_service)])
def test_soc_mode_override_is_closed_and_otherwise_keeps_the_reviewed_mode(kind, parse):
    document = yaml.safe_load((ROOT / f"response/deployments/path-a/{kind}.yaml").read_text())
    assert parse(document, {"SOC_MODE": ""})["mode"] == "observe"
    assert parse(document, {"SOC_MODE": "enforce"})["mode"] == "enforce"
    with pytest.raises(ConfigError):
        parse(document, {"SOC_MODE": "disabled"})
    assert document["mode"] == "observe"            # the reviewed file is never mutated


def test_every_policy_overlay_keeps_identical_safeguards_except_isolation_enrolment():
    base = yaml.safe_load((ROOT / "response/policies/default.yaml").read_text())
    for overlay in sorted((ROOT / "response/policies").glob("*.yaml")):
        PolicyCatalog.from_path(overlay)            # loads (fail-closed validation)
        document = yaml.safe_load(overlay.read_text())
        document["defaults"]["protections"]["allowed_isolation_hosts"] = base["defaults"]["protections"]["allowed_isolation_hosts"]
        if overlay.name.startswith("lab-validation"):
            # validation overlays may shorten ONLY the TTL (to the schema minimum of 60 s)
            for policy, original in zip(document["policies"], base["policies"]):
                assert policy["ttl_seconds"] == 60, overlay.name
                policy["ttl_seconds"] = original["ttl_seconds"]
        assert document == base, overlay.name


def test_validation_overlays_are_never_the_shipped_default():
    for line in (ROOT / ".env.example").read_text().splitlines():
        stripped = line.split("#", 1)[0].strip()
        assert not stripped.startswith("SOC_POLICY=lab-validation") and stripped != "SOC_MODE=enforce"
    for line in (ROOT / "Makefile").read_text().splitlines():
        if line.startswith(("SOC_POLICY", "SOC_MODE")):     # top-level defaults only, never a recipe line
            assert "lab-validation" not in line and "enforce" not in line, line


def test_infrastructure_addresses_are_protected_from_automatic_blocking():
    catalog = PolicyCatalog.from_path(ROOT / "response/policies/default.yaml")
    for address in ("172.16.50.1", "172.16.50.10", "172.16.50.11", "172.16.50.12", "172.16.50.254", "10.1.1.20"):
        with pytest.raises(Exception):
            catalog.protections.assert_target_allowed(action="block_ip", target_type="ip", target_value=address)
