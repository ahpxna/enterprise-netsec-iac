"""Ed25519 handoff: the orchestrator verifies but can never forge a command."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import stat

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from response.decision import DecisionEngine
from response.errors import CorrelationRejected
from response.orchestrator.audit import InMemoryAuditLedger
from response.orchestrator.engine import ResponseOrchestrator
from response.policy import PolicyCatalog
from response.signing import Ed25519CommandAuthenticator, generate_key_pair, load_private_key
from test_correlation_boundaries import NOW, evidence, policy_document

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def keys(tmp_path):
    private, public = generate_key_pair(tmp_path / "keys", "decision-2026-q3")
    signer = Ed25519CommandAuthenticator.signer(private, "decision-2026-q3")
    verifier = Ed25519CommandAuthenticator.verifier(tmp_path / "keys")
    return signer, verifier, private


def signed_command(signer):
    catalog = PolicyCatalog.from_mapping(policy_document())
    result = DecisionEngine(catalog, signer).evaluate(**evidence())
    return catalog, result.command


def test_signed_command_verifies_with_public_key_only(keys):
    signer, verifier, _ = keys
    _, command = signed_command(signer)
    verifier.verify(command, now=NOW)
    schema = json.loads((ROOT / "response/schemas/response-command-v1.schema.json").read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(command)
    assert len(command["authorization"]["signature"]) == 86


def test_verifier_cannot_sign(keys):
    _, verifier, _ = keys
    with pytest.raises(CorrelationRejected):
        verifier.sign({"authorization": {}})


@pytest.mark.parametrize("field,value", [("target", {"type": "ip", "value": "203.0.113.99"}),
                                         ("ttl_seconds", 60), ("action", "isolate_host")])
def test_any_tampered_field_invalidates_the_signature(keys, field, value):
    signer, verifier, _ = keys
    _, command = signed_command(signer)
    forged = deepcopy(command)
    forged[field] = value
    with pytest.raises(CorrelationRejected):
        verifier.verify(forged, now=NOW)


def test_expiry_unknown_key_and_malformed_signature_are_rejected(keys):
    signer, verifier, _ = keys
    _, command = signed_command(signer)
    with pytest.raises(CorrelationRejected):
        verifier.verify(command, now=NOW + timedelta(hours=1))
    unknown = deepcopy(command)
    unknown["authorization"]["key_id"] = "someone-else"
    with pytest.raises(CorrelationRejected):
        verifier.verify(unknown, now=NOW)
    short = deepcopy(command)
    short["authorization"]["signature"] = "A" * 43     # an HMAC-shaped value is not a valid signature here
    with pytest.raises(CorrelationRejected):
        verifier.verify(short, now=NOW)


def test_a_different_key_cannot_forge_a_command(keys, tmp_path):
    _, verifier, _ = keys
    private, _ = generate_key_pair(tmp_path / "other", "decision-2026-q3")
    attacker = Ed25519CommandAuthenticator.signer(private, "decision-2026-q3")
    _, command = signed_command(attacker)
    with pytest.raises(CorrelationRejected):
        verifier.verify(command, now=NOW)


def test_orchestrator_accepts_an_ed25519_command_end_to_end(keys):
    signer, verifier, _ = keys
    catalog, command = signed_command(signer)
    adapters = []
    for name, action in (("opnsense", "block_ip"), ("wazuh", "isolate_host")):
        adapter = type("A", (), {})()
        adapter.name, adapter.action = name, action
        adapters.append(adapter)
    engine = ResponseOrchestrator(catalog=catalog, authenticator=verifier, ledger=InMemoryAuditLedger(),
                                  adapters=adapters)
    assert engine.submit(command, now=NOW).accepted


def test_signing_key_file_must_be_private(keys):
    _, _, private = keys
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    private.chmod(0o640)
    with pytest.raises(ValueError):
        load_private_key(private)


def test_key_generation_never_overwrites(tmp_path):
    generate_key_pair(tmp_path, "k1")
    with pytest.raises(FileExistsError):
        generate_key_pair(tmp_path, "k1")
