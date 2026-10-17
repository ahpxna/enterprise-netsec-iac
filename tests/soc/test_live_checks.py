"""The live SOC verifiers, executed against an in-process lab that runs the real services.

Passing here shows that every check's queries, field names, ordering assumptions and
verdicts are consistent with the actual decision runner, orchestrator, audit export,
schemas and inference API.  It does NOT show that the Docker/VyOS lab behaves the same;
that is what ``make soc-ai-validate`` is for.
"""

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/validation"))

import soc_live as live  # noqa: E402
from soc_live import CHECKS, LabNotReady, Run, Timeouts  # noqa: E402

from live_lab import InProcessLab  # noqa: E402

RUN_ID = "0123456789"
FAST = Timeouts(ingest=60, decision=120, lifecycle=120, expiry=240, ai_pipeline=900, interval=5)


@pytest.fixture()
def lab(tmp_path):
    lab = InProcessLab(tmp_path)
    yield lab
    lab.close()


@pytest.fixture()
def run(lab):
    return Run(lab, run_id=RUN_ID, timeouts=FAST)


@pytest.fixture()
def ai_lab(tmp_path, approved_registry):
    lab = InProcessLab(tmp_path, registry=approved_registry)
    yield lab
    lab.close()


def verdict(control, run):
    assertion, observed = CHECKS[control](run)
    assert isinstance(assertion, str) and len(assertion) > 40
    json.dumps(observed)                    # evidence must be serialisable
    return observed


# ------------------------------------------------------------------ ingestion
def test_ingestion_controls_pass_against_the_pipeline_contract(run):
    log01 = verdict("LOG-01", run)
    assert set(log01["sources"]) == set(live.FIXTURE_DATASETS.values())
    verdict("LOG-02", run)
    log03 = verdict("LOG-03", run)
    assert log03["queue_type"] == "persisted" and log03["queued_events_during_outage"] == 1


def test_log02_fails_when_the_raw_document_is_modified(run):
    scenario = run.ingestion()
    scenario["firewall.log"]["raw"]["event"] = {"original": "tampered"}   # replaces the copy, not the store
    with pytest.raises(AssertionError, match="raw document differs"):
        live.check_log02(run)


def test_log01_fails_without_source_provenance(run, lab):
    scenario = run.ingestion()
    for fixture in live.FIXTURE_DATASETS:
        scenario[fixture]["normalized"] = {**scenario[fixture]["normalized"],
                                           "cxyz": {**scenario[fixture]["normalized"]["cxyz"],
                                                    "source_authentication": "unknown"}}
    with pytest.raises(AssertionError, match="provenance"):
        live.check_log01(run)


# ------------------------------------------------------------------ AI
def test_ai_controls_pass_with_an_approved_registry(ai_lab):
    run = Run(ai_lab, run_id=RUN_ID, timeouts=FAST)
    ai01 = verdict("AI-01", run)
    assert ai01["feature_schema"] == "network-window-v1" and ai01["model_id"] == "synthetic-if-live"
    ai02 = verdict("AI-02", run)
    assert ai02["metadata_sha256"] == ai_lab.registry.digest
    ai03 = verdict("AI-03", run)
    assert ai03["mismatch_status"] == 422 and ai03["unknown_feature_status"] == 422
    ai04 = verdict("AI-04", run)
    assert ai04["detectors"][0] == "static-rules" and len(ai04["detectors"]) == 5


def test_ai03_fails_if_a_schema_mismatch_is_accepted(ai_lab):
    run = Run(ai_lab, run_id=RUN_ID, timeouts=FAST)
    original = ai_lab.ai_request

    def lenient(method, path, body=None):
        if path == "/v1/infer":
            return 200, {"score": 0.1}
        return original(method, path, body)

    ai_lab.ai_request = lenient
    with pytest.raises(AssertionError, match="FEATURE_SCHEMA_MISMATCH"):
        live.check_ai03(run)


def test_ai02_fails_when_the_deployed_digest_differs(ai_lab):
    run = Run(ai_lab, run_id=RUN_ID, timeouts=FAST)
    ai_lab.deployed_metadata_digest = lambda: "f" * 64
    with pytest.raises(AssertionError, match="SOC_AI_METADATA_SHA256"):
        live.check_ai02(run)


def test_ai04_fails_when_the_registry_lacks_the_five_way_comparison(ai_lab, tmp_path):
    registry = tmp_path / "partial"
    registry.mkdir()
    for item in ai_lab.registry.path.iterdir():
        if not item.name.startswith("comparison"):
            (registry / item.name).write_bytes(item.read_bytes())
    ai_lab.registry_dir = lambda: registry
    with pytest.raises(AssertionError, match="five-detector comparison"):
        live.check_ai04(Run(ai_lab, run_id=RUN_ID, timeouts=FAST))


# ------------------------------------------------------------------ correlation + response
def test_response_controls_pass_against_the_real_decision_and_orchestrator(run, lab):
    cor01 = verdict("COR-01", run)
    assert cor01["corroborated_signals"][0] == "ai_anomaly" and "suricata_alert" in cor01["corroborated_signals"]
    resp01 = verdict("RESP-01", run)
    assert resp01["states"][:3] == ["REQUESTED", "APPLIED", "VERIFIED"] and resp01["adapter"] == ["nftables"]
    resp03 = verdict("RESP-03", run)
    assert resp03["seconds_to_expiry"] >= 58 and resp03["rate_limited_targets"]
    assert lab.firewall.ips == set()          # everything recovered, including rate-test targets
    soc02 = verdict("SOC-02", run)
    assert 0 <= soc02["mttd_seconds"] < 600 and soc02["containment_seconds"] >= soc02["mttd_seconds"]
    soc03 = verdict("SOC-03", run)
    assert soc03["states"][-1] == "EXPIRED" and soc03["policy"] == "COR-001"
    soc01 = verdict("SOC-01", run)
    assert set(soc01["dashboards"]) == set(live.DASHBOARDS) and all(v >= 1 for v in soc01["trace_counts"].values())


def test_protected_target_is_denied_and_never_reaches_the_firewall(run, lab):
    scenario = run.response()
    assert scenario["protected_decision"]["decision"]["outcome"] == "denied"
    assert scenario["protected_audits"] == [] and not any(scenario["protected_during"].values())


def test_cor01_fails_if_anomaly_only_evidence_produces_a_request(run, lab):
    scenario = run.response()
    fake_audit = deepcopy(scenario["chain"][0])
    fake_audit["target"]["value"] = run.solo
    scenario["solo_audits"] = [fake_audit]
    with pytest.raises(AssertionError, match="anomaly-only"):
        live.check_cor01(run)


def test_resp03_fails_if_the_firewall_never_recovers(run):
    scenario = run.response()
    scenario["blocked_after"] = {"fw-core": True, "fw-dmz": False}
    with pytest.raises(AssertionError, match="still blocked after expiry"):
        live.check_resp03(run)


def test_soc03_fails_when_a_transition_is_missing(run):
    scenario = run.response()
    scenario["chain"] = [e for e in scenario["chain"] if e["state"] != "APPLIED"]
    with pytest.raises(AssertionError, match="consecutive"):
        live.check_soc03(run)


def test_soc02_fails_when_timestamps_are_not_causal(run):
    scenario = run.response()
    for event in scenario["chain"]:
        if event["state"] == "REQUESTED":
            event["@timestamp"] = "2001-01-01T00:00:00Z"
    with pytest.raises(AssertionError, match="causally ordered"):
        live.check_soc02(run)


def test_enforcement_not_enabled_is_an_error_not_a_pass_or_fail(tmp_path):
    lab = InProcessLab(tmp_path, enforce=False)
    try:
        with pytest.raises(LabNotReady, match="enforce"):
            live.check_resp01(Run(lab, run_id=RUN_ID, timeouts=FAST))
    finally:
        lab.close()


def test_endpoint_isolation_is_verified_only_where_an_endpoint_exists(run, tmp_path):
    with pytest.raises(LabNotReady, match="no controlled endpoint"):
        live.check_resp02(run)
    private = tmp_path / "b"
    private.mkdir(mode=0o700)
    lab_b = InProcessLab(private, policy="lab-validation-path-b", with_endpoint=True)
    try:
        observed = verdict("RESP-02", Run(lab_b, run_id=RUN_ID, timeouts=FAST))
        assert observed["reachable_before"] and not observed["reachable_during"] and observed["reachable_after"]
        assert observed["states"][-1] == "EXPIRED"
    finally:
        lab_b.close()


def test_a_failed_shared_scenario_is_reported_by_every_later_check_not_rerun(run):
    # Regression (live run on Docker Desktop): the response scenario failed in COR-01, and RESP-01, RESP-03 and
    # SOC-01..03 each re-ran it, re-injected the same documents and failed on HTTP 409 instead of the cause.
    calls = []

    def scenario():
        calls.append(1)
        raise AssertionError("timed out waiting for REQUESTED -> APPLIED -> VERIFIED audit events")

    run._run_response = scenario
    for check in (live.check_cor01, live.check_resp01, live.check_soc03):
        with pytest.raises(AssertionError, match="REQUESTED -> APPLIED -> VERIFIED"):
            check(run)
    assert calls == [1]

    run.cache.clear()
    run._run_response = lambda: (_ for _ in ()).throw(LabNotReady("enforcement is not enabled"))
    for _ in range(2):
        with pytest.raises(LabNotReady, match="enforcement is not enabled"):
            live.check_resp01(run)
