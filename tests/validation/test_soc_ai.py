"""LIVE Path A verifiers for the SOC AI / response controls (LOG, AI, COR, RESP, SOC).

Run with ``make soc-ai-validate`` against a running stack that was started with
``make soc-ai-validate-up`` (enforce mode and the 60 s validation policy).  Each test maps
to one control in compliance/controls.yaml and records explicit evidence; a precondition
that is not met raises ``LabNotReady`` (evidence ERROR), never a pass.  The checks live in
``soc_live.py`` and are shared with the Path B audit and the offline in-process lab tests.

RESP-02 (endpoint isolation) has no Path A test by design: Path A has no Wazuh-agent
endpoint, so that control is scoped to Path B in the catalog.
"""

import os

import pytest

import soc_live

pytestmark = pytest.mark.skipif(
    os.environ.get("LAB_ENVIRONMENT", "local-containerlab") not in {"local-containerlab", "path-a"},
    reason="Path A verifiers",
)


@pytest.fixture(scope="session")
def soc_run():
    lab = soc_live.DockerLab(environment="path-a")
    return soc_live.Run(lab, timeouts=soc_live.Timeouts.from_environment())


def verify(control: str, soc_run, evidence) -> None:
    assertion, observed = soc_live.CHECKS[control](soc_run)
    evidence(control=control, assertion=assertion, observed=observed,
             enforcement_node="clab-companyxyz-fw-core,clab-companyxyz-fw-dmz" if control.startswith("RESP") else None)


def test_log01_multi_source_ingestion(soc_run, evidence):
    verify("LOG-01", soc_run, evidence)


def test_log02_ecs_normalization_preserves_raw(soc_run, evidence):
    verify("LOG-02", soc_run, evidence)


def test_log03_ingestion_failure_is_accounted(soc_run, evidence):
    verify("LOG-03", soc_run, evidence)


def test_ai01_feature_to_inference_event(soc_run, evidence):
    verify("AI-01", soc_run, evidence)


def test_ai02_model_provenance_is_bound_to_serving(soc_run, evidence):
    verify("AI-02", soc_run, evidence)


def test_ai03_schema_mismatch_is_rejected(soc_run, evidence):
    verify("AI-03", soc_run, evidence)


def test_ai04_five_detector_comparison_is_carried(soc_run, evidence):
    verify("AI-04", soc_run, evidence)


def test_cor01_anomaly_alone_never_requests_containment(soc_run, evidence):
    verify("COR-01", soc_run, evidence)


def test_resp01_firewall_containment_is_applied_and_verified(soc_run, evidence):
    verify("RESP-01", soc_run, evidence)


def test_resp03_safeguards_ttl_rate_limit_and_audit(soc_run, evidence):
    verify("RESP-03", soc_run, evidence)


def test_soc01_dashboards_show_the_attack_trace(soc_run, evidence):
    verify("SOC-01", soc_run, evidence)


def test_soc02_timing_is_derived_from_immutable_records(soc_run, evidence):
    verify("SOC-02", soc_run, evidence)


def test_soc03_audit_chain_links_alert_to_rollback(soc_run, evidence):
    verify("SOC-03", soc_run, evidence)
