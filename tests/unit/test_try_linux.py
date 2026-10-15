"""The one-command runner must say exactly where and why a stage failed, and never mask a failure."""

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import try_linux as tl  # noqa: E402

MAKE_FAILURE = """docker compose --profile soc up -d --wait elasticsearch
 Container x-elasticsearch-1  Error
dependency failed to start: container x-elasticsearch-1 is unhealthy
make: *** [Makefile:121: soc-up] Error 1
"""

PYTEST_FAILURE = """FAILED tests/soc/test_response_service.py::test_ttl_expiry_reverts_and_is_exported - AssertionError: assert 1 == 2
ERROR tests/soc/test_live_checks.py::test_x - RuntimeError: boom
2 failed, 10 passed in 3.2s
"""

TRACEBACK = """Traceback (most recent call last):
  File "/repo/scripts/soc_ai_preflight.py", line 41, in main
    raise SystemExit(msg)
  File "/repo/ai/models/isolation_forest.py", line 252, in load_approved_model
    raise ModelProvenanceError("metadata digest does not match the deployment approval")
ai.models.isolation_forest.ModelProvenanceError: metadata digest does not match the deployment approval
"""


def test_failure_points_name_the_make_target_pytest_test_and_python_frame():
    make = tl.extract_failure_points(MAKE_FAILURE)
    assert "make target 'soc-up' failed at Makefile:121 (exit 1)" in make
    pytest_points = tl.extract_failure_points(PYTEST_FAILURE)
    assert any("test_ttl_expiry_reverts_and_is_exported" in p and "assert 1 == 2" in p for p in pytest_points)
    frame = tl.extract_failure_points(TRACEBACK)
    assert any("isolation_forest.py:252 in load_approved_model" in p for p in frame)
    assert tl.extract_failure_points("all fine\nstill fine\n") == []
    assert tl.extract_failure_points("Error response from daemon: pull access denied for x")[0].startswith("Error response from daemon")


@pytest.mark.parametrize("text, expected", [
    ("permission denied while trying to connect to the Docker daemon socket", "docker' group"),
    ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", "not running"),
    ("failed to resolve source metadata for docker.io/library/debian: dial tcp: i/o timeout", "registry"),
    ("max virtual memory areas vm.max_map_count [65530] is too low", "vm.max_map_count"),
    ("Bind for 0.0.0.0:443 failed: port is already allocated", "port"),
    ("network cxyz_mgmt declared as external, but could not be found", "management network"),
    ("exec /usr/bin/x: exec format error", "architecture"),
    ("sudo: a password is required", "sudo"),
    ("SOC_AI_METADATA_SHA256 is unset: promote a model", "approved model"),
    ("FAILED tests/validation/test_hardening.py::test_ntp_authenticated", "NTS"),
])
def test_known_causes_are_recognised_with_a_concrete_fix(text, expected):
    hints = tl.match_hints(text)
    assert hints and any(expected.lower() in (cause + fix).lower() for cause, fix in hints), hints
    assert all(fix for _, fix in hints)


def test_unknown_output_gets_no_invented_diagnosis():
    assert tl.match_hints("everything is on fire in a way nobody has seen") == []


def args(*argv):
    return tl.parse_args(list(argv))


def fake_stages(tmp):
    py = sys.executable
    ok = lambda code="print('fine')": [tl.Cmd(argv=[py, "-c", code], label="python")]       # noqa: E731
    return [
        tl.Stage("a-ok", "first", "host", cmds=ok()),
        tl.Stage("b-bad", "second (fails like make)", "live", cmds=ok("import sys; print('make: *** [Makefile:7: images] Error 2'); "
                                                                        "print('Cannot connect to the Docker daemon'); sys.exit(2)"), needs=("a-ok",)),
        tl.Stage("c-blocked", "third needs second", "live", cmds=ok(), needs=("b-bad",)),
        tl.Stage("d-independent", "fourth is independent", "live", cmds=ok(), needs=("a-ok",)),
        tl.Stage("e-finding", "fifth is a failing test", "audit", cmds=ok("import sys; print('FAILED tests/x.py::test_y - assert 0'); sys.exit(1)"),
                 needs=("d-independent",), finding=True),
        tl.Stage("f-after-finding", "sixth still runs after a finding", "audit", cmds=ok(), needs=("e-finding",)),
        tl.Stage("g-python", "seventh is python-implemented", "audit", check=lambda ctx: (tl.WARN, "advisory note"), needs=("a-ok",)),
    ]


@pytest.fixture()
def run(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(tl, "ROOT", tmp_path)
    monkeypatch.setattr(tl, "VENV", tmp_path / ".venv")
    monkeypatch.setattr(tl, "build_stages", lambda ctx: fake_stages(tmp_path))

    def go(*argv):
        code = tl.main(["--quick", *argv])
        return code, capsys.readouterr().out
    return go


def test_failure_report_says_where_why_how_to_fix_and_how_to_retry(run, tmp_path):
    code, out = run("--no-viz")
    assert code == 1
    assert "FAILED  b-bad" in out and "make target 'images' failed at Makefile:7 (exit 2)" in out
    assert "cause   : the Docker daemon is not running" in out and "fix     : sudo systemctl enable --now docker" in out
    assert "re-run  : scripts/try-on-linux.sh --only b-bad --quick" in out
    logs = sorted((tmp_path / "logs" / "try-linux").glob("*"))[-1]
    log = (logs / "02-b-bad.log").read_text()
    assert "Cannot connect to the Docker daemon" in log and "[runner] exit code 2" in log and log.startswith("\n$ ")
    report = (logs / "report.md").read_text()
    assert "## b-bad: FAIL" in report and "sudo systemctl enable --now docker" in report
    data = json.loads((logs / "report.json").read_text())
    assert {r["stage"]: r["status"] for r in data["results"]} == {
        "a-ok": "PASS", "b-bad": "FAIL", "c-blocked": "BLOCKED", "d-independent": "PASS", "e-finding": "FAIL", "f-after-finding": "PASS", "g-python": "WARN"}


def test_blocked_stages_name_their_blocker_and_findings_do_not_block(run):
    _, out = run("--no-viz")
    assert "BLOCKED by b-bad" in out
    assert "fifth is a failing test" in out and "pytest failed: tests/x.py::test_y - assert 0" in out
    summary = out.split("=" * 78)[1]
    line = next(row for row in summary.splitlines() if "f-after-finding" in row)
    assert line.strip().startswith("PASS")
    assert "2 stage(s) failed: b-bad, e-finding" in out


def test_only_from_skip_and_fail_fast_select_exactly_the_requested_stages(run):
    code, out = run("--only", "a-ok,d-independent")
    assert code == 0 and "ALL STAGES PASSED" in out and "b-bad" not in out.split("=" * 78)[1]
    code, out = run("--from", "d-independent", "--skip", "e-finding")
    assert "a-ok" not in out.split("=" * 78)[1] and "e-finding" not in out.split("=" * 78)[1] and code == 0
    code, out = run("--fail-fast")
    summary = out.split("=" * 78)[1]
    assert code == 1 and "d-independent" not in summary                    # stopped right after b-bad
    with pytest.raises(SystemExit, match="unknown stage"):
        run("--only", "nope")


def test_dry_run_executes_nothing(run, tmp_path):
    marker = tmp_path / "touched"
    stages = [tl.Stage("t", "would touch a file", "host", cmds=[tl.Cmd(argv=[sys.executable, "-c", f"open({str(marker)!r}, 'w')"])])]
    tl.build_stages = lambda ctx: stages
    code, out = run("--dry-run", "--no-viz")
    assert code == 0 and not marker.exists() and "DRY RUN" in out


def test_timeout_kills_the_command_and_reports_it(run, tmp_path):
    stages = [tl.Stage("slow", "sleeps forever", "host", cmds=[tl.Cmd(argv=[sys.executable, "-c", "import time; time.sleep(60)"], timeout=2)])]
    tl.build_stages = lambda ctx: stages
    code, out = run("--no-viz")
    assert code == 1 and "timed out after 2s" in out


def test_missing_binary_is_reported_as_command_not_found(run):
    tl.build_stages = lambda ctx: [tl.Stage("x", "needs a tool", "host", cmds=[tl.Cmd(argv=["definitely-not-installed-tool"])])]
    code, out = run("--no-viz")
    assert code == 1 and "command not found" in out


def test_stage_catalogue_is_consistent():
    ctx = tl.Ctx(args(), ROOT / "logs" / "x")
    stages = tl.build_stages(ctx)
    ids = [s.id for s in stages]
    assert len(ids) == len(set(ids))
    for stage in stages:
        assert set(stage.needs) <= set(ids), stage.id
        assert stage.cmds or stage.check, stage.id
        assert ids.index(stage.id) > max([ids.index(n) for n in stage.needs] or [-1]), f"{stage.id} runs before a dependency"
        assert set(stage.modes) <= {"full", "quick", "offline"}
    offline = [s.id for s in stages if "offline" in s.modes]
    assert offline == ["host-os", "deps-python", "offline-static", "offline-tests", "viz-start"]
    # the fabric is the only thing --quick leaves out of the live chain
    assert {s.id for s in stages if "full" in s.modes} - {s.id for s in stages if "quick" in s.modes} >= {"fabric-up", "security-up", "configure", "soc-validate"}


def test_every_make_target_the_runner_calls_exists():
    makefile = (ROOT / "Makefile").read_text()
    targets = set(__import__("re").findall(r"^([a-zA-Z0-9_-]+):", makefile, __import__("re").M))
    ctx = tl.Ctx(args(), ROOT / "logs" / "x")
    for stage in tl.build_stages(ctx):
        cmds = stage.cmds(ctx) if callable(stage.cmds) else stage.cmds
        for cmd in cmds:
            if cmd.argv and cmd.argv[0] == "make":
                assert cmd.argv[1] in targets, (stage.id, cmd.argv)


def test_every_repo_script_the_runner_calls_exists():
    ctx = tl.Ctx(args(), ROOT / "logs" / "x")
    for stage in tl.build_stages(ctx):
        for cmd in (stage.cmds(ctx) if callable(stage.cmds) else stage.cmds):
            for item in cmd.argv or []:
                if str(item).startswith(("scripts/", "compliance/")) and str(item).endswith(".py"):
                    assert (ROOT / item).is_file(), (stage.id, item)


def test_host_stage_refuses_a_non_linux_machine_outside_offline_mode(monkeypatch):
    ctx = tl.Ctx(args("--quick"), ROOT / "logs" / "x")
    monkeypatch.setattr(ctx, "linux", False)
    status, message = tl.check_host(ctx)
    assert status == tl.FAIL and "Linux" in message and "--offline" in message
    assert tl.check_host(tl.Ctx(args("--offline"), ROOT / "logs" / "x"))[0] == tl.PASS


def test_shell_wrapper_is_syntactically_valid_and_delegates():
    import subprocess

    wrapper = ROOT / "scripts" / "try-on-linux.sh"
    assert subprocess.run(["bash", "-n", str(wrapper)]).returncode == 0
    text = wrapper.read_text()
    assert "try_linux.py" in text and text.startswith("#!/usr/bin/env bash") and wrapper.stat().st_mode & 0o111
