#!/usr/bin/env python3
"""One command to install, build, run and test the whole lab on a Linux machine.

    ./scripts/try-on-linux.sh                # everything: dependencies, offline gates, fabric, security plane, SOC/AI, validation
    ./scripts/try-on-linux.sh --quick        # no containerlab fabric: offline gates + SOC analytics + AI/response (observe mode)
    ./scripts/try-on-linux.sh --offline      # only the checks that need no containers (also works on macOS)
    ./scripts/try-on-linux.sh --list         # print the stages
    ./scripts/try-on-linux.sh --only soc-up  # re-run one stage (and nothing else)

Every stage is one or more commands whose output goes to ``logs/try-linux/<timestamp>/NN-<stage>.log``.
When a stage fails the runner says exactly WHERE (stage, command, failing make target and line,
failing pytest test or Python frame), WHY it most likely failed (a hint table of the usual causes: Docker
permissions, unreachable registry, ``vm.max_map_count``, port conflicts, wrong architecture ...), the
container logs that matter, the log file, and the command that re-runs just that stage. Stages that
depend on a failed one are reported as BLOCKED instead of failing again for the same reason.

The runner is standard-library only so it can start before any dependency is installed.  It never
deletes data; ``--teardown`` stops the stack but keeps volumes unless ``--purge`` is also given.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable, Sequence

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = "scripts/try-on-linux.sh"
VENV = ROOT / ".venv"
STATE = ROOT / ".cxyz-state"
VIZ_PORT_DEFAULT = 8088
MIN_PYTHON = (3, 11)

PASS, FAIL, SKIP, BLOCKED, WARN = "PASS", "FAIL", "SKIP", "BLOCKED", "WARN"
COLORS = {PASS: "32", FAIL: "31", SKIP: "90", BLOCKED: "33", WARN: "33"}
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


# --------------------------------------------------------------------------------------- hints
# (regex over the command output, cause, fix).  First matches win; a stage may add its own first.
Hint = tuple[str, str, str]
GLOBAL_HINTS: list[Hint] = [
    (r"permission denied while trying to connect to the (Docker|docker) daemon|got permission denied.*docker\.sock",
     "your user cannot talk to the Docker daemon (not in the 'docker' group yet)",
     "sudo usermod -aG docker $USER && newgrp docker   # then re-run this script"),
    (r"Cannot connect to the Docker daemon|Is the docker daemon running|docker.sock: connect: no such file",
     "the Docker daemon is not running", "sudo systemctl enable --now docker"),
    (r"no space left on device", "the disk is full (Docker images/volumes are large)",
     "df -h /var/lib/docker .   # free space, e.g. `docker system prune` (review what it removes first)"),
    (r"toomanyrequests|pull rate limit|You have reached your .*pull rate limit",
     "Docker Hub rate limit reached", "docker login   # an authenticated pull has a much higher limit"),
    (r"TLS handshake timeout|i/o timeout|no such host|Temporary failure in name resolution|dial tcp [^\n]*(timeout|refused)|"
     r"failed to resolve source metadata|Get \"https://[^\"]*\": (dial|net/http)|connection reset by peer|Could not resolve host",
     "the machine cannot reach a container registry / package mirror (DNS, proxy or firewall)",
     "docker pull hello-world   # if this fails too, fix DNS/proxy (/etc/docker/daemon.json, HTTPS_PROXY) first"),
    (r"max virtual memory areas vm\.max_map_count|vm\.max_map_count \[\d+\] is too low",
     "Elasticsearch/Wazuh indexer need a larger vm.max_map_count", "sudo sysctl -w vm.max_map_count=262144"),
    (r"address already in use|port is already allocated|bind: address already in use",
     "a host port needed by the lab is already taken", "sudo ss -ltnp | grep -E ':(5601|5602|443|80|51820|8088)\\b'   # stop the owner or change the port"),
    (r"containerlab: command not found|sudo: containerlab: command not found",
     "containerlab is not installed (or not on root's PATH)", "bash -c \"$(curl -sL https://get.containerlab.dev)\""),
    (r"exec format error|no matching manifest for linux/(arm64|arm)|platform \(linux/amd64\) does not match",
     "CPU architecture mismatch: the pinned FRR image is linux/amd64 only", "use an x86-64 Linux host (Path A is not portable to arm64)"),
    (r"network cxyz_mgmt declared as external|network cxyz_mgmt .* not found|network .*cxyz_mgmt.* not found",
     "the management network does not exist yet (the containerlab fabric creates it)", "run the fabric stage first: ./scripts/try-on-linux.sh --only fabric-up"),
    (r"network cxyz_dc declared as external|network cxyz_dc .* not found",
     "the shared DC bridge network does not exist", "./scripts/try-on-linux.sh --only dc-network"),
    (r"sudo: a password is required|sudo: no tty present|sudo: a terminal is required",
     "sudo needs a password and this shell cannot prompt for it", "run from an interactive terminal, or `sudo -v` first"),
    (r"ModuleNotFoundError: No module named '(yaml|pytest|jsonschema|fastapi|sklearn|numpy)'",
     "a Python dependency is missing from the virtual environment", "./scripts/try-on-linux.sh --only deps-python"),
    (r"ansible-playbook: command not found|ansible: command not found",
     "Ansible is not on PATH in the login shell the Makefile uses", "./scripts/try-on-linux.sh --only deps-python   # links it into ~/.local/bin"),
    (r"SOC_AI_METADATA_SHA256 is unset|does not match ai/registry/active/metadata.json|metadata.json is missing",
     "no approved model digest in .env", "./scripts/try-on-linux.sh --only demo-model"),
    (r"Wazuh PKI directory is missing|missing docker/wazuh/certs", "the Wazuh certificates were not generated", "./scripts/try-on-linux.sh --only wazuh-config"),
    (r"is unhealthy|dependency failed to start|container .* exited \((1|137|139)\)",
     "a container started but never became healthy", "see the container logs captured below (the same lines are in the log file)"),
    (r"test_ntp_authenticated|TIME-01|chronyc|NTS", "TIME-01 needs the HOST clock disciplined by authenticated NTS",
     "configure chrony from host/chrony-cxyz.sources.example, then `make host-time-check`"),
    (r"nft: command not found|nftables.*not found", "nftables is not installed on the host", "sudo apt-get install -y nftables"),
    (r"Operation not permitted.*sysctl|sysctl: permission denied", "sysctl is not writable here (container/WSL/restricted host)", "set the sysctl on the real host kernel"),
]

DIAGNOSTICS = {
    "images": [["docker", "version"], ["docker", "info", "--format", "{{.ServerVersion}} root={{.DockerRootDir}} driver={{.Driver}}"]],
    "soc-up": [["docker", "compose", "--profile", "soc", "ps", "-a"],
               ["docker", "compose", "--profile", "soc", "logs", "--tail", "60", "elasticsearch", "kibana", "logstash"]],
    "soc-smoke": [["docker", "compose", "--profile", "soc", "logs", "--tail", "60", "logstash", "elasticsearch"]],
    "soc-ai-up": [["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.path-a.yml", "--profile", "soc", "--profile", "soc-ai", "ps", "-a"],
                  ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.path-a.yml", "--profile", "soc", "--profile", "soc-ai", "logs", "--tail", "60",
                   "soc-service-init", "soc-ai-api", "soc-response", "soc-decision", "soc-enrichment-worker", "soc-feature-worker"]],
    "fabric-up": [["containerlab", "inspect", "-t", "clab/companyxyz.clab.yml"], ["docker", "ps", "-a", "--filter", "name=clab-", "--format", "{{.Names}}\t{{.Status}}"]],
    "fabric-verify": [["docker", "ps", "-a", "--filter", "name=clab-", "--format", "{{.Names}}\t{{.Status}}"]],
    "security-up": [["docker", "compose", "--profile", "siem", "--profile", "ids", "--profile", "ztna", "--profile", "dmz", "ps", "-a"],
                    ["docker", "compose", "--profile", "siem", "logs", "--tail", "40", "wazuh.manager", "wazuh-indexer"]],
}


# --------------------------------------------------------------------------------------- model
@dataclasses.dataclass
class Cmd:
    argv: Sequence[str] | None = None            # exec form (preferred)
    shell: str | None = None                     # only for fixed pipelines written in this file
    sudo: bool = False
    env: dict[str, str] = dataclasses.field(default_factory=dict)
    timeout: int = 1800
    label: str = ""
    ok_codes: tuple[int, ...] = (0,)
    interactive: bool = False                    # needs the terminal (sudo password prompt)

    def display(self) -> str:
        text = self.shell if self.shell is not None else " ".join(shlex.quote(a) for a in (self.argv or []))
        return ("sudo " if self.sudo else "") + text


@dataclasses.dataclass
class Stage:
    id: str
    title: str
    group: str                                   # host | deps | offline | viz | live | audit
    cmds: list[Cmd] | Callable[["Ctx"], list[Cmd]] = dataclasses.field(default_factory=list)
    check: Callable[["Ctx"], tuple[str, str]] | None = None   # python-implemented stage -> (status, message)
    needs: tuple[str, ...] = ()
    modes: tuple[str, ...] = ("full", "quick", "offline")
    hints: list[Hint] = dataclasses.field(default_factory=list)
    warn_only: bool = False                      # a failure is a finding, not a blocker
    finding: bool = False                        # failures are control findings (tests), not harness errors


@dataclasses.dataclass
class Result:
    stage: str
    title: str
    status: str
    seconds: float = 0.0
    message: str = ""
    command: str = ""
    rc: int | None = None
    log: str = ""
    points: list[str] = dataclasses.field(default_factory=list)
    hints: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    diagnostics: str = ""
    tail: list[str] = dataclasses.field(default_factory=list)


class Ctx:
    def __init__(self, args: argparse.Namespace, logdir: pathlib.Path) -> None:
        self.args, self.logdir = args, logdir
        self.mode = "offline" if args.offline else "quick" if args.quick else "full"
        self.root = ROOT
        self.is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        self.linux = platform.system() == "Linux"
        self.results: dict[str, Result] = {}
        self.facts: dict[str, str] = {}
        self.viz_url: str | None = None

    @property
    def py(self) -> str:
        return str(VENV / "bin" / "python") if (VENV / "bin" / "python").exists() else sys.executable

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        local = pathlib.Path.home() / ".local" / "bin"
        env["PATH"] = os.pathsep.join([str(VENV / "bin"), str(local), env.get("PATH", "")])
        env["VIRTUAL_ENV"] = str(VENV)
        env["PYTHONUNBUFFERED"] = "1"
        env.setdefault("SOC_PATH", "path-a")
        env["COMPOSE_PROGRESS"] = "plain"
        env["DOCKER_BUILDKIT"] = "1"
        env["BUILDKIT_PROGRESS"] = "plain"
        return env


# --------------------------------------------------------------------------------------- analysis
MAKE_ERR = re.compile(r"make(?:\[\d+\])?: \*\*\* \[(?P<file>[^:\]]+):(?P<line>\d+): (?P<target>[^\]]+)\] Error (?P<rc>\d+)")
PYTEST_FAIL = re.compile(r"^(FAILED|ERROR) (\S+?)(?: - (.*))?$")
TRACE_FRAME = re.compile(r'^\s*File "(?P<file>[^"]+)", line (?P<line>\d+), in (?P<fn>\S+)')
GENERIC_ERR = re.compile(r"(^|\s)(ERROR|Error|error|FATAL|fatal|failed|Failed|FAILED|denied|refused|not found|No such file|cannot|Cannot)\b[:\s]")


def extract_failure_points(text: str, limit: int = 8) -> list[str]:
    """The lines that say WHERE it broke: failing make target, pytest test, last Python frame, first error line."""

    lines = text.splitlines()
    points: list[str] = []
    for m in MAKE_ERR.finditer(text):
        points.append(f"make target '{m['target']}' failed at {m['file']}:{m['line']} (exit {m['rc']})")
    for line in lines:
        m = PYTEST_FAIL.match(line.strip())
        if m:
            points.append(f"pytest {m[1].lower()}: {m[2]}" + (f" - {m[3][:160]}" if m[3] else ""))
    frames = [(i, TRACE_FRAME.match(line)) for i, line in enumerate(lines)]
    frames = [(i, m) for i, m in frames if m]
    if frames:
        i, m = frames[-1]
        exception = next((lines[j].strip() for j in range(i + 1, min(i + 8, len(lines))) if re.match(r"^[A-Za-z_.]+(Error|Exception|Exit)\b", lines[j].strip())), "")
        points.append(f"python: {pathlib.Path(m['file']).name}:{m['line']} in {m['fn']}" + (f" -> {exception[:160]}" if exception else ""))
    for line in lines:
        if "Error response from daemon" in line or line.startswith(("E: ", "ERROR: ", "Error: ", "error: ")):
            points.append(line.strip()[:200])
    if not points:
        for line in reversed(lines):
            if GENERIC_ERR.search(line) and line.strip():
                points.append(line.strip()[:200])
                break
    seen: list[str] = []
    for p in points:
        if p not in seen:
            seen.append(p)
    return seen[:limit]


def match_hints(text: str, extra: Iterable[Hint] = ()) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for pattern, cause, fix in [*extra, *GLOBAL_HINTS]:
        if re.search(pattern, text, re.I):
            if (cause, fix) not in found:
                found.append((cause, fix))
    return found[:3]


# --------------------------------------------------------------------------------------- execution
class Runner:
    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self._sudo_keepalive: threading.Event | None = None

    # -- low level
    def run_cmd(self, cmd: Cmd, logfile: pathlib.Path, env: dict[str, str]) -> tuple[int, str]:
        argv = list(cmd.argv) if cmd.argv is not None else ["bash", "-o", "pipefail", "-c", cmd.shell or "true"]
        if cmd.sudo and not self.ctx.is_root:
            argv = ["sudo", "-E", *argv]
        full_env = {**env, **cmd.env}
        header = f"\n$ {cmd.display()}\n"
        with open(logfile, "a", encoding="utf-8", errors="replace") as log:
            log.write(header)
            log.flush()
            if self.ctx.args.dry_run:
                log.write("(dry run: not executed)\n")
                return 0, ""
            started = time.monotonic()
            try:
                # Commands that may call sudo keep this terminal (its sudo ticket) and its process group; the rest get their own
                # session so a timeout can kill the whole tree.
                proc = subprocess.Popen(argv, cwd=self.ctx.root, env=full_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        stdin=None if cmd.interactive else subprocess.DEVNULL, text=True, errors="replace",
                                        start_new_session=not cmd.interactive)
            except FileNotFoundError as exc:
                log.write(f"{argv[0]}: command not found ({exc})\n")
                return 127, f"{argv[0]}: command not found"
            collected: list[str] = []
            last = {"line": "", "at": time.monotonic()}

            def pump() -> None:
                assert proc.stdout is not None
                for line in proc.stdout:
                    log.write(line)
                    log.flush()
                    collected.append(line)
                    if len(collected) > 4000:
                        del collected[:1000]
                    last["line"], last["at"] = line.rstrip(), time.monotonic()
                    if self.ctx.args.verbose:
                        sys.stdout.write("    | " + line)

            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            rc: int | None = None
            heartbeat = time.monotonic()
            while rc is None:
                try:
                    rc = proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    elapsed = time.monotonic() - started
                    if elapsed > cmd.timeout:
                        self.kill_tree(proc, cmd)
                        time.sleep(3)
                        if proc.poll() is None:
                            self.kill_tree(proc, cmd, hard=True)
                        log.write(f"\n[runner] killed after {cmd.timeout}s timeout\n")
                        reader.join(2)
                        return 124, "".join(collected) + f"\ncommand timed out after {cmd.timeout}s"
                    if not self.ctx.args.verbose and time.monotonic() - heartbeat > 20:
                        heartbeat = time.monotonic()
                        snippet = (last["line"][:70] + "…") if len(last["line"]) > 70 else last["line"]
                        sys.stdout.write(paint(f"      … {int(elapsed)}s  {snippet}\n", "90"))
                        sys.stdout.flush()
            reader.join(5)
            output = "".join(collected)
            if rc not in cmd.ok_codes:
                log.write(f"\n[runner] exit code {rc}\n")
            return (0 if rc in cmd.ok_codes else rc), output

    @staticmethod
    def kill_tree(proc: "subprocess.Popen[str]", cmd: Cmd, hard: bool = False) -> None:
        sig = signal.SIGKILL if hard else signal.SIGTERM
        try:
            if cmd.interactive:
                subprocess.run(["pkill", f"-{int(sig)}", "-P", str(proc.pid)], check=False)
                proc.send_signal(sig)
            else:
                os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def keep_sudo_alive(self) -> None:
        if self.ctx.is_root or shutil.which("sudo") is None or self._sudo_keepalive is not None:
            return
        stop = threading.Event()
        self._sudo_keepalive = stop

        def loop() -> None:
            while not stop.wait(50):
                subprocess.run(["sudo", "-n", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

        threading.Thread(target=loop, daemon=True).start()

    # -- stage level
    def run_stage(self, stage: Stage, index: int, total: int) -> Result:
        ctx = self.ctx
        logfile = ctx.logdir / f"{index:02d}-{stage.id}.log"
        banner = f"[{index:02d}/{total:02d}] {stage.title}"
        print(paint("▶ ", "36") + banner, flush=True)
        started = time.monotonic()
        result = Result(stage=stage.id, title=stage.title, status=PASS, log=str(logfile.relative_to(ctx.root)))
        try:
            if stage.check is not None:
                status, message = stage.check(ctx)
                result.status, result.message = status, message
                if stage.id == "host-sudo" and status == PASS:
                    self.keep_sudo_alive()
                logfile.write_text(f"{stage.id}: {status} {message}\n", encoding="utf-8")
                if status == FAIL:
                    result.points = [message]
                    result.hints = match_hints(message, stage.hints)
            else:
                cmds = stage.cmds(ctx) if callable(stage.cmds) else stage.cmds
                if not cmds:
                    result.status, result.message = SKIP, "nothing to do"
                for cmd in cmds:
                    if cmd.interactive:
                        self.keep_sudo_alive()
                    rc, output = self.run_cmd(cmd, logfile, ctx.env())
                    if rc != 0:
                        result.status, result.rc, result.command = FAIL, rc, cmd.display()
                        text = output
                        result.points = extract_failure_points(text)
                        result.hints = match_hints(text, stage.hints)
                        result.tail = [line for line in text.splitlines() if line.strip()][-14:]
                        result.diagnostics = self.diagnose(stage, logfile)
                        break
        except Exception as exc:  # the runner itself must never hide a problem behind a traceback
            result.status, result.message = FAIL, f"runner error: {type(exc).__name__}: {exc}"
            result.points = [result.message]
        result.seconds = time.monotonic() - started
        if result.status == FAIL and (stage.warn_only or stage.finding):
            result.status = WARN if stage.warn_only else FAIL
        return result

    def diagnose(self, stage: Stage, logfile: pathlib.Path) -> str:
        if self.ctx.args.dry_run or shutil.which("docker") is None:
            return ""
        out = []
        for argv in DIAGNOSTICS.get(stage.id, []):
            if shutil.which(argv[0]) is None:
                continue
            try:
                done = subprocess.run(argv, cwd=self.ctx.root, env=self.ctx.env(), capture_output=True, text=True, timeout=25, check=False)
                text = (done.stdout + done.stderr).strip()
            except (subprocess.TimeoutExpired, OSError) as exc:
                text = f"({exc})"
            out.append("$ " + " ".join(argv) + "\n" + text)
        joined = "\n\n".join(out)
        if joined:
            with open(logfile, "a", encoding="utf-8", errors="replace") as log:
                log.write("\n[diagnostics on failure]\n" + joined + "\n")
        return joined


# --------------------------------------------------------------------------------------- stage helpers
def first_existing(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def os_release() -> dict[str, str]:
    path = pathlib.Path("/etc/os-release")
    out: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            key, _, value = line.partition("=")
            out[key] = value.strip().strip('"')
    return out


def family(ctx: Ctx) -> str:
    rel = os_release()
    ids = f"{rel.get('ID', '')} {rel.get('ID_LIKE', '')}".lower()
    if "debian" in ids or "ubuntu" in ids:
        return "debian"
    if any(x in ids for x in ("fedora", "rhel", "centos", "rocky", "almalinux")):
        return "redhat"
    return "other"


def check_host(ctx: Ctx) -> tuple[str, str]:
    if ctx.mode == "offline":
        ctx.facts["os"] = f"{platform.system()} {platform.release()} {platform.machine()}"
        return PASS, f"offline mode runs anywhere ({ctx.facts['os']})"
    if not ctx.linux:
        return FAIL, f"this stage needs a Linux host (found {platform.system()}). Use --offline here, or run on an x86-64 Linux machine."
    problems, notes = [], []
    rel = os_release()
    ctx.facts["os"] = f"{rel.get('PRETTY_NAME', 'Linux')} / kernel {platform.release()} / {platform.machine()}"
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"}:
        if ctx.mode == "full":
            problems.append(f"CPU is {machine}: the pinned FRR fabric image is linux/amd64 only. Use --quick (no fabric) or an x86-64 host.")
        else:
            notes.append(f"CPU is {machine}; some images may be emulated")
    try:
        mem_kb = int(next(line.split()[1] for line in pathlib.Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:")))
        gb = mem_kb / 1024 / 1024
        ctx.facts["memory"] = f"{gb:.1f} GiB"
        need = 12 if ctx.mode == "full" else 8
        if gb < need - 0.5:
            problems.append(f"only {gb:.1f} GiB RAM; {need} GiB are needed for this mode (Wazuh indexer + Elasticsearch are heavy)")
    except (OSError, StopIteration, ValueError):
        notes.append("could not read /proc/meminfo")
    free = shutil.disk_usage(ctx.root).free / 1024 ** 3
    ctx.facts["disk free"] = f"{free:.0f} GiB"
    if free < 25:
        problems.append(f"only {free:.0f} GiB free in {ctx.root}; at least 25 GiB are needed for images and volumes")
    if not family(ctx) in {"debian", "redhat"}:
        notes.append("unrecognised distribution: automatic package installation is limited to Debian/Ubuntu and Fedora/RHEL families")
    if not pathlib.Path("/sys/fs/cgroup").exists():
        problems.append("no cgroup filesystem: containers cannot run here")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, "; ".join([ctx.facts["os"], f"{ctx.facts.get('memory', '?')} RAM", f"{ctx.facts['disk free']} free", *notes])


def check_sudo(ctx: Ctx) -> tuple[str, str]:
    if ctx.is_root:
        return PASS, "running as root"
    if shutil.which("sudo") is None:
        return FAIL, "sudo is not installed and you are not root (the lab needs root for containerlab, sysctl and package installs)"
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        return PASS, "passwordless sudo"
    if not sys.stdin.isatty():
        return FAIL, "sudo needs a password and there is no terminal to ask for it: run `sudo -v` first, or run from an interactive shell"
    print("   sudo password needed once (kept alive while the script runs):", flush=True)
    return (PASS, "sudo authenticated") if subprocess.run(["sudo", "-v"]).returncode == 0 else (FAIL, "sudo authentication failed")


def pkg_install(ctx: Ctx) -> list[Cmd]:
    fam = family(ctx)
    if ctx.args.no_install:
        return []
    want = ["ca-certificates", "curl", "git", "make", "jq", "openssl", "iproute2", "python3", "python3-venv", "python3-pip", "nftables"]
    if fam == "debian":
        missing = [p for p in want]
        return [Cmd(argv=["apt-get", "update", "-y"], sudo=True, env={"DEBIAN_FRONTEND": "noninteractive"}, label="apt update", interactive=True),
                Cmd(argv=["apt-get", "install", "-y", "--no-install-recommends", *missing], sudo=True,
                    env={"DEBIAN_FRONTEND": "noninteractive"}, label="apt install base packages", interactive=True)]
    if fam == "redhat":
        names = ["ca-certificates", "curl", "git", "make", "jq", "openssl", "iproute", "python3", "python3-pip", "nftables"]
        return [Cmd(argv=["dnf", "install", "-y", *names], sudo=True, label="dnf install base packages", interactive=True)]
    return [Cmd(shell="echo 'unsupported distribution: install curl git make jq openssl iproute2 python3 python3-venv nftables yourself' >&2; exit 3", label="unsupported")]


def docker_install(ctx: Ctx) -> list[Cmd]:
    if ctx.args.no_install:
        return []
    have_docker = shutil.which("docker") is not None
    compose_ok = have_docker and subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0
    cmds: list[Cmd] = []
    if not (have_docker and compose_ok):
        rel = os_release()
        if family(ctx) == "debian" and rel.get("ID") == "ubuntu" and rel.get("VERSION_ID", "0") >= "24.04":
            cmds.append(Cmd(argv=["apt-get", "install", "-y", "docker.io", "docker-compose-v2"], sudo=True, env={"DEBIAN_FRONTEND": "noninteractive"},
                            label="install Docker from the distribution", interactive=True))
        else:
            cmds.append(Cmd(shell="d=$(mktemp -d) && curl -fsSL https://get.docker.com -o \"$d/get-docker.sh\" && sudo sh \"$d/get-docker.sh\"",
                            label="install Docker with the official convenience script", interactive=True, timeout=900))
    cmds.append(Cmd(argv=["systemctl", "enable", "--now", "docker"], sudo=True, label="start the Docker daemon", interactive=True))
    return cmds


def check_docker_access(ctx: Ctx) -> tuple[str, str]:
    """Docker usable by this user? If only group membership is missing, add it and re-exec under `sg docker`."""

    if shutil.which("docker") is None:
        return FAIL, "docker is not installed (re-run without --no-install)"
    done = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True)
    if done.returncode == 0:
        compose = subprocess.run(["docker", "compose", "version", "--short"], capture_output=True, text=True)
        if compose.returncode != 0:
            return FAIL, "Docker Compose v2 plugin is missing ('docker compose version' failed)"
        ctx.facts["docker"] = f"{done.stdout.strip()} (compose {compose.stdout.strip()})"
        return PASS, f"Docker {done.stdout.strip()}, Compose {compose.stdout.strip()}"
    err = (done.stdout + done.stderr).strip()
    if re.search(r"permission denied", err, re.I) and not ctx.is_root:
        if os.environ.get("CXYZ_SG_DONE"):
            return FAIL, "still no permission on the Docker socket even after joining the 'docker' group: log out and back in, then re-run"
        subprocess.run(["sudo", "usermod", "-aG", "docker", os.environ.get("USER", "")], check=False)
        print("   added you to the 'docker' group; re-running this script inside that group …", flush=True)
        argv = ["sg", "docker", "-c", " ".join(shlex.quote(a) for a in [sys.executable, str(ROOT / "scripts/try_linux.py"), *sys.argv[1:], "--from", "deps-docker"])]
        os.execvpe("sg", argv, {**os.environ, "CXYZ_SG_DONE": "1"})
    return FAIL, "the Docker daemon is not usable: " + (err.splitlines()[0][:200] if err else "docker info failed")


def find_python() -> str | None:
    for name in ("python3.12", "python3.13", "python3.11"):   # 3.12 is what CI runs; newer/older only if absent
        found = shutil.which(name)
        if found:
            return found
    current = shutil.which("python3")
    if current:
        out = subprocess.run([current, "-c", "import sys;print(sys.version_info[:2]>=%s)" % (MIN_PYTHON,)], capture_output=True, text=True)
        if out.stdout.strip() == "True":
            return current
    return None


def python_env_cmds(ctx: Ctx) -> list[Cmd]:
    if ctx.args.no_install:
        return [Cmd(argv=[ctx.py, "-c", "import yaml, pytest, jsonschema, fastapi, sklearn; print('dependencies already present')"], label="verify dependencies")]
    python = find_python()
    cmds: list[Cmd] = []
    if not (VENV / "bin" / "python").exists():
        if python:
            cmds.append(Cmd(argv=[python, "-m", "venv", str(VENV)], label="create .venv"))
        else:
            cmds.append(Cmd(shell=f"python3 -m pip install --user --break-system-packages uv >/dev/null 2>&1 || python3 -m pip install --user uv; "
                                  f"~/.local/bin/uv venv --python 3.12 {shlex.quote(str(VENV))}", label="create .venv with uv-managed Python 3.12", timeout=900))
    pip = [str(VENV / "bin" / "python"), "-m", "pip"]
    cmds.append(Cmd(argv=[*pip, "install", "--upgrade", "pip"], label="upgrade pip"))
    requirements = ["requirements-ci.txt", "requirements-soc-test.txt", "requirements-soc-live.txt"]
    extra: list[str] = []
    if ctx.args.with_lstm:
        requirements.append("requirements-soc-lstm.txt")
        extra = ["--extra-index-url", "https://download.pytorch.org/whl/cpu"]
    cmds.append(Cmd(argv=[*pip, "install", *extra, *[a for r in requirements for a in ("-r", r)]], label="install Python requirements", timeout=2400))
    link = ("mkdir -p ~/.local/bin && for t in ansible ansible-playbook ansible-galaxy ansible-lint yamllint; do "
            f"[ -e {shlex.quote(str(VENV))}/bin/$t ] && [ ! -e ~/.local/bin/$t ] && ln -s {shlex.quote(str(VENV))}/bin/$t ~/.local/bin/$t; done; true")
    cmds.append(Cmd(shell=link, label="expose ansible/yamllint to the login shells the Makefile uses"))
    if (ROOT / "ansible" / "requirements.yml").is_file():
        cmds.append(Cmd(argv=[str(VENV / "bin" / "ansible-galaxy"), "collection", "install", "-r", "ansible/requirements.yml"], label="install Ansible collections", timeout=900))
    return cmds


def containerlab_cmds(ctx: Ctx) -> list[Cmd]:
    if shutil.which("containerlab") or ctx.args.no_install:
        return [Cmd(argv=["containerlab", "version"], label="containerlab version")]
    return [Cmd(shell="d=$(mktemp -d); curl -sL https://get.containerlab.dev -o $d/install.sh && sudo bash $d/install.sh", label="install containerlab", interactive=True, timeout=900),
            Cmd(argv=["containerlab", "version"], label="containerlab version")]


def sysctl_cmds(ctx: Ctx) -> list[Cmd]:
    return [Cmd(argv=["sysctl", "-w", "vm.max_map_count=262144"], sudo=True, interactive=True, label="vm.max_map_count (Elasticsearch, Wazuh indexer)"),
            Cmd(argv=["sysctl", "-w", "fs.inotify.max_user_instances=1024"], sudo=True, interactive=True, label="inotify limit (many containers)"),
            Cmd(argv=["sysctl", "-w", "net.ipv4.ip_forward=1"], sudo=True, interactive=True, label="IPv4 forwarding (routed lab)")]


def py_script(ctx: Ctx, script: str, *args: str) -> Cmd:
    return Cmd(argv=[ctx.py, script, *args], label=script)


def static_cmds(ctx: Ctx) -> list[Cmd]:
    checks = [("scripts/render_fabric.py", "--check"), ("scripts/render_batfish_snapshot.py", "--check"), ("scripts/render_vm_inventory.py", "--check"),
              ("scripts/render_k8s_assets.py", "--check"), ("scripts/check_vyos_boot.py",), ("scripts/check_path_b_intent.py",),
              ("scripts/security_static_checks.py",), ("scripts/check_image_lock.py",), ("scripts/check_soc_static.py",),
              ("scripts/check_soc_ai_static.py",), ("scripts/check_ci_contract.py",), ("scripts/check_yaml_syntax.py",),
              ("scripts/netviz.py", "--check"), ("compliance/check_wiring.py",)]
    cmds = [Cmd(argv=[ctx.py, *c], label=" ".join(c)) for c in checks]
    if shutil.which("kubectl"):
        cmds.append(Cmd(argv=[ctx.py, "scripts/check_k8s_schema.py"], label="kubernetes schema"))
    return cmds


def compose_cmds(ctx: Ctx) -> list[Cmd]:
    profiles = [["siem", "ids", "ztna", "dmz", "vpn-test", "soc", "soc-ai"]]
    cmds = []
    for group in profiles:
        argv = ["docker", "compose", "--env-file", ".env.example"]
        for p in group:
            argv += ["--profile", p]
        cmds.append(Cmd(argv=[*argv, "config", "--quiet"], label="docker compose config (all profiles)"))
    cmds.append(Cmd(argv=["docker", "compose", "--env-file", ".env.example", "-f", "docker-compose.yml", "-f", "docker-compose.path-a.yml",
                          "--profile", "soc", "--profile", "soc-ai", "config", "--quiet"], label="docker compose config (Path A overlay)"))
    cmds.append(Cmd(argv=[str(VENV / "bin" / "yamllint"), "."], label="yamllint"))
    return cmds


def viz_start(ctx: Ctx) -> tuple[str, str]:
    if ctx.args.no_viz:
        return SKIP, "disabled with --no-viz"
    STATE.mkdir(exist_ok=True)
    pidfile = STATE / "netviz.pid"
    if pidfile.exists():
        try:
            os.kill(int(pidfile.read_text().split()[0]), 0)
            port = int(pidfile.read_text().split()[1])
            ctx.viz_url = f"http://127.0.0.1:{port}"
            return PASS, f"already running: {ctx.viz_url}"
        except (OSError, ValueError, IndexError):
            pidfile.unlink(missing_ok=True)
    port = ctx.args.viz_port
    for candidate in range(port, port + 20):
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", candidate)) != 0:
                port = candidate
                break
    log = open(ctx.logdir / "netviz.log", "a")
    proc = subprocess.Popen([ctx.py, "scripts/netviz.py", "--host", ctx.args.viz_host, "--port", str(port)], cwd=ROOT, env=ctx.env(),
                            stdout=log, stderr=log, start_new_session=True)
    for _ in range(40):
        time.sleep(0.25)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as reply:
                if reply.status == 200:
                    pidfile.write_text(f"{proc.pid} {port}\n")
                    ctx.viz_url = f"http://127.0.0.1:{port}"
                    return PASS, f"network explorer: {ctx.viz_url}  (stop: make netviz-stop)"
        except OSError:
            if proc.poll() is not None:
                break
    return FAIL, f"the network explorer did not start; see {log.name}"


def make(ctx: Ctx, target: str, *extra: str, timeout: int = 1800, interactive: bool = False, label: str = "") -> Cmd:
    return Cmd(argv=["make", target, *extra], timeout=timeout, interactive=interactive, label=label or f"make {target}")


def demo_model_cmds(ctx: Ctx) -> list[Cmd]:
    registry = ROOT / "ai" / "registry" / "active" / "metadata.json"
    env_ok = False
    env_file = ROOT / ".env"
    if env_file.is_file():
        env_ok = bool(re.search(r"^SOC_AI_METADATA_SHA256=[a-f0-9]{64}\s*$", env_file.read_text(), re.M))
    if registry.is_file() and env_ok:
        return [Cmd(argv=[ctx.py, "scripts/soc_ai_preflight.py"], label="registry and digest already present: preflight only")]
    args = ["scripts/demo_registry.py", "--write-env"] + (["--with-lstm"] if ctx.args.with_lstm else [])
    return [Cmd(argv=[ctx.py, *args], label="build the DEMO registry (synthetic data, proves wiring only)", timeout=1500),
            Cmd(argv=[ctx.py, "scripts/soc_ai_preflight.py"], label="preflight")]


def mgmt_network_cmds(ctx: Ctx) -> list[Cmd]:
    if ctx.mode != "quick":
        return []
    return [Cmd(shell="docker network inspect cxyz_mgmt >/dev/null 2>&1 || docker network create --subnet 10.1.1.0/24 --gateway 10.1.1.1 "
                      "--label com.cxyz.created-by=try-on-linux-quick cxyz_mgmt", label="management network for the orchestrator (no fabric in --quick)")]


def fabric_verify(ctx: Ctx) -> tuple[str, str]:
    done = subprocess.run(["docker", "ps", "--filter", "name=clab-companyxyz-", "--format", "{{.Names}} {{.Status}}"], capture_output=True, text=True)
    rows = [line for line in done.stdout.splitlines() if line.strip()]
    running = [r for r in rows if " Up" in r]
    if len(running) < 12:
        missing = {"isp1", "isp2", "edge", "fw-core", "core", "dist1", "dist2", "pc1", "pc4", "server1", "fw-dmz", "dmz-web"} - {r.split()[0].replace("clab-companyxyz-", "") for r in running}
        return FAIL, f"{len(running)}/12 lab nodes are running; not running: {', '.join(sorted(missing))}"
    for fw, table in (("fw-core", "cxyz"), ("fw-dmz", "dmz")):
        check = subprocess.run(["docker", "exec", f"clab-companyxyz-{fw}", "nft", "list", "set", "inet", table, "soc_blocklist"], capture_output=True, text=True)
        if check.returncode != 0:
            return FAIL, f"{fw}: nftables set inet {table} soc_blocklist is missing ({(check.stderr or check.stdout).strip()[:120]})"
    for fw in ("fw-core", "fw-dmz"):
        listen = subprocess.run(["docker", "exec", f"clab-companyxyz-{fw}", "sh", "-c", "ss -ltn 2>/dev/null | grep -q ':9443' "], capture_output=True)
        if listen.returncode != 0:
            return FAIL, f"{fw}: the enforcement agent is not listening on 9443 (see /var/log/cxyz-enforcer.log inside the container)"
    return PASS, "12/12 nodes running, containment sets present, enforcement agents listening"


def report_summary(ctx: Ctx) -> tuple[str, str]:
    runs = sorted((ROOT / "evidence" / "runs").glob("*")) if (ROOT / "evidence" / "runs").is_dir() else []
    if not runs:
        return WARN, "no evidence run found (validation stages did not produce evidence)"
    out = ROOT / "evidence" / "COMPLIANCE-REPORT.md"
    done = subprocess.run([ctx.py, "-m", "compliance.generate_report", "--profile", "path-a", "--run", str(runs[-1]), "--out", str(out)],
                          cwd=ROOT, env=ctx.env(), capture_output=True, text=True)
    if done.returncode != 0:
        return FAIL, (done.stdout + done.stderr).strip().splitlines()[-1][:200]
    text = out.read_text(encoding="utf-8")
    summary = re.search(r"\*\*Summary:\*\*[^\n]*", text)
    bad = re.findall(r"\| (\S+) \|[^\n]*(❌ FAIL|⚠️ ERROR)", text)
    message = (summary[0].replace("**", "") if summary else "report written") + f"  -> {out.relative_to(ROOT)}"
    if bad:
        message += "; not passing: " + ", ".join(f"{c} ({s.split()[-1]})" for c, s in bad)
    return (WARN if bad else PASS), message


def build_stages(ctx: Ctx) -> list[Stage]:
    S, C = Stage, Cmd
    return [
        S("host-os", "Check the machine (OS, CPU, RAM, disk)", "host", check=check_host),
        S("host-sudo", "Check sudo (needed for packages, sysctl, containerlab)", "host", check=check_sudo, needs=("host-os",), modes=("full", "quick")),
        S("deps-packages", "Install base packages", "deps", cmds=pkg_install, needs=("host-sudo",), modes=("full", "quick")),
        S("deps-docker", "Install and start Docker + Compose", "deps", cmds=docker_install, needs=("deps-packages",), modes=("full", "quick")),
        S("deps-docker-access", "Verify this user can use Docker", "deps", check=check_docker_access, needs=("deps-docker",), modes=("full", "quick")),
        S("deps-containerlab", "Install containerlab", "deps", cmds=containerlab_cmds, needs=("deps-packages",), modes=("full",)),
        S("deps-sysctl", "Kernel settings (vm.max_map_count, inotify, forwarding)", "deps", cmds=sysctl_cmds, needs=("host-sudo",), modes=("full", "quick")),
        S("deps-python", "Python virtualenv + test requirements", "deps", cmds=python_env_cmds, needs=("host-os",)),
        S("offline-static", "Static gates (render --check, security/SOC/CI invariants, wiring)", "offline", cmds=static_cmds, needs=("deps-python",)),
        S("offline-tests", "Unit + SOC test suites (pytest)", "offline", cmds=lambda c: [Cmd(argv=[c.py, "-m", "pytest", "tests/unit", "tests/soc", "-q", "-rf", "-p", "no:cacheprovider"], label="pytest unit + soc", timeout=1800)],
          needs=("deps-python",), finding=True),
        S("offline-compose", "Docker Compose model + YAML lint", "offline", cmds=compose_cmds, needs=("deps-python", "deps-docker-access"), modes=("full", "quick")),
        S("viz-start", "Start the network explorer (clickable topology)", "viz", check=viz_start, needs=("deps-python",)),
        S("secrets", "Generate .env, keys and the SOC PKI", "live", cmds=lambda c: [make(c, "secrets")], needs=("deps-python",), modes=("full", "quick")),
        S("images", "Build the local service images", "live", cmds=lambda c: [make(c, "images", timeout=3600)], needs=("deps-docker-access", "secrets"), modes=("full", "quick")),
        S("dc-network", "Create the shared DC bridge network", "live", cmds=lambda c: [make(c, "dc-network", interactive=True)], needs=("deps-docker-access", "secrets"), modes=("full", "quick")),
        S("wazuh-config", "Generate the Wazuh certificates", "live", cmds=lambda c: [make(c, "wazuh-config")], needs=("images", "dc-network"), modes=("full", "quick")),
        S("fabric-up", "Deploy the routed fabric (containerlab, 12 nodes)", "live", cmds=lambda c: [make(c, "net", interactive=True, timeout=2400)],
          needs=("deps-containerlab", "dc-network", "deps-sysctl"), modes=("full",)),
        S("fabric-verify", "Verify the fabric: 12 nodes, containment sets, enforcement agents", "live", check=fabric_verify, needs=("fabric-up",), modes=("full",)),
        S("security-up", "Start Wazuh, Suricata, ZTNA and the DMZ app", "live", cmds=lambda c: [make(c, "security", timeout=3000)], needs=("wazuh-config", "fabric-verify"), modes=("full",)),
        S("soc-up", "Start the SOC analytics plane (Elasticsearch, Logstash, Kibana)", "live", cmds=lambda c: [make(c, "soc-up", timeout=2400), make(c, "soc-health")],
          needs=("images", "dc-network", "deps-sysctl"), modes=("full", "quick")),
        S("soc-smoke", "Prove ingestion: four sources, malformed input, dashboard", "live", cmds=lambda c: [make(c, "soc-smoke", timeout=900)], needs=("soc-up",), modes=("full", "quick")),
        S("mgmt-network", "Management network for the orchestrator (quick mode only)", "live", cmds=mgmt_network_cmds, needs=("deps-docker-access",), modes=("quick",)),
        S("demo-model", "Build a DEMO approved model (synthetic data; proves wiring only)", "live", cmds=demo_model_cmds, needs=("deps-python", "secrets"), modes=("full", "quick")),
        S("soc-ai-up", "Start features, inference, enrichment, decision, orchestrator (observe mode)", "live",
          cmds=lambda c: [make(c, "soc-ai-up", timeout=2400), make(c, "soc-ai-status")], needs=("soc-smoke", "demo-model", "mgmt-network"), modes=("full", "quick")),
        S("configure", "Apply the Ansible hardening roles", "audit", cmds=lambda c: [make(c, "configure", timeout=3600)], needs=("fabric-verify", "security-up"), modes=("full",), finding=True),
        S("validate", "Live validation: routing, segmentation, hardening", "audit", cmds=lambda c: [make(c, "validate", timeout=2400)], needs=("configure",), modes=("full",), finding=True),
        S("attack", "Replay the attack chain and prove the SIEM sees it", "audit", cmds=lambda c: [make(c, "attack", timeout=1800)], needs=("validate",), modes=("full",), finding=True),
        S("soc-validate", "Live SOC/AI/response verifiers (enforce mode for ~10 min, then restored)", "audit",
          cmds=lambda c: [make(c, "soc-ai-validate", timeout=5400, interactive=True)], needs=("soc-ai-up", "fabric-verify"), modes=("full",), finding=True),
        S("report", "Compliance report from the evidence just produced", "audit", check=report_summary, needs=("soc-validate",), modes=("full",)),
    ]


# --------------------------------------------------------------------------------------- orchestration
def select(stages: list[Stage], ctx: Ctx) -> list[Stage]:
    a = ctx.args
    chosen = [s for s in stages if ctx.mode in s.modes]
    if a.only:
        wanted = [x.strip() for x in a.only.split(",") if x.strip()]
        unknown = [w for w in wanted if w not in {s.id for s in stages}]
        if unknown:
            raise SystemExit(f"unknown stage(s): {', '.join(unknown)} (see --list)")
        chosen = [s for s in stages if s.id in wanted]
    if a.start:
        ids = [s.id for s in chosen]
        if a.start not in ids:
            raise SystemExit(f"--from {a.start}: not in the selected stages")
        chosen = chosen[ids.index(a.start):]
    if a.skip:
        skipped = {x.strip() for x in a.skip.split(",")}
        chosen = [s for s in chosen if s.id not in skipped]
    return chosen


def render_failure(r: Result, ctx: Ctx) -> None:
    pad = "    "
    print(paint(f"✗ FAILED  {r.stage}", "31;1") + f"  ({r.title})  exit={r.rc}  after {r.seconds:.0f}s")
    if r.command:
        print(f"{pad}command : {r.command}")
    for i, point in enumerate(r.points[:6]):
        print(f"{pad}{'where' if i == 0 else '     '}   : {point}")
    if r.message and r.message not in r.points:
        print(f"{pad}detail  : {r.message}")
    for cause, fix in r.hints:
        print(f"{pad}cause   : {cause}")
        print(f"{pad}fix     : {fix}")
    if r.tail and not r.hints:
        print(f"{pad}last output:")
        for line in r.tail[-8:]:
            print(f"{pad}  | {line[:160]}")
    if r.diagnostics:
        print(f"{pad}container state/logs captured (full text in the log file)")
    print(f"{pad}log     : {r.log}")
    print(f"{pad}re-run  : {SCRIPT} --only {r.stage}" + ("" if ctx.mode == "full" else f" --{ctx.mode}"))


def write_report(ctx: Ctx, results: list[Result], started: datetime) -> pathlib.Path:
    data = {
        "started": started.isoformat(timespec="seconds"), "mode": ctx.mode, "facts": ctx.facts,
        "git": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
        "results": [dataclasses.asdict(r) for r in results], "viz": ctx.viz_url,
    }
    (ctx.logdir / "report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    lines = [f"# try-on-linux report ({ctx.mode})", "", f"- started: {data['started']}", f"- git: {data['git']}",
             *[f"- {k}: {v}" for k, v in ctx.facts.items()], "", "| stage | status | time | note |", "|---|---|---|---|"]
    for r in results:
        note = (r.points[0] if r.points else r.message).replace("|", "/")[:140]
        lines.append(f"| {r.stage} | {r.status} | {r.seconds:.0f}s | {note} |")
    for r in results:
        if r.status in {FAIL, WARN} and (r.points or r.hints or r.tail):
            lines += ["", f"## {r.stage}: {r.status}", "", f"- command: `{r.command}`", f"- log: `{r.log}`"]
            lines += [f"- where: {p}" for p in r.points]
            lines += [f"- cause: {c}\n  - fix: `{f}`" for c, f in r.hints]
            if r.tail:
                lines += ["", "```", *r.tail, "```"]
    path = ctx.logdir / "report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def summarize(ctx: Ctx, results: list[Result], report: pathlib.Path) -> int:
    counts: dict[str, int] = {}
    print("\n" + "=" * 78)
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
        mark = paint(f"{r.status:7}", COLORS.get(r.status, "0"))
        note = (r.points[0] if r.status == FAIL and r.points else r.message)[:78]
        print(f" {mark} {r.stage:18} {r.seconds:6.0f}s  {note}")
    print("=" * 78)
    print("  " + "   ".join(f"{k}: {v}" for k, v in counts.items()))
    failed = [r for r in results if r.status == FAIL]
    print(f"  report : {report.relative_to(ROOT)}  (+ report.json and one log per stage)")
    if ctx.viz_url:
        print(f"  explorer: {ctx.viz_url}   (remote host? ssh -L {ctx.viz_url.rsplit(':', 1)[1]}:127.0.0.1:{ctx.viz_url.rsplit(':', 1)[1]} user@host)")
    if ctx.mode != "offline" and not failed:
        print("  Kibana : https://127.0.0.1:5602   Wazuh: https://127.0.0.1:5601   (passwords: ELASTIC_PASSWORD / WAZUH_DASHBOARD_PASSWORD in .env)")
    if failed:
        print("\n" + paint(f"  {len(failed)} stage(s) failed:", "31;1") + " " + ", ".join(r.stage for r in failed))
        print(f"  fix the first one and re-run:  {SCRIPT} --only {failed[0].stage}   (or just {SCRIPT} --from {failed[0].stage})")
        return 1
    print("\n" + paint("  ALL STAGES PASSED" + (" (with warnings)" if counts.get(WARN) else ""), "32;1"))
    return 0


def teardown(ctx: Ctx) -> int:
    print("stopping the lab (volumes are kept unless --purge)…")
    env = ctx.env()
    steps = [["make", "soc-ai-down"], ["make", "soc-down"], ["make", "down"]]
    pid = STATE / "netviz.pid"
    if pid.exists():
        try:
            os.kill(int(pid.read_text().split()[0]), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        pid.unlink(missing_ok=True)
    rc = 0
    for step in steps:
        print("  $ " + " ".join(step))
        rc |= subprocess.run(step, cwd=ROOT, env=env, check=False).returncode
    if ctx.args.purge:
        print("  --purge: removing the quick-mode management network if we created it")
        subprocess.run(["docker", "network", "rm", "cxyz_mgmt"], cwd=ROOT, check=False)
    return rc


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="skip the containerlab fabric, Wazuh/ZTNA and the audit stages")
    mode.add_argument("--offline", action="store_true", help="only checks that need no containers (works on macOS too)")
    p.add_argument("--only", help="comma-separated stage ids to run (dependencies are NOT run: use it to retry)")
    p.add_argument("--from", dest="start", help="start at this stage id")
    p.add_argument("--skip", help="comma-separated stage ids to skip")
    p.add_argument("--list", action="store_true", help="list stages and exit")
    p.add_argument("--dry-run", action="store_true", help="show what would run; execute nothing")
    p.add_argument("--fail-fast", action="store_true", help="stop at the first failure instead of continuing independent stages")
    p.add_argument("--no-install", action="store_true", help="never install packages; only verify what is there")
    p.add_argument("--with-lstm", action="store_true", help="also install PyTorch (CPU) and build the LSTM + five-detector comparison")
    p.add_argument("--no-viz", action="store_true", help="do not start the network explorer")
    p.add_argument("--viz-host", default="127.0.0.1", help="explorer bind address (default loopback; there is no authentication)")
    p.add_argument("--viz-port", type=int, default=VIZ_PORT_DEFAULT)
    p.add_argument("--verbose", "-v", action="store_true", help="stream command output instead of only logging it")
    p.add_argument("--teardown", action="store_true", help="stop the lab (keeps volumes)")
    p.add_argument("--purge", action="store_true", help="with --teardown: also remove the helper management network")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logdir = ROOT / "logs" / "try-linux" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ctx = Ctx(args, logdir)
    stages = build_stages(ctx)
    if args.list:
        for s in stages:
            print(f"{s.id:20} {','.join(s.modes):20} {s.title}")
        return 0
    if args.teardown:
        return teardown(ctx)
    chosen = select(stages, ctx)
    logdir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    print(paint(f"CompanyXYZ lab — try-on-linux  [{ctx.mode}]  {len(chosen)} stages   logs: {logdir.relative_to(ROOT)}", "1"))
    if args.dry_run:
        print("DRY RUN: nothing is executed, nothing is installed")
    runner = Runner(ctx)
    results: list[Result] = []
    selected_ids = {s.id for s in chosen}
    by_id = {s.id: s for s in stages}
    try:
        for index, stage in enumerate(chosen, start=1):
            blockers = [d for d in stage.needs if d in selected_ids and ctx.results.get(d) and ctx.results[d].status in {FAIL, BLOCKED}
                        and not (by_id[d].finding and ctx.results[d].status == FAIL)]
            if blockers and not args.only:
                r = Result(stage.id, stage.title, BLOCKED, message=f"blocked by failed stage: {', '.join(blockers)}")
                print(paint("■ ", "33") + f"[{index:02d}/{len(chosen):02d}] {stage.title}  -> BLOCKED by {', '.join(blockers)}")
            else:
                r = runner.run_stage(stage, index, len(chosen))
                if r.status == FAIL:
                    render_failure(r, ctx)
                else:
                    detail = f"  {r.message}" if r.message else ""
                    print(f"  {paint(r.status, COLORS.get(r.status, '0'))} in {r.seconds:.0f}s{detail}")
            ctx.results[stage.id] = r
            results.append(r)
            if r.status == FAIL and args.fail_fast:
                break
    except KeyboardInterrupt:
        print("\ninterrupted: partial results below (stages already done are kept; re-run with --from <stage>)")
    report = write_report(ctx, results, started)
    return summarize(ctx, results, report)


if __name__ == "__main__":
    raise SystemExit(main())
