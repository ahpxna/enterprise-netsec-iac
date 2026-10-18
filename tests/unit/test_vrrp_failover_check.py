"""HA-01 must see traffic flow WHILE the VRRP master is down, not only before it went down."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("vrrp_failover_check", ROOT / "scripts/vrrp_failover_check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

START = 1792292261.9


def replies(start, end, step=0.1):
    moment, lines = start, []
    while moment < end:
        lines.append(f"[{moment:.6f}] 64 bytes from 198.10.10.1: icmp_seq={len(lines) + 1} ttl=60 time=0.2 ms")
        moment += step
    return lines


def test_the_first_linux_run_capture_fails_it_passed_before():
    # pc1's capture from that run: 13 replies, the failover, "Net Unreachable" twice, then nothing.
    capture = replies(START, START + 1.3) + [
        f"[{START + 1.36:.6f}] From 192.168.10.254 icmp_seq=14 Destination Net Unreachable",
        f"[{START + 1.47:.6f}] From 192.168.10.254 icmp_seq=15 Destination Net Unreachable",
    ]
    result = check.analyse(capture, START + 1.0, START + 7.0)
    assert result["pass"] is False and result["replies_while_master_down"] == 3
    assert result["max_interruption_seconds"] > 5            # the old check reported a 0.109 s gap


def test_unreachable_replies_are_not_traffic():
    capture = [f"[{START + n / 10:.6f}] From 192.168.10.254 icmp_seq={n} Destination Net Unreachable" for n in range(80)]
    assert check.analyse(capture, START + 1, START + 7)["replies_while_master_down"] == 0


def test_a_short_takeover_passes():
    capture = replies(START, START + 1.0) + replies(START + 2.2, START + 17)     # 1.2 s blackout, then traffic
    result = check.analyse(capture, START + 1.0, START + 7.0)
    assert result["pass"] is True and 1.1 < result["recovery_seconds"] < 1.3
    assert result["max_interruption_seconds"] < 1.3 and result["replies_while_master_down"] > 40


def test_traffic_that_only_returns_with_the_master_fails():
    capture = replies(START, START + 1.0) + replies(START + 7.1, START + 17)
    result = check.analyse(capture, START + 1.0, START + 7.0)
    assert result["pass"] is False and result["recovery_seconds"] is None


def test_traffic_that_recovers_and_stops_again_fails():
    capture = replies(START, START + 1.0) + replies(START + 1.5, START + 1.8) + replies(START + 7.2, START + 17)
    result = check.analyse(capture, START + 1.0, START + 7.0)
    assert result["pass"] is False and result["max_interruption_seconds"] > 5


def test_command_line_exit_code_and_json(tmp_path, capsys):
    capture = tmp_path / "ping.txt"
    capture.write_text("\n".join(replies(START, START + 17)) + "\n")
    assert check.main(["x", str(capture), str(START + 1), str(START + 7)]) == 0
    assert '"pass": true' in capsys.readouterr().out
    capture.write_text("\n".join(replies(START, START + 1)) + "\n")
    assert check.main(["x", str(capture), str(START + 1), str(START + 7)]) == 1
