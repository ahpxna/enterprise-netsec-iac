"""The outbox lock: one worker at a time, but re-entrant inside that worker (serve holds it and calls drain)."""

import pytest

from soc.workers.enrichment import drain
from soc.workers.outbox import Outbox


def outbox_path(tmp_path):
    root = tmp_path / "enrichment"
    root.mkdir(mode=0o700)
    return root / "outbox.sqlite"


def test_the_lock_is_reentrant_for_one_worker_and_exclusive_against_another(tmp_path):
    path = outbox_path(tmp_path)
    worker, other = Outbox(path), Outbox(path)
    with worker.exclusive():
        with worker.exclusive():
            with pytest.raises(RuntimeError, match="another outbox worker is active"):
                with other.exclusive():
                    pass
        # Leaving the inner block must not release the outer hold.
        with pytest.raises(RuntimeError, match="another outbox worker is active"):
            with other.exclusive():
                pass
    with other.exclusive():
        pass


def test_drain_runs_inside_the_serve_loop_lock(tmp_path):
    # Regression: `serve` took the lock and then drain() took it again through a second open file
    # description, which flock() refuses, so the live worker crash-looped on every start.
    outbox = Outbox(outbox_path(tmp_path))
    with outbox.exclusive():
        assert drain(outbox, inference=None, elastic=None, limit=10) == drain(outbox, inference=None, elastic=None, limit=10)
