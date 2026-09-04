"""ingest_finding must be able to leave the transaction to its caller.

Committing per finding cost an fsync plus a refresh round-trip on every call,
which is what made a 121k-issue Aikido bootstrap take the better part of an
hour — sampling the live sync caught COMMIT in 10 of 13 active-query probes.
Bulk callers pass commit=False and commit in batches instead.
"""

import inspect

from app.services import ingest as ingest_mod
from app.services import aikido_full_sync as sync_mod


def test_ingest_finding_accepts_commit_flag():
    sig = inspect.signature(ingest_mod.ingest_finding)
    assert "commit" in sig.parameters
    # Existing callers (webhooks, single-finding API) must be unaffected.
    assert sig.parameters["commit"].default is True


def test_both_return_paths_honour_the_flag():
    """Merge and create paths both used to commit unconditionally."""
    src = inspect.getsource(ingest_mod.ingest_finding)
    # Every commit in the function body is now behind the flag.
    for line_no, line in enumerate(src.splitlines()):
        if "await db.commit()" in line:
            preceding = src.splitlines()[max(0, line_no - 3) : line_no]
            assert any("if commit:" in p for p in preceding), (
                f"unguarded commit at relative line {line_no}: {line.strip()}"
            )
    assert src.count("await db.commit()") == 2


def test_bootstrap_batches_and_isolates_each_finding():
    src = inspect.getsource(sync_mod)
    # Caller owns the transaction...
    assert "commit=False" in src
    # ...committing periodically rather than per finding...
    assert "INGEST_COMMIT_EVERY" in src
    assert sync_mod.INGEST_COMMIT_EVERY >= 100
    # ...and a savepoint keeps one bad payload from poisoning the batch.
    assert "session.begin_nested()" in src
    # The old blanket rollback would have discarded the whole uncommitted batch.
    assert "await session.rollback()" not in src.split("Bootstrap: Ingest")[0][-3000:]
