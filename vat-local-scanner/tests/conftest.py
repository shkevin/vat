import pytest

from vat_scanner import cli


@pytest.fixture(autouse=True)
def _no_reconcile_network(monkeypatch):
    """Default the VAT known-digests reconcile fetch to a no-op (None) so unit tests
    never make a real network call. Tests exercising the reconcile override it."""
    monkeypatch.setattr(cli, "fetch_known_digests", lambda *a, **k: None, raising=False)
