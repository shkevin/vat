"""Tests for Linear API polling service."""

import pytest

from app.services.linear_poll_service import poll_linear_for_updates


@pytest.mark.asyncio
async def test_poll_returns_zeros_when_disabled(db, monkeypatch):
    """When linear_poll_enabled is False, poll returns zeros without calling Linear."""
    monkeypatch.setenv("VAT_LINEAR_POLL_ENABLED", "false")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        result = await poll_linear_for_updates(db)
        assert result["issues_fetched"] == 0
        assert result["comments_processed"] == 0
        assert result["descriptions_processed"] == 0
        assert result["errors"] == []
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_poll_returns_zeros_when_not_configured(db, monkeypatch):
    """When Linear credentials are missing, poll returns zeros."""
    monkeypatch.setenv("VAT_LINEAR_POLL_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()

    async def _no_creds(_db):
        return (None, None, None)

    monkeypatch.setattr(
        "app.services.linear_poll_service.get_linear_credentials", _no_creds
    )
    try:
        result = await poll_linear_for_updates(db)
        assert result["issues_fetched"] == 0
        assert result["comments_processed"] == 0
        assert result["descriptions_processed"] == 0
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_poll_skipped_when_webhook_configured(db, monkeypatch):
    """When webhook secret is configured, poll returns zeros (unless force=True)."""
    monkeypatch.setenv("VAT_LINEAR_POLL_ENABLED", "true")
    from app.core.config import get_settings

    get_settings.cache_clear()

    async def _creds_with_webhook(_db):
        return ("api-key", "team-id", "whs_secret")

    monkeypatch.setattr(
        "app.services.linear_poll_service.get_linear_credentials", _creds_with_webhook
    )
    try:
        result = await poll_linear_for_updates(db)
        assert result["issues_fetched"] == 0
        assert result["comments_processed"] == 0
        assert result["descriptions_processed"] == 0
    finally:
        get_settings.cache_clear()
