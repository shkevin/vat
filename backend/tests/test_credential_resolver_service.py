from __future__ import annotations

from types import ModuleType, SimpleNamespace

import pytest

from app.services import credential_resolver


@pytest.mark.asyncio
async def test_settings_credential_resolver_fallback_and_success(monkeypatch):
    resolver = credential_resolver.SettingsCredentialResolver()

    monkeypatch.setattr(credential_resolver, "SOURCE_CREDENTIAL_RESOLVERS", {})
    monkeypatch.setattr(credential_resolver, "TRACKER_CREDENTIAL_RESOLVERS", {})
    assert await resolver.get_source_credentials(SimpleNamespace(), "missing") == {}
    assert await resolver.get_tracker_credentials(SimpleNamespace(), "missing") == {}

    async def src(_db):
        return {"token": "s"}

    async def trk(_db):
        return {"api_key": "t"}

    monkeypatch.setattr(
        credential_resolver, "SOURCE_CREDENTIAL_RESOLVERS", {"aikido": src}
    )
    monkeypatch.setattr(
        credential_resolver, "TRACKER_CREDENTIAL_RESOLVERS", {"linear": trk}
    )
    assert await resolver.get_source_credentials(SimpleNamespace(), "aikido") == {
        "token": "s"
    }
    assert await resolver.get_tracker_credentials(SimpleNamespace(), "linear") == {
        "api_key": "t"
    }


@pytest.mark.asyncio
async def test_register_default_resolvers(monkeypatch):
    fake_settings = ModuleType("app.api.settings")

    async def get_aikido_credentials(_db):
        return {"token": "aik"}

    async def get_linear_credentials(_db):
        return ("lin-key", "team-1", "extra")

    fake_settings.get_aikido_credentials = get_aikido_credentials
    fake_settings.get_linear_credentials = get_linear_credentials

    import sys

    monkeypatch.setitem(sys.modules, "app.api.settings", fake_settings)
    monkeypatch.setattr(credential_resolver, "SOURCE_CREDENTIAL_RESOLVERS", {})
    monkeypatch.setattr(credential_resolver, "TRACKER_CREDENTIAL_RESOLVERS", {})

    credential_resolver._register_default_resolvers()

    src = await credential_resolver.SOURCE_CREDENTIAL_RESOLVERS["aikido"](
        SimpleNamespace()
    )
    trk = await credential_resolver.TRACKER_CREDENTIAL_RESOLVERS["linear"](
        SimpleNamespace()
    )
    assert src == {"token": "aik"}
    assert trk == {"api_key": "lin-key", "team_id": "team-1"}
