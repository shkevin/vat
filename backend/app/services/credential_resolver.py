"""Credential resolver — adapter-agnostic credential fetching."""

from typing import Awaitable, Callable, Protocol

from sqlalchemy.ext.asyncio import AsyncSession


class CredentialResolver(Protocol):
    """Resolve credentials for an adapter. Implemented by settings layer."""

    async def get_source_credentials(
        self, db: AsyncSession, adapter_key: str
    ) -> dict: ...
    async def get_tracker_credentials(
        self, db: AsyncSession, adapter_key: str
    ) -> dict: ...


# Registry: adapter_key -> async (db) -> credentials dict
SOURCE_CREDENTIAL_RESOLVERS: dict[str, Callable[[AsyncSession], Awaitable[dict]]] = {}
TRACKER_CREDENTIAL_RESOLVERS: dict[str, Callable[[AsyncSession], Awaitable[dict]]] = {}


def _register_default_resolvers() -> None:
    """Wire settings credential fetchers into registry. Called on app init."""
    from app.api.settings import get_aikido_credentials, get_linear_credentials

    async def _linear_as_dict(db: AsyncSession) -> dict:
        api_key, team_id, _ = await get_linear_credentials(db)
        return {"api_key": api_key, "team_id": team_id}

    SOURCE_CREDENTIAL_RESOLVERS["aikido"] = get_aikido_credentials
    TRACKER_CREDENTIAL_RESOLVERS["linear"] = _linear_as_dict


# Register on import (adapters must be loaded first for registry to exist)
_register_default_resolvers()


class SettingsCredentialResolver:
    """Resolves credentials via registry. Populated by settings module."""

    async def get_source_credentials(self, db: AsyncSession, adapter_key: str) -> dict:
        resolver = SOURCE_CREDENTIAL_RESOLVERS.get(adapter_key)
        if not resolver:
            return {}
        return await resolver(db)

    async def get_tracker_credentials(self, db: AsyncSession, adapter_key: str) -> dict:
        resolver = TRACKER_CREDENTIAL_RESOLVERS.get(adapter_key)
        if not resolver:
            return {}
        return await resolver(db)
