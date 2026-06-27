"""Detail endpoint visibility must match list tenant semantics."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api import findings as findings_api
from app.schemas.auth import UserContext


def _ctx(*, tenant_id: str | None = "t-default") -> UserContext:
    return UserContext(
        user_id="u-1",
        email="reviewer@vat.local",
        tenant_id=tenant_id,
        role="reviewer",
        raw_identity="reviewer@vat.local",
    )


@pytest.mark.asyncio
async def test_get_finding_by_id_allows_legacy_null_tenant(monkeypatch):
    db = AsyncMock()
    finding = SimpleNamespace(tenant_id=None)
    monkeypatch.setattr(findings_api, "get_finding", AsyncMock(return_value=finding))
    monkeypatch.setattr(
        findings_api,
        "finding_to_api_dict_with_group_key",
        lambda f: {"id": "f-1", "tenantId": f.tenant_id},
    )
    # Ledger provenance is exercised separately; neutralize it for the visibility test.
    monkeypatch.setattr(
        findings_api, "decision_provenance", AsyncMock(return_value=None)
    )

    out = await findings_api.get_finding_by_id("f-1", db=db, ctx=_ctx())

    assert out["id"] == "f-1"


@pytest.mark.asyncio
async def test_get_finding_by_id_hides_other_tenant_rows(monkeypatch):
    db = AsyncMock()
    finding = SimpleNamespace(tenant_id="t-other")
    monkeypatch.setattr(findings_api, "get_finding", AsyncMock(return_value=finding))

    with pytest.raises(HTTPException) as exc:
        await findings_api.get_finding_by_id("f-1", db=db, ctx=_ctx(tenant_id="t-default"))

    assert exc.value.status_code == 404
