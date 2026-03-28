from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.services import user_service


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_get_user_by_id_guard_and_success():
    assert await user_service.get_user_by_id(SimpleNamespace(), "") is None
    assert await user_service.get_user_by_id(SimpleNamespace(), "   ") is None

    expected = SimpleNamespace(id="u-1")
    db = SimpleNamespace(execute=AsyncMock(return_value=_Result(expected)))
    out = await user_service.get_user_by_id(db, " u-1 ")
    assert out is expected


def test_verify_password_paths(monkeypatch):
    assert user_service.verify_password("pw", None) is False

    monkeypatch.setattr(user_service.bcrypt, "checkpw", lambda _p, _h: True)
    assert user_service.verify_password("pw", "hash") is True

    def _boom(_p, _h):
        raise RuntimeError("bad hash")

    monkeypatch.setattr(user_service.bcrypt, "checkpw", _boom)
    assert user_service.verify_password("pw", "hash") is False


@pytest.mark.asyncio
async def test_get_user_by_email_guards():
    assert await user_service.get_user_by_email(SimpleNamespace(), "") is None
    assert await user_service.get_user_by_email(SimpleNamespace(), "   ") is None
    assert (
        await user_service.get_user_by_email_in_google_tenant(SimpleNamespace(), "") is None
    )
    assert (
        await user_service.get_user_by_email_in_google_tenant(SimpleNamespace(), "   ")
        is None
    )
