"""Tests for JWT issuance and validation."""

import pytest
from unittest.mock import patch

from app.core.jwt import create_token, decode_token, JWT_ALGORITHM, JWT_ISSUER


@pytest.fixture
def mock_settings():
    """Mock settings for JWT tests."""
    with patch("app.core.jwt.get_settings") as m:
        m.return_value.secret_key = "test-secret-key"
        m.return_value.jwt_expire_hours = 24
        yield m


def test_create_token_returns_valid_jwt(mock_settings):
    """create_token produces a JWT with expected claims."""
    token = create_token(
        user_id="u-1",
        email="alice@co.com",
        tenant_id="t-1",
        role="reviewer",
    )
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # header.payload.sig


def test_decode_token_returns_payload_for_valid_token(mock_settings):
    """decode_token returns payload dict for valid token."""
    token = create_token(
        user_id="u-1",
        email="alice@co.com",
        tenant_id="t-1",
        role="admin",
    )
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "alice@co.com"
    assert payload["user_id"] == "u-1"
    assert payload["tenant_id"] == "t-1"
    assert payload["role"] == "admin"
    assert payload["iss"] == JWT_ISSUER
    assert "exp" in payload
    assert "iat" in payload


def test_decode_token_returns_none_for_invalid_token(mock_settings):
    """decode_token returns None for malformed or invalid token."""
    assert decode_token("not-a-jwt") is None
    assert decode_token("a.b.c") is None  # wrong signature
    assert decode_token("") is None


def test_decode_token_returns_none_for_wrong_secret(mock_settings):
    """decode_token returns None when token signed with different secret."""
    token = create_token("u-1", "a@b.com", None, "reviewer")
    with patch("app.core.jwt.get_settings") as m:
        m.return_value.secret_key = "different-secret"
        m.return_value.jwt_expire_hours = 24
        assert decode_token(token) is None


def test_create_token_with_null_tenant_id(mock_settings):
    """create_token accepts None tenant_id."""
    token = create_token(
        user_id="u-1",
        email="alice@co.com",
        tenant_id=None,
        role="reviewer",
    )
    payload = decode_token(token)
    assert payload is not None
    assert payload["tenant_id"] is None


def test_create_token_custom_expiry(mock_settings):
    """create_token respects expire_hours override."""
    token = create_token(
        user_id="u-1",
        email="a@b.com",
        tenant_id=None,
        role="reviewer",
        expire_hours=1,
    )
    payload = decode_token(token)
    assert payload is not None
    assert payload["exp"] - payload["iat"] == 3600  # 1 hour in seconds
