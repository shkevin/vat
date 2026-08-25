"""Pytest fixtures for VAT backend tests."""

import pytest
import respx
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

# Backend tests require the PostgreSQL async driver. In lightweight environments
# (for example scanner-only test runs), skip these tests instead of failing
# collection with ModuleNotFoundError.
pytest.importorskip("asyncpg")

from app.core.config import get_settings
from app.core.database import engine as app_engine, get_db
from app.main import app

settings = get_settings()

# Test engine with NullPool — each session gets a fresh connection, avoiding
# asyncpg "another operation is in progress" when the default pool reuses connections.
test_engine = create_async_engine(
    settings.database_url,
    poolclass=NullPool,
    echo=settings.database_url.startswith("postgresql+asyncpg://vat:vat@localhost"),
)
test_async_session = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
async def _dispose_engines():
    """Dispose both test and app engines before event loop closes."""
    yield
    await test_engine.dispose()
    await app_engine.dispose()


@pytest.fixture
async def db() -> AsyncSession:
    """Provide a database session for tests."""
    try:
        async with test_async_session() as session:
            # Fail fast with a clean skip when local Postgres is not reachable.
            await session.execute(text("SELECT 1"))
            yield session
    except Exception as exc:
        pytest.skip(f"PostgreSQL not available for backend tests: {exc}")


@pytest.fixture
async def client(db: AsyncSession):
    """Async HTTP client for API tests. Overrides get_db to use test session (avoids connection sharing)."""

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as ac:
            yield ac
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Linear / Aikido adapter fixtures (respx)
# ---------------------------------------------------------------------------


def _linear_graphql_response(request):
    """Return GraphQL response matching the operation in the request body."""
    import json

    body = request.content.decode() if request.content else ""
    try:
        data = json.loads(body)
        query = data.get("query", "")
    except Exception:
        query = body

    if "issueCreate" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issueCreate": {
                        "success": True,
                        "issue": {"id": "mock-uuid", "identifier": "VAT-1"},
                    }
                }
            },
        )
    if "commentCreate" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "commentCreate": {
                        "success": True,
                        "comment": {"id": "mock-comment-uuid"},
                    }
                }
            },
        )
    if "issueUpdate" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issueUpdate": {
                        "success": True,
                        "issue": {"id": "mock-issue-uuid"},
                    }
                }
            },
        )
    if "issueLabelCreate" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issueLabelCreate": {
                        "success": True,
                        "issueLabel": {"id": "label-new", "name": "new-label"},
                    }
                }
            },
        )
    # teams with organization.urlKey (for get_organization_url_key)
    if "organization" in query and "urlKey" in query:
        if "team(id" in query:
            return respx.MockResponse(
                200,
                json={"data": {"team": {"organization": {"urlKey": "acme-org"}}}},
            )
        if "teams" in query and "filter" in query:
            return respx.MockResponse(
                200,
                json={
                    "data": {
                        "teams": {
                            "nodes": [{"organization": {"urlKey": "acme-org"}}]
                        }
                    }
                },
            )
    if "teams" in query and "filter" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "teams": {
                        "nodes": [{"id": "mock-team-uuid", "key": "acme-org"}]
                    }
                }
            },
        )
    if "team(id" in query and "states" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "team": {
                        "id": "mock-team-uuid",
                        "states": {
                            "nodes": [
                                {"id": "state-backlog", "type": "backlog"},
                                {"id": "state-unstarted", "type": "unstarted"},
                                {"id": "state-done", "type": "done"},
                            ]
                        },
                    }
                }
            },
        )
    if "issueLabels" in query and "IssueLabelFilter" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issueLabels": {
                        "nodes": [
                            {"id": "label-1", "name": "security-bug"},
                            {"id": "label-2", "name": "vat"},
                        ]
                    }
                }
            },
        )
    if "workflowState(id" in query or "workflowState(" in query:
        return respx.MockResponse(
            200,
            json={"data": {"workflowState": {"id": "mock-state-done", "type": "done"}}},
        )
    if "issue(id" in query and "team" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issue": {"id": "mock-issue-uuid", "team": {"id": "mock-team-uuid"}}
                }
            },
        )
    # list_issues (link_linear, find_existing_issue_for_cve): nodes with identifier, title, description
    if "issues" in query and "filter" in query and "pageInfo" in query:
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issues": {
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                        "nodes": [
                            {
                                "id": "mock-issue-uuid",
                                "identifier": "AUT-51",
                                "title": "Kafka client auth bypass CVE-2024-1234",
                                "description": "",
                            }
                        ],
                    }
                }
            },
        )
    # Other issues queries (e.g. get_issue_by_identifier for reopen)
    if (
        "issues(filter" in query
        or "issues (" in query
        or ("issues" in query and "filter" in query)
    ):
        return respx.MockResponse(
            200,
            json={
                "data": {
                    "issues": {
                        "nodes": [
                            {
                                "id": "mock-issue-uuid-from-identifier",
                                "team": {"id": "mock-team-uuid"},
                            }
                        ]
                    }
                }
            },
        )
    return respx.MockResponse(400, json={"errors": [{"message": "Unknown operation"}]})


@pytest.fixture
def linear_respx():
    """Mock Linear GraphQL API. Use with @respx.mock or as context manager."""
    with respx.mock(assert_all_mocked=False) as router:
        route = router.post("https://api.linear.app/graphql")
        route.mock(side_effect=_linear_graphql_response)
        yield router


@pytest.fixture
def aikido_respx():
    """Mock Aikido REST API (OAuth + issues/export + repositories). Use with @respx.mock."""
    with respx.mock(assert_all_mocked=False, assert_all_called=False) as router:
        router.post("https://app.aikido.dev/api/oauth/token").mock(
            return_value=Response(
                200,
                json={
                    "access_token": "mock-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        )
        router.get("https://app.aikido.dev/api/public/v1/issues/export").mock(
            return_value=Response(
                200,
                json={
                    "issues": [
                        {
                            "id": "ai-001",
                            "cve_id": "CVE-2024-21626",
                            "title": "Test CVE",
                            "type": "vulnerability",
                            "severity": "high",
                            "code_repo_name": "test-repo",
                            "branch": "main",
                            "first_detected_at": "2024-01-15T10:30:00Z",
                        }
                    ]
                },
            )
        )
        router.get("https://app.aikido.dev/api/public/v1/repositories/code").mock(
            return_value=Response(
                200,
                json={
                    "repositories": [{"id": 1, "name": "test-repo", "branch": "main"}]
                },
            )
        )
        router.put(
            url__regex=r"https://app\.aikido\.dev/api/public/v1/issues/[^/]+/ignore"
        ).mock(return_value=Response(200, json={}))
        router.put(
            url__regex=r"https://app\.aikido\.dev/api/public/v1/issues/[^/]+/unignore"
        ).mock(return_value=Response(200, json={}))
        yield router


# ---------------------------------------------------------------------------
# Google OAuth fixtures (respx)
# ---------------------------------------------------------------------------


@pytest.fixture
def google_respx():
    """Mock Google OAuth token and userinfo endpoints for /auth/google/callback tests."""
    with respx.mock(assert_all_mocked=False, assert_all_called=False) as router:
        router.post("https://oauth2.googleapis.com/token").mock(
            return_value=Response(
                200,
                json={
                    "access_token": "mock-google-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        )
        router.get("https://www.googleapis.com/oauth2/v2/userinfo").mock(
            return_value=Response(
                200,
                json={
                    "email": "test@example.com",
                    "name": "Test User",
                    "picture": "https://example.com/photo.jpg",
                },
            )
        )
        yield router


@pytest.fixture
def google_oauth_enabled(monkeypatch):
    """Enable Google OAuth in config for tests. Clears settings cache."""
    from app.core.config import get_settings

    monkeypatch.setenv("VAT_GOOGLE_CLIENT_ID", "test-google-client-id")
    monkeypatch.setenv("VAT_GOOGLE_CLIENT_SECRET", "test-google-client-secret")
    monkeypatch.setenv("VAT_PUBLIC_URL", "http://test")
    monkeypatch.setenv("VAT_FRONTEND_URL", "http://test")
    get_settings.cache_clear()
    try:
        yield
    finally:
        get_settings.cache_clear()
