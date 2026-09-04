"""Team -> asset-name mapping for the 'pull Aikido teams as loadouts' flow.

Shapes mirror live Aikido responses: teams carry `responsibilities` of type
code_repository / container_repository whose ids index /repositories/code and
/containers.
"""

from app.adapters.aikido import aikido_teams_to_asset_names

TEAMS = [
    {
        "id": 643146,
        "name": "Dev",
        "active": True,
        "responsibilities": [
            {"id": 1260358, "type": "code_repository"},
            {"id": 602589, "type": "container_repository"},
            {"id": 999999, "type": "container_repository"},  # deleted upstream
            {"id": 1260358, "type": "code_repository"},  # duplicate
        ],
    },
    {"id": 643147, "name": "Marketing", "active": True, "responsibilities": []},
    {"id": 643150, "name": None, "active": False},  # no name, no responsibilities
]
CODE_REPOS = [{"id": 1260358, "name": "containers", "branch": "develop"}]
# Aikido leaves `tag` empty on containers it has only scanned.
CONTAINERS = [
    {
        "id": 602589,
        "name": "kamiwaza/images/init-keycloak-users-fips",
        "tag": "",
        "last_scanned_tag": "latest",
    }
]


def test_maps_responsibilities_to_members_with_context():
    dev = aikido_teams_to_asset_names(TEAMS, CODE_REPOS, CONTAINERS)[0]
    assert dev["id"] == "643146"
    assert dev["name"] == "Dev"
    assert dev["members"] == [
        {"name": "containers", "branch": "develop"},
        # Containers carry no tag: Aikido's is transient and the cache drops it.
        # The frontend derives one from the team's branch + observed tags.
        {"name": "kamiwaza/images/init-keycloak-users-fips"},
    ]
    assert dev["unresolved"] == 1


def test_same_repo_on_two_branches_stays_two_members():
    teams = [
        {
            "id": 1,
            "name": "Rel",
            "responsibilities": [
                {"id": 10, "type": "code_repository"},
                {"id": 11, "type": "code_repository"},
            ],
        }
    ]
    repos = [
        {"id": 10, "name": "containers", "branch": "develop"},
        {"id": 11, "name": "containers", "branch": "release/1.2.1"},
    ]
    members = aikido_teams_to_asset_names(teams, repos, [])[0]["members"]
    assert members == [
        {"name": "containers", "branch": "develop"},
        {"name": "containers", "branch": "release/1.2.1"},
    ]


def test_teams_without_members_survive():
    teams = aikido_teams_to_asset_names(TEAMS, CODE_REPOS, CONTAINERS)
    assert [t["name"] for t in teams] == ["Dev", "Marketing", "team-643150"]
    assert teams[1]["members"] == []
    assert teams[2]["active"] is False


def test_empty_and_malformed_input_is_tolerated():
    assert aikido_teams_to_asset_names([], [], []) == []
    assert aikido_teams_to_asset_names(["nope", None], None, None) == []
    unknown = aikido_teams_to_asset_names(
        [{"id": 1, "name": "X", "responsibilities": [{"id": 5, "type": "virtual_machine"}]}],
        [],
        [],
    )
    assert unknown[0]["members"] == [] and unknown[0]["unresolved"] == 1



async def _run_route(monkeypatch, cached, teams=None):
    """Drive the /aikido/teams route with everything upstream faked."""
    from app.api import aikido as route

    calls: list[str] = []

    async def _teams(_c):
        calls.append("teams")
        return teams if teams is not None else TEAMS[:2]

    async def _repos(_c):
        calls.append("repos")
        return CODE_REPOS

    async def _containers(_c):
        calls.append("containers")
        return CONTAINERS

    async def _creds(_db, _sid):
        return {"client_id": "x", "client_secret": "y", "region": "eu"}

    async def _cached(_db, _sid):
        return cached

    async def _first(_db):
        return "s-1"

    monkeypatch.setattr(route, "fetch_aikido_teams", _teams)
    monkeypatch.setattr(route, "fetch_aikido_code_repositories", _repos)
    monkeypatch.setattr(route, "fetch_aikido_containers", _containers)
    monkeypatch.setattr(route, "get_aikido_credentials", _creds)
    monkeypatch.setattr(route, "get_aikido_dashboard_cached", _cached)
    monkeypatch.setattr(route, "first_aikido_source_id", _first)

    result = await route.aikido_teams(db=None, _ctx=None, source_id=None)
    return result, calls


async def test_complete_cache_means_one_upstream_call(monkeypatch):
    """The sync already cached repos/containers — don't re-fetch them per click.

    Re-fetching cost ~6 upstream calls and was enough on its own to trip
    Aikido's rate limit.
    """
    # A team whose every responsibility the cache can resolve.
    teams = [
        {
            "id": 1,
            "name": "Dev",
            "responsibilities": [{"id": 1260358, "type": "code_repository"}],
        }
    ]
    result, calls = await _run_route(
        monkeypatch,
        {"repos": CODE_REPOS, "containers": CONTAINERS},
        teams=teams,
    )
    assert calls == ["teams"], f"expected cache reuse, got {calls}"
    assert result["teams"][0]["members"] == [
        {"name": "containers", "branch": "develop"}
    ]


async def test_empty_cache_falls_back_upstream(monkeypatch):
    teams = [
        {
            "id": 1,
            "name": "Dev",
            "responsibilities": [{"id": 1260358, "type": "code_repository"}],
        }
    ]
    result, calls = await _run_route(monkeypatch, {}, teams=teams)
    assert calls == ["teams", "repos", "containers"]
    assert result["teams"][0]["unresolved"] == 0


async def test_rate_limit_is_reported_as_429_not_a_generic_failure(monkeypatch):
    """A 502 "upstream error" gives the user nothing to act on."""
    import httpx
    import pytest
    from fastapi import HTTPException
    from app.api import aikido as route

    async def _teams(_c):
        request = httpx.Request("GET", "https://app.aikido.dev/api/public/v1/teams")
        raise httpx.HTTPStatusError(
            "429", request=request, response=httpx.Response(429, request=request)
        )

    async def _creds(_db, _sid):
        return {"client_id": "x", "client_secret": "y", "region": "eu"}

    async def _cached(_db, _sid):
        return {}

    monkeypatch.setattr(route, "fetch_aikido_teams", _teams)
    monkeypatch.setattr(route, "get_aikido_credentials", _creds)
    monkeypatch.setattr(route, "get_aikido_dashboard_cached", _cached)

    with pytest.raises(HTTPException) as exc:
        await route.aikido_teams(db=None, _ctx=None, source_id="s-1")
    assert exc.value.status_code == 429
    assert "rate limit" in exc.value.detail.lower()


async def test_upstream_failure_is_not_reported_as_an_empty_workspace(monkeypatch):
    """A 429 on /teams used to return 200 with zero teams.

    fetch_aikido_teams went through the swallowing getter, so "Aikido is rate
    limiting you" and "you have no teams" were indistinguishable to the caller.
    """
    import httpx
    import pytest
    from fastapi import HTTPException
    from app.api import aikido as route

    async def _teams(_c):
        request = httpx.Request("GET", "https://app.aikido.dev/api/public/v1/teams")
        raise httpx.HTTPStatusError(
            "429", request=request, response=httpx.Response(429, request=request)
        )

    async def _creds(_db, _sid):
        return {"client_id": "x", "client_secret": "y", "region": "eu"}

    async def _cached(_db, _sid):
        return {"repos": CODE_REPOS, "containers": CONTAINERS}

    monkeypatch.setattr(route, "fetch_aikido_teams", _teams)
    monkeypatch.setattr(route, "get_aikido_credentials", _creds)
    monkeypatch.setattr(route, "get_aikido_dashboard_cached", _cached)

    with pytest.raises(HTTPException) as exc:
        await route.aikido_teams(db=None, _ctx=None, source_id="s-1")
    assert exc.value.status_code == 429


async def test_unresolved_members_are_counted_in_the_response(monkeypatch):
    """Dropped responsibilities must be visible, not silently missing."""
    from app.api import aikido as route

    async def _teams(_c):
        return TEAMS[:1]  # has one responsibility pointing at a missing id

    async def _repos(_c):
        return CODE_REPOS

    async def _containers(_c):
        return CONTAINERS

    async def _creds(_db, _sid):
        return {"client_id": "x", "client_secret": "y", "region": "eu"}

    async def _cached(_db, _sid):
        return {}

    for name, fn in (("fetch_aikido_teams", _teams),
                     ("fetch_aikido_code_repositories", _repos),
                     ("fetch_aikido_containers", _containers),
                     ("get_aikido_credentials", _creds),
                     ("get_aikido_dashboard_cached", _cached)):
        monkeypatch.setattr(route, name, fn)

    result = await route.aikido_teams(db=None, _ctx=None, source_id="s-1")
    assert result["unresolvedTotal"] == sum(t["unresolved"] for t in result["teams"])
    assert result["unresolvedTotal"] > 0
