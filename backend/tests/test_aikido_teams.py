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
CONTAINERS = [{"id": 602589, "name": "kamiwaza/images/init-keycloak-users-fips"}]


def test_maps_responsibilities_to_member_names():
    dev = aikido_teams_to_asset_names(TEAMS, CODE_REPOS, CONTAINERS)[0]
    assert dev["id"] == "643146"
    assert dev["name"] == "Dev"
    assert dev["assetNames"] == [
        "containers",
        "kamiwaza/images/init-keycloak-users-fips",
    ]
    assert dev["unresolved"] == 1


def test_teams_without_members_survive():
    teams = aikido_teams_to_asset_names(TEAMS, CODE_REPOS, CONTAINERS)
    assert [t["name"] for t in teams] == ["Dev", "Marketing", "team-643150"]
    assert teams[1]["assetNames"] == []
    assert teams[2]["active"] is False


def test_empty_and_malformed_input_is_tolerated():
    assert aikido_teams_to_asset_names([], [], []) == []
    assert aikido_teams_to_asset_names(["nope", None], None, None) == []
    unknown = aikido_teams_to_asset_names(
        [{"id": 1, "name": "X", "responsibilities": [{"id": 5, "type": "virtual_machine"}]}],
        [],
        [],
    )
    assert unknown[0]["assetNames"] == [] and unknown[0]["unresolved"] == 1
