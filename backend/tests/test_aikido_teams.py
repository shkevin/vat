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
        # tag is empty upstream, so last_scanned_tag stands in.
        {"name": "kamiwaza/images/init-keycloak-users-fips", "tag": "latest"},
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
