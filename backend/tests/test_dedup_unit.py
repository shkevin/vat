from app.services import dedup


def test_normalize_and_component_base_edges():
    assert dedup.normalize("") == ""
    assert dedup.normalize("  A.B  ") == "a.b"

    assert dedup.component_base("") == ""
    assert dedup.component_base("@1.2.3") == ""
    assert dedup.component_base("lodash@4.17.21") == "lodash"
    assert dedup.component_base("vllm 0.8.5.post1+cpu") == "vllm"
    assert dedup.component_base("Requests") == "requests"


def test_make_fingerprint_for_source_issue_paths():
    assert dedup.make_fingerprint_for_source_issue("", "iss-1") == ""
    assert dedup.make_fingerprint_for_source_issue("aikido", "") == ""

    fp_without_asset = dedup.make_fingerprint_for_source_issue("aikido", "iss-1")
    fp_with_asset = dedup.make_fingerprint_for_source_issue(
        "aikido", "iss-1", image="img", branch="main", tag="v1"
    )
    assert fp_without_asset
    assert fp_with_asset
    assert fp_without_asset != fp_with_asset
