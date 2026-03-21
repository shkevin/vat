"""
Golden scanner fixtures must produce identical typed correlation keys where we expect
cross-source linking (Trivy vs Grype). No database required.
"""

import json
from pathlib import Path

from app.parsers import get_parser
from app.services.correlation import correlation_key_for_payload

_FIXTURES = Path(__file__).resolve().parent / "integration" / "fixtures" / "correlation"


def _corr_tuple(p) -> tuple[str, str]:
    return correlation_key_for_payload(
        finding_type=str(p.finding_type.value),
        image=p.image or "",
        branch=getattr(p, "branch", None) or "",
        tag=getattr(p, "tag", None) or "",
        cve_id=p.cve_id,
        component=p.component or "",
        ecosystem=getattr(p, "ecosystem", None),
        rule_id=getattr(p, "rule_id", None),
        file_path=getattr(p, "file_path", None),
    )


def test_golden_trivy_and_grype_share_correlation_key() -> None:
    trivy = get_parser("trivy").parse(
        json.loads((_FIXTURES / "trivy-e2e.json").read_text())
    )
    grype = get_parser("grype").parse(
        json.loads((_FIXTURES / "grype-e2e.json").read_text())
    )
    assert len(trivy) == 1 and len(grype) == 1
    k1, c1 = _corr_tuple(trivy[0])
    k2, c2 = _corr_tuple(grype[0])
    assert k1 == k2, f"trivy key {k1!r} != grype key {k2!r}"
    assert c1 == "high" and c2 == "high"
