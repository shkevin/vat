"""Deduplication engine — fingerprint computation and lookup."""

import hashlib


def normalize(value: str) -> str:
    """Lowercase, trim, strip version from component."""
    if not value:
        return ""
    return value.lower().strip()


def component_base(component: str) -> str:
    """Strip version numbers for fingerprint.
    Handles: lodash@4.17.21 -> lodash, vllm 0.8.5.post1+cpu -> vllm.
    """
    if not component:
        return ""
    # Take before @ (npm style: name@version)
    base = component.split("@")[0].strip()
    if not base:
        return ""
    # If base has "name version" (space + version starting with digit), use name only
    parts = base.split(None, 1)
    if len(parts) >= 2 and parts[1] and parts[1][0].isdigit():
        base = parts[0].strip()
    return normalize(base)


def make_fingerprint(
    cve_id: str,
    component: str,
    image: str | None = None,
    branch: str | None = None,
    tag: str | None = None,
    source_name: str | None = None,
) -> str:
    """
    Deterministic fingerprint for dedup. PRD §5.1.2.
    Includes image + branch/tag so same CVE in different branches (repos) or
    tags (containers) are separate findings. Without this, multi-branch repos
    like Kamiwaza would merge all branches into one finding.

    When source_name is provided (and source_issue_id is not used), findings from
    different parsers/sources (e.g. vat-local-gitleaks vs vat-local-trivy) remain
    separate so the "Group findings" toggle can show instances vs groups correctly.
    """
    cve = normalize(cve_id)
    comp = component_base(component)
    img = normalize(image or "")
    br = normalize(branch or "")
    tg = normalize(tag or "")
    # Only append source_name when provided — preserves backward compatibility for callers
    # that don't pass it (Aikido, sbom, etc. use source_issue_id or don't need source scoping)
    if source_name and str(source_name).strip():
        src = normalize(source_name)
        payload = f"{cve}|{comp}|{img}|{br}|{tg}|{src}"
    else:
        payload = f"{cve}|{comp}|{img}|{br}|{tg}"
    return hashlib.sha256(payload.encode()).hexdigest()


def make_fingerprint_for_source_issue(
    source_name: str,
    source_issue_id: str,
    image: str | None = None,
    branch: str | None = None,
    tag: str | None = None,
) -> str:
    """
    Fingerprint by source + issue ID for 1:1 mapping when source provides unique IDs.
    Each source issue (e.g. Aikido) becomes one VAT finding — no over-dedup.

    When image/branch/tag are provided, they are included so the same source_issue_id
    in different repos (e.g. kamiwaza develop vs main) or container tags does not merge.
    """
    if not source_name or not source_issue_id:
        return ""
    payload = f"{source_name}:{str(source_issue_id).strip()}"
    if image is not None or branch is not None or tag is not None:
        payload += f"|{normalize(image or '')}|{normalize(branch or '')}|{normalize(tag or '')}"
    return hashlib.sha256(payload.encode()).hexdigest()
