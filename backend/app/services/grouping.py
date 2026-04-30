"""Grouping service — derived group keys for findings.

Grouping is computed at read time, not stored. Same key = same logical issue (actionable item).
See docs/implementation-plan-grouping-model.md.

Asset scope in each key uses the same canonical container/repo image segment as
``assets_service._asset_key_from_dict`` when ``finding.image`` is set, so
multi-scanner spelling differences (``docker.io/...`` vs path-only) share one
group within a list asset.
"""

import re

from app.models.finding import Finding
from app.services.assets_service import _container_image_group_key
from app.services.dedup import component_base
from app.services.sca_cross_scanner import (
    effective_sca_ecosystem,
    normalize_sca_package_for_cross_scanner,
)


def _normalize(s: str | None) -> str:
    if not s or not isinstance(s, str):
        return ""
    return s.lower().strip()


def _normalize_ecosystem_for_grouping(eco: str) -> str:
    """
    Normalize ecosystem for grouping key. npm/yarn/pnpm share the same registry,
    so same package from different package managers should group together.
    """
    e = (eco or "").lower().strip()
    if e in ("npm", "yarn", "pnpm"):
        return "npm"
    return e or ""


def _extract_component_base_for_grouping(component: str | None) -> str:
    """
    Extract package name from component when component_base is missing.
    Handles "name@version" (via dedup.component_base) and "name version" (strip version).
    Parsers should emit component_base; this is a best-effort fallback.
    """
    if not component or not isinstance(component, str):
        return ""
    # First try @-based: lodash@4.17.21 -> lodash
    base = component_base(component.strip())
    if not base:
        return ""
    # If base has space and part after looks like version (e.g. "lodash 4.17.21"), use first part
    parts = base.split(None, 1)
    if len(parts) >= 2 and parts[1] and parts[1][0].isdigit():
        return parts[0].strip()
    return base


def normalize_package_name(ecosystem: str | None, name: str | None) -> str:
    """
    Normalize package name for grouping. Prevents phantom duplicate groups across ecosystems:
    - npm: case-insensitive (Lodash == lodash)
    - PyPI: PEP 503 — collapse [-_.]+ to single -, lowercase (My.Weird_Package → my-weird-package)
    - Maven: full groupId:artifactId lowercased — do NOT strip groupId or you get false collisions
    """
    if not name or not isinstance(name, str):
        return ""
    name = name.strip()
    if not name:
        return ""
    eco = (ecosystem or "").lower().strip()

    if eco in ("npm", "yarn", "pnpm"):
        return name.lower()
    if eco in ("pypi", "pip", "pipenv", "poetry"):
        # PEP 503: collapse runs of -, _, . to single -, then lowercase
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco in ("maven", "gradle"):
        # Prefer groupId:artifactId when present; else fall back to generic (Aikido may have malformed data)
        return name.lower()
    return name.lower()


def _normalize_rule_title(title: str | None, *, strip_locations: bool = True) -> str:
    """Normalize rule title for grouping.
    When strip_locations=True (SAST/IaC): same rule at different locations = one group.
    When strip_locations=False (Secret): keep location in title so each file is a separate group.
    """
    if not title or not isinstance(title, str):
        return ""
    t = title.strip()
    if not strip_locations:
        return t.lower()
    # ", path and N others" or ", path, path and N others" (SAST/IaC only)
    t = re.sub(r", [^,]+(, [^,]+)? and \d+ others?$", "", t, flags=re.IGNORECASE)
    # " in <path>" when path has extension (py, ts, etc.) or is extensionless (Dockerfile, Makefile)
    t = re.sub(
        r"\s+in\s+[\w./-]+\.(py|ts|tsx|js|jsx|json|yml|yaml|md|txt|xml|html|css|sh|go|rs|java|kt|env|tf|hcl|toml|lock)(\s*,\s*[\w./-]+)?$",
        "",
        t,
        flags=re.IGNORECASE,
    )
    t = re.sub(
        r"\s+in\s+[\w./-]*(Dockerfile|Makefile|\.dockerignore|\.gitignore)(\s*,\s*[\w./-]+)?$",
        "",
        t,
        flags=re.IGNORECASE,
    )
    # " at line N in <path>" or " at line N-N in <path>"
    t = re.sub(
        r"\s+at\s+line\s+\d+(-\d+)?\s+in\s+[\w./-]+$", "", t, flags=re.IGNORECASE
    )
    return t.strip().lower()


def _asset_key(f: Finding) -> str:
    """
    Asset context for grouping. Grouping is within asset only — image|branch|tag.

    For findings with ``image`` set, the image segment uses the same canonical
    container/repo key as ``get_assets_with_findings`` / ``_asset_key_from_dict``
    (``_container_image_group_key``), so different scanner spellings
    (``docker.io/foo`` vs path-only ``foo``) share one groupKey suffix. Branch and
    tag columns stay raw-normalized (lowercase trim).
    """
    raw_img = (f.image or "").strip()
    br = _normalize(f.branch or "")
    tg = _normalize(f.tag or "")
    if raw_img:
        img_key = _container_image_group_key(raw_img, None)
        img_key = (img_key or "").strip().lower()
        return f"{img_key}|{br}|{tg}"
    return f"|{br}|{tg}"


def get_finding_group_key(f: Finding) -> str:
    """
    Stable group key for a finding. Same key = same logical issue (actionable item).
    Grouping is scoped within asset (image|branch|tag) — findings in different assets do not group.
    - SCA/CVE: ecosystem + component_base (package) — one group per package per asset
    - SAST: rule_id or cwe_id or normalized title — per asset
    - IaC: rule_id or normalized title — per asset
    - Secret: secret_type or rule_id or normalized title — per asset
    - License: ecosystem + component_base — per asset
    """
    ft = (f.finding_type.value if f.finding_type else "").lower()
    cve_id = _normalize(f.cve_id or "")
    asset = _asset_key(f)

    # SCA: ecosystem + package (component_base), normalized per ecosystem
    if ft == "sca":
        raw_pkg = f.component_base or _extract_component_base_for_grouping(f.component)
        eco = effective_sca_ecosystem(
            getattr(f, "ecosystem", None),
            getattr(f, "benchmark_family", None),
            image=getattr(f, "image", None),
            tag=getattr(f, "tag", None),
        )
        eco = _normalize_ecosystem_for_grouping(eco)
        cross = normalize_sca_package_for_cross_scanner(raw_pkg) if raw_pkg else ""
        pkg = normalize_package_name(eco or None, cross) if cross else ""
        if pkg:
            return f"sca:{eco}|{pkg}#{asset}"
        return f"cve:{cve_id}#{asset}"  # fallback when no package

    # SAST: rule_id or cwe_id or normalized title
    if ft == "sast":
        rid = _normalize(getattr(f, "rule_id", None) or "")
        cwe = _normalize(getattr(f, "cwe_id", None) or "")
        title = _normalize_rule_title(f.title or f.cve_id or "")
        key = rid or cwe or title or f.id
        return f"sast:{key}#{asset}"

    # IaC: rule_id or normalized title
    if ft == "iac":
        rid = _normalize(getattr(f, "rule_id", None) or "")
        title = _normalize_rule_title(f.title or f.cve_id or "")
        key = rid or title or f.id
        return f"iac:{key}#{asset}"

    # Secret: secret_type or rule_id or title — normalize so "private-key" and "private key"
    # from different scanners (Gitleaks vs Trivy) group together
    if ft == "secret":
        st = _normalize(getattr(f, "secret_type", None) or "")
        rid = _normalize(getattr(f, "rule_id", None) or "")
        # Do NOT strip " in <path>" — secrets in different files are separate remediations
        title = _normalize_rule_title(f.title or f.cve_id or "", strip_locations=False)
        raw_key = st or rid or title or f.id
        # Collapse spaces/dashes/underscores for simple rule ids only (e.g. "private-key" vs "private key")
        # Skip when key contains path pattern " in " so "leaked secret in install.sh" stays distinct
        if " in " not in raw_key and len(raw_key) < 80:
            key = re.sub(r"[-_\s]+", "-", raw_key).strip("-") or raw_key
        else:
            key = raw_key
        return f"secret:{key}#{asset}"

    # License: ecosystem + package, normalized per ecosystem
    if ft == "license":
        raw_pkg = f.component_base or _extract_component_base_for_grouping(f.component)
        eco = effective_sca_ecosystem(
            getattr(f, "ecosystem", None),
            getattr(f, "benchmark_family", None),
            image=getattr(f, "image", None),
            tag=getattr(f, "tag", None),
        )
        eco = _normalize_ecosystem_for_grouping(eco)
        cross = normalize_sca_package_for_cross_scanner(raw_pkg) if raw_pkg else ""
        pkg = normalize_package_name(eco or None, cross) if cross else ""
        if pkg:
            return f"license:{eco}|{pkg}#{asset}"
        return f"license:{f.id}#{asset}"

    return f"other:{f.id}#{asset}"


def finding_to_api_dict_with_group_key(f: Finding, *, slim: bool = False) -> dict:
    """
    API/export shape: ``FindingRead.to_api_dict()`` plus server-derived ``groupKey``.
    Use for list/detail responses, VAT bundle, and exports so clients share one source.

    ``slim=True`` builds the dict directly from the ORM object without
    Pydantic validation, avoiding access to deferred columns
    (description/justification/etc.) that would otherwise trigger a
    MissingGreenlet error under async SQLAlchemy. The non-slim path keeps
    the full FindingRead validation for correctness on the detail/export
    surface where every column is loaded eagerly.
    """
    if slim:
        from app.schemas.finding import STATUS_DISPLAY, _external_links_to_camel

        sources = list(f.sources or [])
        slim_sources = [
            {"name": s.get("name"), "importedAt": s.get("importedAt")}
            for s in sources
            if isinstance(s, dict)
        ]
        slim_links = [
            {"kind": link.get("kind"), "url": link.get("url")}
            for link in _external_links_to_camel(list(f.external_links or []))
            if isinstance(link, dict)
        ]
        # tracker_id derives from the first tracker-flavored external link;
        # mirror the property logic in FindingRead for parity.
        tracker_id = None
        for link in f.external_links or []:
            if not isinstance(link, dict):
                continue
            if link.get("kind") in ("tracker", "linear"):
                tracker_id = link.get("issue_id") or link.get("issueId")
                if tracker_id:
                    break
        suppression_scope = (
            f.suppression_scope.value
            if getattr(f, "suppression_scope", None) is not None
            else None
        )
        d = {
            "id": f.id,
            "findingType": f.finding_type.value,
            "fingerprintId": f.fingerprint_id,
            "cveId": f.cve_id,
            "severity": f.severity.value,
            "status": STATUS_DISPLAY.get(f.status.value, f.status.value),
            "componentBase": f.component_base,
            "component": f.component,
            "image": f.image,
            "branch": f.branch,
            "tag": f.tag,
            "imageDigest": f.image_digest,
            "title": f.title,
            "source": f.source,
            "team": f.team,
            "owner": f.owner,
            "trackerId": tracker_id,
            "externalLinks": slim_links,
            "controlRef": f.control_ref,
            "slaDue": f.sla_due,
            "cvss": f.cvss,
            "epss": f.epss,
            "trackerComment": bool(f.tracker_comment),
            "sources": slim_sources,
            "suppressionScope": suppression_scope,
            "attestation": f.attestation,
            "regressionCount": f.regression_count or 0,
            "previousStatus": STATUS_DISPLAY.get(
                f.previous_status or "", f.previous_status
            )
            if f.previous_status
            else None,
            "archived": bool(f.archived),
            "archivedAt": f.archived_at.isoformat() if f.archived_at else None,
            "sourceFileUrl": f.source_file_url,
            "sourceIssueGroupId": f.source_issue_group_id,
            "aikidoSourceId": f.aikido_source_id,
            "filePath": f.file_path,
            "line": f.line,
            "ruleId": f.rule_id,
            "cweId": f.cwe_id,
            "ecosystem": f.ecosystem,
            "secretType": f.secret_type,
            "resource": f.resource,
            "benchmarkId": f.benchmark_id,
            "benchmarkFamily": f.benchmark_family,
            "correlationKey": f.correlation_key,
            "correlationConfidence": f.correlation_confidence,
            "correlatedTo": f.correlated_to,
            "created": f.created_at.isoformat() if f.created_at else None,
            "firstDetectedAt": f.first_detected_at.isoformat()
            if f.first_detected_at
            else None,
            "closedAt": f.closed_at.isoformat() if f.closed_at else None,
        }
    else:
        from app.schemas.finding import FindingRead

        d = FindingRead.model_validate(f).to_api_dict()
    d["groupKey"] = get_finding_group_key(f)
    return d
