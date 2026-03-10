"""Grouping service — derived group keys for findings.

Grouping is computed at read time, not stored. Same key = same logical issue (actionable item).
See docs/implementation-plan-grouping-model.md.
"""

import re

from app.models.finding import Finding
from app.services.dedup import component_base


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
    t = re.sub(r"\s+at\s+line\s+\d+(-\d+)?\s+in\s+[\w./-]+$", "", t, flags=re.IGNORECASE)
    return t.strip().lower()


def _asset_key(f: Finding) -> str:
    """Asset context for grouping. Grouping is within asset only — image|branch|tag."""
    img = _normalize(f.image or "")
    br = _normalize(f.branch or "")
    tg = _normalize(f.tag or "")
    return f"{img}|{br}|{tg}"


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
        eco = _normalize_ecosystem_for_grouping(getattr(f, "ecosystem", None) or "")
        pkg = normalize_package_name(eco or None, raw_pkg) if raw_pkg else ""
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
        eco = _normalize_ecosystem_for_grouping(getattr(f, "ecosystem", None) or "")
        pkg = normalize_package_name(eco or None, raw_pkg) if raw_pkg else ""
        if pkg:
            return f"license:{eco}|{pkg}#{asset}"
        return f"license:{f.id}#{asset}"

    return f"other:{f.id}#{asset}"
