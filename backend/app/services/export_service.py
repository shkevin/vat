"""Export service — full bundle of assets, findings, SBOM, and Executive Summary report."""

import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.finding import FindingRead
from app.services.assets_service import get_assets_with_findings
from app.services.findings_service import enrich_findings_with_source_group_severity, list_findings
from app.services.grouping import get_finding_group_key
from app.services.openscap_storage import list_openscap_scan_results
from app.services.sbom import list_sbom_packages

SEV_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
ASSET_CLOSED = {"Resolved", "False Positive", "Duplicate", "Not Applicable", "Approved", "Suppressed"}


def _safe_openscap_filename(asset_id: str) -> str:
    """Sanitize asset_id for STIG Viewer filename (e.g. container:tag)."""
    safe = "".join(c if c.isalnum() or c in "._-:" else "_" for c in (asset_id or ""))
    return safe[:200] or "openscap-scan"


def _language_to_purl_type(lang: str) -> str:
    """Map language hint to purl type for CycloneDX."""
    l = (lang or "").lower()
    if "java" in l or l == "java":
        return "maven"
    if "js" in l or "ts" in l or l in ("javascript", "typescript"):
        return "npm"
    if "py" in l or l == "python":
        return "pypi"
    if "go" in l:
        return "golang"
    if "rust" in l:
        return "cargo"
    if "ruby" in l:
        return "gem"
    if "php" in l:
        return "composer"
    if "c" in l or "c++" in l:
        return "generic"
    return "generic"


def _supplier_from_purl_type(pt: str) -> dict | None:
    """Derive CycloneDX supplier from purl type (per package ecosystem)."""
    m = {
        "npm": "npm",
        "pypi": "PyPI",
        "maven": "Maven Central",
        "golang": "Go Modules",
        "cargo": "crates.io",
        "gem": "RubyGems",
        "composer": "Packagist",
        "nuget": "NuGet",
    }
    name = m.get(pt)
    return {"name": name} if name else None


def _build_cyclonedx_bom(packages: list[dict]) -> dict:
    """Build CycloneDX 1.4 JSON BOM (standards-only, enterprise-friendly)."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    serial = f"urn:uuid:{uuid.uuid4()}"
    purl_type = _language_to_purl_type

    seen_purl: set[str] = set()
    components: list[dict] = []

    for p in packages:
        lang = p.get("language") or ""
        pt = purl_type(lang)
        ver = p.get("version") or "0.0.0"
        name = p.get("name") or "unknown"
        purl = (
            f"pkg:generic/{quote(name, safe='')}@{quote(ver, safe='')}"
            if pt == "generic"
            else f"pkg:{pt}/{quote(name, safe='')}@{quote(ver, safe='')}"
        )
        if purl in seen_purl:
            continue
        seen_purl.add(purl)

        lic = p.get("licenseId") or p.get("license_id") or ""
        comp: dict = {
            "type": "library",
            "name": name,
            "version": ver or None,
            "purl": purl,
            "licenses": [{"license": {"id": lic}}] if lic and lic != "Unknown" else None,
            "language": lang or None,
        }
        supplier = _supplier_from_purl_type(pt)
        if supplier:
            comp["supplier"] = supplier
        components.append(comp)

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "Compliance", "name": "SBOM Export", "version": "1.0"}],
        },
        "components": components,
    }


def _severity_key(sev: str) -> str:
    s = (sev or "").lower()
    if s == "critical":
        return "critical"
    if s == "high":
        return "high"
    if s in ("medium", "moderate"):
        return "medium"
    if s == "low":
        return "low"
    return "info"


def _is_open(status: str) -> bool:
    return (status or "").strip() not in ASSET_CLOSED


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _escape(s: str) -> str:
    """Escape HTML special chars."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_executive_summary_html(
    findings: list[dict],
    assets: list[dict],
    date_from: datetime,
    date_to: datetime,
) -> str:
    """Build Executive Summary - Yearly (All Instances) HTML report."""
    # Filter findings within date range (first_detected_at or created)
    in_range: list[dict] = []
    for f in findings:
        dt = _parse_dt(f.get("firstDetectedAt") or f.get("created"))
        if dt and date_from <= dt <= date_to:
            in_range.append(f)

    # Count mode: instances (each finding counts)
    open_findings = [f for f in in_range if _is_open(f.get("status") or "")]
    closed_findings = [f for f in in_range if not _is_open(f.get("status") or "")]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in open_findings:
        k = _severity_key(f.get("severity") or f.get("sourceGroupSeverity") or "")
        if k in counts:
            counts[k] += 1

    # Split assets into repos vs containers
    repos = [a for a in assets if a.get("type") == "repo"]
    containers = [a for a in assets if a.get("type") == "container"]

    def _sev_cell(sev: str, val: int) -> str:
        color = {"Critical": "#f87060", "High": "#f5a623", "Medium": "#f5d020", "Low": "#50c878", "Informational": "#7b8fa1"}.get(sev, "#7b8fa1")
        return f'<td style="color:{color}">{val}</td>'

    sev_rows = "".join(
        f"<tr><td>{s}</td>{_sev_cell(s, counts.get(s.lower() if s != 'Informational' else 'info', 0))}</tr>"
        for s in SEV_ORDER
    )

    def _asset_row(a: dict) -> str:
        name = a.get("name", "")
        open_c = a.get("openCount", 0)
        worst = a.get("worstSeverity", "Informational")
        return f"<tr><td>{_escape(name)}</td><td>{open_c}</td><td>{worst}</td></tr>"

    repo_rows = "".join(_asset_row(a) for a in sorted(repos, key=lambda x: (x.get("name") or ""))[:100])
    container_rows = "".join(_asset_row(a) for a in sorted(containers, key=lambda x: (x.get("name") or ""))[:100])

    def _issue_row(f: dict, i: int) -> str:
        sev = f.get("severity") or f.get("sourceGroupSeverity") or "Informational"
        title = f.get("title") or f.get("cveId") or "Unknown"
        asset = f.get("image") or f.get("component") or "-"
        status = f.get("status") or "Open"
        return f'<tr><td>{i}</td><td>{_escape(title)}</td><td>{_escape(asset)}</td><td>{sev}</td><td>{status}</td></tr>'

    issue_rows = "".join(_issue_row(f, i + 1) for i, f in enumerate(open_findings[:1000]))

    date_str = date_to.strftime("%Y-%m-%d")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Executive Summary - Yearly (All Instances)</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0a0a0a; color: #f8fafc; margin: 2rem; }}
    h1 {{ color: #10b981; }}
    h2 {{ color: #94a3b8; margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #334155; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #1e1e1e; color: #94a3b8; }}
    tr:nth-child(even) {{ background: #171717; }}
    .summary {{ display: flex; gap: 2rem; flex-wrap: wrap; margin: 1rem 0; }}
    .summary-item {{ background: #171717; padding: 1rem 1.5rem; border-radius: 8px; border: 1px solid #334155; }}
    .summary-item strong {{ color: #10b981; font-size: 1.5rem; }}
  </style>
</head>
<body>
  <h1>Executive Summary - Yearly (All Instances)</h1>
  <p>Generated: {date_str} | Period: Last 365 days</p>

  <div class="summary">
    <div class="summary-item"><strong>{len(open_findings)}</strong> Open</div>
    <div class="summary-item"><strong>{len(closed_findings)}</strong> Closed</div>
    <div class="summary-item"><strong>{len(in_range)}</strong> Total (instances)</div>
  </div>

  <h2>Severity Breakdown (Open)</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>{sev_rows}</tbody>
  </table>

  <h2>Repositories</h2>
  <table>
    <thead><tr><th>Repository</th><th>Open</th><th>Worst Severity</th></tr></thead>
    <tbody>{repo_rows or "<tr><td colspan='3'>No repositories</td></tr>"}</tbody>
  </table>

  <h2>Containers</h2>
  <table>
    <thead><tr><th>Container</th><th>Open</th><th>Worst Severity</th></tr></thead>
    <tbody>{container_rows or "<tr><td colspan='3'>No containers</td></tr>"}</tbody>
  </table>

  <h2>Open Findings (first 1000)</h2>
  <table>
    <thead><tr><th>#</th><th>Title</th><th>Asset</th><th>Severity</th><th>Status</th></tr></thead>
    <tbody>{issue_rows or "<tr><td colspan='5'>No open findings</td></tr>"}</tbody>
  </table>
</body>
</html>
"""


async def build_export_bundle(
    db: AsyncSession,
    tenant_id: Optional[str] = None,
) -> bytes:
    """
    Build a ZIP bundle containing:
    - assets-findings.json: all assets and their findings
    - sbom-cyclonedx.json: SBOM in CycloneDX 1.4 format
    - executive-summary-yearly.html: Executive Summary report (365 days, instances)
    - stig/: OpenSCAP XCCDF/OVAL XML per asset for STIG Viewer and XACTA (DISA auditor format)
    """
    import zipfile

    # 1. Fetch all findings and assets (no limit)
    findings = await list_findings(
        db,
        tenant_id=tenant_id,
        archived=False,
        limit=0,
    )
    rows = [FindingRead.model_validate(f).to_api_dict() for f in findings]
    for i, f in enumerate(findings):
        rows[i]["groupKey"] = get_finding_group_key(f)
    rows = await enrich_findings_with_source_group_severity(db, rows)
    assets = await get_assets_with_findings(db, findings_dicts=rows)

    vat_data = {"findings": rows, "assets": assets}

    # 2. Fetch SBOM packages and build CycloneDX BOM (standards-only)
    packages = await list_sbom_packages(db, tenant_id=tenant_id, limit=10000)
    cyclonedx = _build_cyclonedx_bom(packages)

    # 3. Executive Summary HTML (365 days, instances)
    now = datetime.now(timezone.utc)
    date_to = now
    date_from = now - timedelta(days=365)
    html_report = _build_executive_summary_html(rows, assets, date_from, date_to)

    # 4. OpenSCAP STIG export (raw XCCDF/OVAL XML per asset)
    openscap_results = await list_openscap_scan_results(db, tenant_id=tenant_id)
    stig_manifest: list[dict] = []

    # 5. Build ZIP
    buf = io.BytesIO()
    date_str = now.strftime("%Y-%m-%d")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            f"vat-export-{date_str}/assets-findings.json",
            json.dumps(vat_data, indent=2, default=str),
        )
        zf.writestr(
            f"vat-export-{date_str}/sbom-cyclonedx.json",
            json.dumps(cyclonedx, indent=2),
        )
        zf.writestr(
            f"vat-export-{date_str}/executive-summary-yearly.html",
            html_report,
        )
        for row in openscap_results:
            ext = "xccdf.xml" if row.parser_id == "openscap" else "oval-results.xml"
            safe_asset = _safe_openscap_filename(row.asset_id)
            safe_source = _safe_openscap_filename(row.source_id)
            base_name = f"{safe_asset}_{safe_source}" if safe_source else safe_asset
            filename = f"vat-export-{date_str}/stig/{base_name}.{ext}"
            try:
                xml_str = row.raw_xccdf_xml.decode("utf-8", errors="replace")
                zf.writestr(filename, xml_str)
                stig_manifest.append({
                    "assetId": row.asset_id,
                    "sourceId": row.source_id,
                    "filename": f"{base_name}.{ext}",
                    "parserId": row.parser_id,
                    "createdAt": row.created_at.isoformat() if row.created_at else None,
                })
            except Exception:
                pass
        if stig_manifest:
            zf.writestr(
                f"vat-export-{date_str}/stig/manifest.json",
                json.dumps(stig_manifest, indent=2, default=str),
            )

    return buf.getvalue()
