"""Export service — full bundle of assets, findings, SBOM, and Executive Summary report."""

import csv
import hashlib
import io
import json
import logging
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.version import get_vat_backend_version
from app.models.audit_event import AuditEvent
from app.services.assets_service import get_assets_with_findings

if TYPE_CHECKING:
    from app.schemas.auth import UserContext
from app.services.findings_service import (
    enrich_findings_with_source_group_severity,
    list_findings,
)
from app.services.grouping import finding_to_api_dict_with_group_key
from app.services.metric_semantics import is_open_risk
from app.services.openscap_storage import list_openscap_scan_results
from app.services.sbom import list_sbom_packages

logger = logging.getLogger(__name__)

SEV_ORDER = ("Critical", "High", "Medium", "Low", "Informational")


def _safe_openscap_filename(asset_id: str) -> str:
    """Sanitize asset_id for STIG Viewer filename (e.g. container:tag)."""
    safe = "".join(c if c.isalnum() or c in "._-:" else "_" for c in (asset_id or ""))
    return safe[:200] or "openscap-scan"


def _safe_export_filename(name: str, *, max_len: int = 200) -> str:
    """Sanitize arbitrary labels for export file names."""
    safe = "".join(c if c.isalnum() or c in "._-:" else "_" for c in (name or ""))
    return (safe[:max_len] or "unknown").strip(".")


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


def _build_cyclonedx_bom(
    packages: list[dict],
    *,
    include_component_ref: bool = False,
    metadata_component_name: str | None = None,
) -> dict:
    """Build CycloneDX 1.4 JSON BOM (standards-only, enterprise-friendly)."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    serial = f"urn:uuid:{uuid.uuid4()}"
    purl_type = _language_to_purl_type

    seen_keys: set[tuple[str, str | None]] = set()
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
        component_ref = (p.get("component") or "").strip() or None
        dedupe_key = (purl, component_ref if include_component_ref else None)
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)

        lic = p.get("licenseId") or p.get("license_id") or ""
        comp: dict = {
            "type": "library",
            "name": name,
            "version": ver or None,
            "purl": purl,
            "licenses": [{"license": {"id": lic}}]
            if lic and lic != "Unknown"
            else None,
            "language": lang or None,
        }
        supplier = _supplier_from_purl_type(pt)
        if supplier:
            comp["supplier"] = supplier
        if include_component_ref and component_ref:
            comp["properties"] = [{"name": "vat:container_ref", "value": component_ref}]
        components.append(comp)

    metadata: dict = {
        "timestamp": now,
        "tools": [{"vendor": "Compliance", "name": "SBOM Export", "version": "1.0"}],
    }
    if metadata_component_name:
        metadata["component"] = {
            "type": "container",
            "name": metadata_component_name,
        }

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
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
    return is_open_risk(status)


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


@dataclass
class ExportBundleOptions:
    """Options for compliance-oriented export bundles (PRD evidence package)."""

    include_archived: bool = False
    finding_date_from: Optional[str] = None
    finding_date_to: Optional[str] = None
    include_audit_events: bool = True
    apply_asset_filter: bool = False
    asset_ids: Optional[list[str]] = None
    audit_date_from: Optional[str] = None
    audit_date_to: Optional[str] = None
    audit_limit: int = 5000


def _compact_json(data: Any, *, default: Any = None) -> str:
    """Serialize large export payloads without pretty-print whitespace."""
    kwargs: dict[str, Any] = {"separators": (",", ":")}
    if default is not None:
        kwargs["default"] = default
    return json.dumps(data, **kwargs)


def _finding_reference_dt(row: dict) -> Optional[datetime]:
    return _parse_dt(row.get("firstDetectedAt") or row.get("created"))


def _filter_findings_by_date_range(
    rows: list[dict],
    *,
    date_from: Optional[datetime],
    date_to: Optional[datetime],
) -> list[dict]:
    """When either bound is set, keep rows whose reference time falls in [from, to]."""
    if date_from is None and date_to is None:
        return rows
    out: list[dict] = []
    for r in rows:
        ref = _finding_reference_dt(r)
        if ref is None:
            out.append(r)
            continue
        if date_from is not None and ref < date_from:
            continue
        if date_to is not None and ref > date_to:
            continue
        out.append(r)
    return out


def _filter_findings_and_assets_by_asset_ids(
    rows: list[dict],
    assets: list[dict],
    *,
    asset_ids: set[str],
) -> tuple[list[dict], list[dict]]:
    """Restrict export payload to a provided set of asset IDs."""
    scoped_assets = [a for a in assets if str(a.get("id") or "") in asset_ids]
    finding_ids: set[str] = set()
    for asset in scoped_assets:
        for fid in asset.get("findingIds") or []:
            if fid is not None:
                finding_ids.add(str(fid))
        for finding in asset.get("findings") or []:
            f_id = finding.get("id") if isinstance(finding, dict) else None
            if f_id is not None:
                finding_ids.add(str(f_id))
    scoped_rows = [r for r in rows if str(r.get("id") or "") in finding_ids]
    return scoped_rows, scoped_assets


def _flat_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, default=str)[:8000]
    return str(v)


def _finding_csv_row(f: dict) -> dict[str, str]:
    att = f.get("attestation") if isinstance(f.get("attestation"), dict) else {}
    return {
        "id": _flat_str(f.get("id")),
        "fingerprintId": _flat_str(f.get("fingerprintId")),
        "cveId": _flat_str(f.get("cveId")),
        "title": _flat_str(f.get("title")),
        "findingType": _flat_str(f.get("findingType")),
        "severity": _flat_str(f.get("severity")),
        "status": _flat_str(f.get("status")),
        "source": _flat_str(f.get("source")),
        "component": _flat_str(f.get("component")),
        "image": _flat_str(f.get("image")),
        "team": _flat_str(f.get("team")),
        "owner": _flat_str(f.get("owner")),
        "controlRef": _flat_str(f.get("controlRef")),
        "suppressionScope": _flat_str(f.get("suppressionScope")),
        "archived": _flat_str(f.get("archived")),
        "firstDetectedAt": _flat_str(f.get("firstDetectedAt")),
        "created": _flat_str(f.get("created")),
        "closedAt": _flat_str(f.get("closedAt")),
        "waiverRef": _flat_str(att.get("waiverRef")),
        "approver": _flat_str(att.get("approver")),
        "approverTitle": _flat_str(att.get("approverTitle")),
        "approvedAt": _flat_str(att.get("approvedAt")),
        "expiresAt": _flat_str(att.get("expiresAt")),
        "justification": _flat_str(f.get("justification")),
    }


def _findings_csv_bytes(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    fieldnames = list(_finding_csv_row({}).keys())
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for f in rows:
        w.writerow(_finding_csv_row(f))
    return buf.getvalue().encode("utf-8")


def _build_waiver_records(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for f in rows:
        if (f.get("status") or "") != "Risk Accepted":
            continue
        att = f.get("attestation") if isinstance(f.get("attestation"), dict) else {}
        out.append(
            {
                "findingId": f.get("id"),
                "cveId": f.get("cveId"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "component": f.get("component"),
                "image": f.get("image"),
                "waiverRef": att.get("waiverRef"),
                "approver": att.get("approver"),
                "approverTitle": att.get("approverTitle"),
                "approvedAt": att.get("approvedAt"),
                "expiresAt": att.get("expiresAt"),
                "controlRef": f.get("controlRef"),
            }
        )
    return out


def _waivers_csv_bytes(records: list[dict]) -> bytes:
    buf = io.StringIO()
    cols = [
        "findingId",
        "cveId",
        "title",
        "severity",
        "component",
        "image",
        "waiverRef",
        "approver",
        "approverTitle",
        "approvedAt",
        "expiresAt",
        "controlRef",
    ]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in records:
        w.writerow({k: _flat_str(r.get(k)) for k in cols})
    return buf.getvalue().encode("utf-8")


def _pdf_safe(text: str, max_len: int = 118) -> str:
    s = str(text).replace("\r", " ").replace("\n", " ")
    return s.encode("ascii", "replace").decode("ascii")[:max_len]


def _build_compliance_pdf_bytes(
    rows: list[dict],
    *,
    summary_from: datetime,
    summary_to: datetime,
    generated_at: datetime,
    backend_version: str,
    tenant_id: Optional[str],
    waiver_records: list[dict],
) -> bytes:
    from fpdf import FPDF

    in_range: list[dict] = []
    for f in rows:
        dt = _finding_reference_dt(f)
        if dt and summary_from <= dt <= summary_to:
            in_range.append(f)
    open_ct = sum(1 for f in in_range if _is_open(f.get("status") or ""))
    fp_ct = sum(
        1 for f in in_range if (f.get("status") or "") == "False Positive"
    )
    sup_ct = sum(1 for f in in_range if (f.get("status") or "") == "Suppressed")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "VAT compliance evidence summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=9)
    pdf.cell(
        0,
        5,
        _pdf_safe(f"Generated (UTC): {generated_at.strftime('%Y-%m-%d %H:%M:%S')}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(
        0,
        5,
        _pdf_safe(f"Backend version: {backend_version}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(
        0,
        5,
        _pdf_safe(f"Tenant: {tenant_id or '(global / unset)'}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.cell(
        0,
        5,
        _pdf_safe(
            f"Summary window: {summary_from.date().isoformat()} .. {summary_to.date().isoformat()}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Aggregate counts (findings in summary window)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=9)
    pdf.cell(0, 5, _pdf_safe(f"Instances in window: {len(in_range)}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _pdf_safe(f"Open (non-terminal): {open_ct}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _pdf_safe(f"False positive closures: {fp_ct}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _pdf_safe(f"Suppressed closures: {sup_ct}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0,
        5,
        _pdf_safe(f"Active waiver records (export scope): {len(waiver_records)}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 6, "Waiver registry (first 40)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=8)
    for rec in waiver_records[:40]:
        line = (
            f"{rec.get('findingId')} | {rec.get('waiverRef')} | "
            f"{rec.get('approver')} | exp {rec.get('expiresAt')}"
        )
        pdf.cell(0, 4, _pdf_safe(line, 130), new_x="LMARGIN", new_y="NEXT")
    if len(waiver_records) > 40:
        pdf.cell(0, 4, _pdf_safe(f"... and {len(waiver_records) - 40} more (see waivers.csv)"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(
        0,
        4,
        _pdf_safe(
            "Full machine-readable data: assets-findings.json, findings.csv, waivers.json. "
            "System audit stream: audit-events.json (when included). "
            "SBOM: sbom-cyclonedx.json. OpenSCAP: stig/."
        ),
    )
    out = pdf.output()
    return out if isinstance(out, (bytes, bytearray)) else str(out).encode("latin-1")


def _audit_event_to_dict(r: AuditEvent) -> dict:
    return {
        "event_id": r.event_id,
        "trace_id": r.trace_id,
        "event_type": r.event_type,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "source_id": r.source_id,
        "parser_id": r.parser_id,
        "asset_id": r.asset_id,
        "finding_id": r.finding_id,
        "decision_name": r.decision_name,
        "decision_reason_code": r.decision_reason_code,
        "decision_confidence": r.decision_confidence,
        "decision_result": r.decision_result,
        "record_hash": r.record_hash,
        "prev_record_hash": r.prev_record_hash,
        "data": r.data or {},
    }


def _as_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


async def load_audit_events_for_export(
    db: AsyncSession,
    *,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 20000,
) -> list[dict]:
    q = select(AuditEvent)
    clauses = []
    df = _parse_dt(date_from) if date_from else None
    dt = _parse_dt(date_to) if date_to else None
    if df is not None:
        clauses.append(AuditEvent.created_at >= _as_naive_utc(df))
    if dt is not None:
        clauses.append(AuditEvent.created_at <= _as_naive_utc(dt))
    if clauses:
        q = q.where(and_(*clauses))
    q = q.order_by(AuditEvent.created_at.asc()).limit(min(limit, 50000))
    rows = (await db.execute(q)).scalars().all()
    return [_audit_event_to_dict(r) for r in rows]


def _build_evidence_manifest(
    *,
    generated_at: datetime,
    backend_version: str,
    tenant_id: Optional[str],
    options: ExportBundleOptions,
    file_entries: list[dict[str, Any]],
    warnings: Optional[list[str]] = None,
) -> dict:
    body: dict[str, Any] = {
        "schemaVersion": "evidence-v2",
        "packageType": "vat-compliance-bundle",
        "generatedAt": generated_at.isoformat().replace("+00:00", "Z"),
        "vatBackendVersion": backend_version,
        "tenantId": tenant_id,
        "exportOptions": {k: v for k, v in asdict(options).items()},
        "files": file_entries,
    }
    if warnings:
        body["warnings"] = warnings
    return body


def _escape(s: str) -> str:
    """Escape HTML special chars."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


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
        color = {
            "Critical": "#f87060",
            "High": "#f5a623",
            "Medium": "#f5d020",
            "Low": "#50c878",
            "Informational": "#7b8fa1",
        }.get(sev, "#7b8fa1")
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

    repo_rows = "".join(
        _asset_row(a) for a in sorted(repos, key=lambda x: (x.get("name") or ""))[:100]
    )
    container_rows = "".join(
        _asset_row(a)
        for a in sorted(containers, key=lambda x: (x.get("name") or ""))[:100]
    )

    def _issue_row(f: dict, i: int) -> str:
        sev = f.get("severity") or f.get("sourceGroupSeverity") or "Informational"
        title = f.get("title") or f.get("cveId") or "Unknown"
        asset = f.get("image") or f.get("component") or "-"
        status = f.get("status") or "Open"
        return f"<tr><td>{i}</td><td>{_escape(title)}</td><td>{_escape(asset)}</td><td>{sev}</td><td>{status}</td></tr>"

    issue_rows = "".join(
        _issue_row(f, i + 1) for i, f in enumerate(open_findings[:1000])
    )

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
    ctx: "UserContext",
    options: Optional[ExportBundleOptions] = None,
) -> bytes:
    """
    Build a ZIP bundle containing:
    - evidence-manifest.json: scope, backend version, SHA-256 per payload file
    - assets-findings.json: assets and findings (optional date filter)
    - findings.csv, waivers.json, waivers.csv: tabular / waiver registry
    - compliance-summary.pdf: printable evidence summary
    - executive-summary-yearly.html: Executive Summary report
    - audit-events.json: system audit stream (optional)
    - auditor-workbook.xlsx: multi-sheet auditor package (findings, waivers, STIG tables)
    - stig/: OpenSCAP XCCDF/OVAL XML per asset, README-STIG-Viewer.txt, manifest.json
    - sbom-cyclonedx.json, sbom/by-asset/*.cdx.json
    """
    import zipfile

    opts = options or ExportBundleOptions()
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    root = f"vat-export-{date_str}"
    backend_version = get_vat_backend_version()

    archived_filter: Optional[bool] = None if opts.include_archived else False
    findings = await list_findings(
        db,
        ctx=ctx,
        archived=archived_filter,
        limit=0,
    )
    tenant_id = ctx.tenant_id
    rows = [finding_to_api_dict_with_group_key(f) for f in findings]
    rows = await enrich_findings_with_source_group_severity(db, rows)

    slice_from = _parse_dt(opts.finding_date_from)
    slice_to = _parse_dt(opts.finding_date_to)
    rows = _filter_findings_by_date_range(rows, date_from=slice_from, date_to=slice_to)

    assets = await get_assets_with_findings(
        db,
        findings_dicts=rows,
        ctx=ctx,
        include_findings=False,
        include_finding_derived_assets=False,
    )
    if opts.apply_asset_filter:
        selected_asset_ids = {str(aid) for aid in (opts.asset_ids or []) if str(aid)}
        rows, assets = _filter_findings_and_assets_by_asset_ids(
            rows,
            assets,
            asset_ids=selected_asset_ids,
        )
    vat_data = {"findings": rows, "assets": assets}

    packages = await list_sbom_packages(
        db,
        tenant_id=ctx.tenant_id,
        cross_tenant=ctx.cross_tenant,
        limit=10000,
    )
    cyclonedx = _build_cyclonedx_bom(packages)
    per_asset_packages: dict[str, list[dict]] = {}
    for p in packages:
        component = (p.get("component") or "").strip()
        if not component:
            continue
        per_asset_packages.setdefault(component, []).append(p)

    summary_to = slice_to or now
    summary_from = slice_from or (summary_to - timedelta(days=365))
    html_report = _build_executive_summary_html(rows, assets, summary_from, summary_to)

    waiver_records = _build_waiver_records(rows)
    export_warnings: list[str] = []

    buf = io.BytesIO()
    zf = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    inner_prefix = f"{root}/"
    file_entries: list[dict[str, Any]] = []

    def put(rel: str, content: str | bytes) -> None:
        if isinstance(content, str):
            content = content.encode("utf-8")
        zf.writestr(f"{inner_prefix}{rel}", content)
        if rel != "evidence-manifest.json":
            file_entries.append(
                {
                    "path": rel,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "sizeBytes": len(content),
                }
            )

    put("assets-findings.json", _compact_json(vat_data, default=str))
    put("findings.csv", _findings_csv_bytes(rows))
    put("waivers.json", _compact_json(waiver_records, default=str))
    put("waivers.csv", _waivers_csv_bytes(waiver_records))
    put("executive-summary-yearly.html", html_report)
    put("sbom/sbom-cyclonedx.json", _compact_json(cyclonedx))

    sbom_asset_manifest: list[dict[str, str | int]] = []
    for component, rows_for_component in sorted(per_asset_packages.items()):
        asset_bom = _build_cyclonedx_bom(
            rows_for_component,
            include_component_ref=True,
            metadata_component_name=component,
        )
        safe_component = _safe_export_filename(component)
        rel = f"sbom/by-asset/{safe_component}.cdx.json"
        put(rel, _compact_json(asset_bom))
        sbom_asset_manifest.append(
            {
                "component": component,
                "file": rel,
                "packageCount": len(rows_for_component),
            }
        )
    if sbom_asset_manifest:
        put("sbom/by-asset/manifest.json", _compact_json(sbom_asset_manifest))

    from app.services.audit_workbook_export import (
        STIG_RULE_ROWS_CAP,
        STIG_VIEWER_README,
        build_auditor_workbook_bytes,
        extract_xccdf_rule_results,
    )

    openscap_results = await list_openscap_scan_results(
        db,
        tenant_id=ctx.tenant_id,
        cross_tenant=ctx.cross_tenant,
    )
    stig_manifest: list[dict] = []
    stig_rule_rows: list[dict[str, Any]] = []
    for row in openscap_results:
        ext = "xccdf.xml" if row.parser_id == "openscap" else "oval-results.xml"
        safe_asset = _safe_openscap_filename(row.asset_id)
        safe_source = _safe_openscap_filename(row.source_id)
        base_name = f"{safe_asset}_{safe_source}" if safe_source else safe_asset
        rel = f"stig/{base_name}.{ext}"
        try:
            raw_xml = row.raw_xccdf_xml
            if not raw_xml:
                continue
            xml_str = raw_xml.decode("utf-8", errors="replace")
            put(rel, xml_str)
            stig_manifest.append(
                {
                    "assetId": row.asset_id,
                    "sourceId": row.source_id,
                    "filename": f"{base_name}.{ext}",
                    "parserId": row.parser_id,
                    "createdAt": row.created_at.isoformat() if row.created_at else None,
                    "benchmarkId": row.benchmark_id,
                    "benchmarkFamily": row.benchmark_family,
                    "profileScope": row.profile_scope,
                    "contentVersion": row.content_version,
                    "evidenceSha256": row.evidence_sha256,
                }
            )
            if row.parser_id == "openscap":
                for r in extract_xccdf_rule_results(raw_xml):
                    if len(stig_rule_rows) >= STIG_RULE_ROWS_CAP:
                        break
                    stig_rule_rows.append(
                        {
                            "assetId": row.asset_id,
                            "sourceId": row.source_id,
                            "parserId": row.parser_id,
                            "benchmarkId": row.benchmark_id or "",
                            "ruleId": r.get("ruleId", ""),
                            "result": r.get("result", ""),
                            "severity": r.get("severity", ""),
                        }
                    )
        except Exception:
            pass
    put("stig/README-STIG-Viewer.txt", STIG_VIEWER_README)
    if stig_manifest:
        put("stig/manifest.json", _compact_json(stig_manifest, default=str))

    audit_events_for_workbook: list[dict] | None = None
    if opts.include_audit_events:
        try:
            audit_events_for_workbook = await load_audit_events_for_export(
                db,
                date_from=opts.audit_date_from,
                date_to=opts.audit_date_to,
                limit=opts.audit_limit,
            )
        except Exception as exc:
            logger.exception("embedding audit events in export bundle failed")
            export_warnings.append(f"audit_embed_failed: {exc!s}")
            audit_events_for_workbook = []
        put(
            "audit-events.json",
            _compact_json(audit_events_for_workbook, default=str),
        )

    try:
        workbook_bytes = build_auditor_workbook_bytes(
            findings=rows,
            waiver_records=waiver_records,
            stig_file_manifest=stig_manifest,
            stig_rule_rows=stig_rule_rows,
            audit_events=audit_events_for_workbook,
            generated_at=now,
            tenant_id=tenant_id,
            backend_version=backend_version,
            export_options={k: v for k, v in asdict(opts).items()},
        )
        put("auditor-workbook.xlsx", workbook_bytes)
    except Exception as exc:
        logger.exception("auditor workbook generation failed")
        export_warnings.append(f"auditor_workbook_failed: {exc!s}")

    manifest_body = _build_evidence_manifest(
        generated_at=now,
        backend_version=backend_version,
        tenant_id=tenant_id,
        options=opts,
        file_entries=file_entries,
        warnings=export_warnings or None,
    )
    put("evidence-manifest.json", json.dumps(manifest_body, indent=2, default=str))
    zf.close()
    return buf.getvalue()
