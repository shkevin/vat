"""Multi-sheet auditor workbook (xlsx) for compliance reviews + STIG summary tables."""

from __future__ import annotations

import io
import json
from datetime import datetime
from typing import Any, Optional

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

STIG_RULE_ROWS_CAP = 100_000

# Match export_service.ASSET_CLOSED for open vs terminal remediation backlog
_ASSET_CLOSED = {
    "Resolved",
    "False Positive",
    "Duplicate",
    "Not Applicable",
    "Approved",
    "Suppressed",
}


def _flat_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, default=str)[:8000]
    return str(v)


def extract_xccdf_rule_results(raw_xml: bytes) -> list[dict[str, str]]:
    """Parse XCCDF TestResult rule-result elements for spreadsheet export."""
    try:
        from defusedxml import ElementTree

        root = ElementTree.fromstring(raw_xml)
    except Exception:
        return []
    out: list[dict[str, str]] = []
    for el in root.iter():
        tag = el.tag.split("}")[-1] if "}" in (el.tag or "") else (el.tag or "")
        if tag != "rule-result":
            continue
        rule_id = (el.get("idref") or el.get("id") or "").strip()
        sev = (el.get("severity") or "").strip()
        res_text = ""
        for child in el:
            ct = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if ct == "result" and child.text:
                res_text = (child.text or "").strip()
                break
        out.append(
            {
                "ruleId": rule_id,
                "result": res_text,
                "severity": sev,
            }
        )
    return out


def _is_stig_related_finding(f: dict) -> bool:
    src = (f.get("source") or "").lower()
    if "openscap" in src:
        return True
    if f.get("benchmarkId") or f.get("stableRuleKey"):
        return True
    return False


def _finding_audit_log_rows(findings: list[dict]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for f in findings:
        fid = _flat_str(f.get("id"))
        for entry in f.get("audit") or []:
            if not isinstance(entry, dict):
                continue
            rows.append(
                {
                    "findingId": fid,
                    "timestamp": _flat_str(entry.get("ts")),
                    "user": _flat_str(entry.get("user")),
                    "action": _flat_str(entry.get("action")),
                    "note": _flat_str(entry.get("note")),
                }
            )
    return rows


def _system_audit_rows(events: list[dict]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for e in events:
        rows.append(
            {
                "eventId": _flat_str(e.get("event_id")),
                "createdAt": _flat_str(e.get("created_at")),
                "eventType": _flat_str(e.get("event_type")),
                "findingId": _flat_str(e.get("finding_id")),
                "assetId": _flat_str(e.get("asset_id")),
                "sourceId": _flat_str(e.get("source_id")),
                "parserId": _flat_str(e.get("parser_id")),
                "decisionName": _flat_str(e.get("decision_name")),
                "decisionResult": _flat_str(e.get("decision_result")),
            }
        )
    return rows


def _metrics_summary(
    findings: list[dict],
    *,
    generated_at: datetime,
) -> list[dict[str, Any]]:
    def is_open_status(s: str) -> bool:
        return (s or "").strip() not in _ASSET_CLOSED

    open_n = sum(1 for f in findings if is_open_status(f.get("status") or ""))
    by_sev: dict[str, int] = {}
    for f in findings:
        if not is_open_status(f.get("status") or ""):
            continue
        sev = f.get("severity") or "Unknown"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    rows = [
        {"metric": "generatedAtUtc", "value": generated_at.isoformat()},
        {"metric": "totalFindingsInExport", "value": len(findings)},
        {"metric": "openFindings", "value": open_n},
    ]
    for sev, c in sorted(by_sev.items(), key=lambda x: x[0]):
        rows.append({"metric": f"openBySeverity_{sev}", "value": c})
    return rows


def _write_sheet(wb: Workbook, title: str, headers: list[str], data_rows: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet(title)
    bold = Font(bold=True)
    for col, h in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.font = bold
    for r_i, row in enumerate(data_rows, start=2):
        for c_i, h in enumerate(headers, start=1):
            v = row.get(h)
            if v is None:
                v = ""
            elif isinstance(v, (dict, list)):
                v = str(v)[:32000]
            ws.cell(row=r_i, column=c_i, value=v)
    ws.freeze_panes = "A2"
    for i, h in enumerate(headers, start=1):
        ws.column_dimensions[get_column_letter(i)].width = min(max(len(h) + 2, 12), 48)


def _build_waiver_records_local(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for f in rows:
        if (f.get("status") or "") != "Risk Accepted":
            continue
        att = f.get("attestation") if isinstance(f.get("attestation"), dict) else {}
        out.append(
            {
                "findingId": f.get("id"),
                "cveId": f.get("cveId"),
                "ruleId": f.get("ruleId"),
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


def build_auditor_workbook_bytes(
    *,
    findings: list[dict],
    waiver_records: Optional[list[dict]] = None,
    stig_file_manifest: list[dict[str, Any]],
    stig_rule_rows: list[dict[str, Any]],
    audit_events: Optional[list[dict]] = None,
    generated_at: datetime,
    tenant_id: Optional[str],
    backend_version: str,
    export_options: dict[str, Any],
) -> bytes:
    """
    Build auditor-workbook.xlsx: findings, waivers, justifications, decision logs,
    metrics, STIG Viewer file index, STIG check results (from XCCDF), remediation backlog.
    """
    waiver_records = waiver_records if waiver_records is not None else _build_waiver_records_local(findings)

    wb = Workbook()
    default_ws = wb.active
    wb.remove(default_ws)

    # --- ReadMe ---
    readme_rows = [
        {"key": "package", "value": "VAT auditor workbook (companion to evidence ZIP)"},
        {"key": "generatedAtUtc", "value": generated_at.isoformat().replace("+00:00", "Z")},
        {"key": "vatBackendVersion", "value": backend_version},
        {"key": "tenantId", "value": tenant_id or "(global / unset)"},
        {
            "key": "definitions",
            "value": (
                "False Positive = scanner incorrect (global suppression). "
                "Suppressed = real finding accepted in context. "
                "Risk Accepted = formal waiver with attestation."
            ),
        },
        {
            "key": "stigViewer",
            "value": (
                "Import raw results from ZIP folder stig/ (*.xccdf.xml, *.oval-results.xml). "
                "See stig/README-STIG-Viewer.txt in the bundle."
            ),
        },
        {
            "key": "stigRuleRowsNote",
            "value": (
                f"STIG_Check_Results lists up to {STIG_RULE_ROWS_CAP} rule-results parsed from XCCDF; "
                "XML files remain authoritative for STIG Viewer re-import."
            ),
        },
        {"key": "exportOptions", "value": json.dumps(export_options, default=str)},
    ]
    _write_sheet(wb, "ReadMe", ["key", "value"], readme_rows)

    # --- Findings (wide) ---
    finding_headers = [
        "id",
        "fingerprintId",
        "cveId",
        "ruleId",
        "stableRuleKey",
        "benchmarkId",
        "benchmarkFamily",
        "profileScope",
        "title",
        "findingType",
        "severity",
        "status",
        "source",
        "component",
        "image",
        "filePath",
        "team",
        "owner",
        "controlRef",
        "suppressionScope",
        "archived",
        "firstDetectedAt",
        "created",
        "closedAt",
        "slaDue",
        "justification",
        "compensatingControls",
        "reviewerNote",
        "waiverRef",
        "approver",
        "approverTitle",
        "approvedAt",
        "expiresAt",
    ]
    finding_rows: list[dict[str, Any]] = []
    for f in findings:
        att = f.get("attestation") if isinstance(f.get("attestation"), dict) else {}
        finding_rows.append(
            {
                "id": f.get("id"),
                "fingerprintId": f.get("fingerprintId"),
                "cveId": f.get("cveId"),
                "ruleId": f.get("ruleId"),
                "stableRuleKey": f.get("stableRuleKey"),
                "benchmarkId": f.get("benchmarkId"),
                "benchmarkFamily": f.get("benchmarkFamily"),
                "profileScope": f.get("profileScope"),
                "title": f.get("title"),
                "findingType": f.get("findingType"),
                "severity": f.get("severity"),
                "status": f.get("status"),
                "source": f.get("source"),
                "component": f.get("component"),
                "image": f.get("image"),
                "filePath": f.get("filePath"),
                "team": f.get("team"),
                "owner": f.get("owner"),
                "controlRef": f.get("controlRef"),
                "suppressionScope": f.get("suppressionScope"),
                "archived": f.get("archived"),
                "firstDetectedAt": f.get("firstDetectedAt"),
                "created": f.get("created"),
                "closedAt": f.get("closedAt"),
                "slaDue": f.get("slaDue"),
                "justification": f.get("justification"),
                "compensatingControls": f.get("compensatingControls"),
                "reviewerNote": f.get("reviewerNote"),
                "waiverRef": att.get("waiverRef"),
                "approver": att.get("approver"),
                "approverTitle": att.get("approverTitle"),
                "approvedAt": att.get("approvedAt"),
                "expiresAt": att.get("expiresAt"),
            }
        )
    _write_sheet(wb, "Findings", finding_headers, finding_rows)

    # --- Waivers ---
    w_headers = [
        "findingId",
        "cveId",
        "ruleId",
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
    _write_sheet(wb, "Waivers_Risk_Acceptance", w_headers, waiver_records)

    # --- Justifications (long text) ---
    just_headers = ["findingId", "cveId", "title", "status", "justification", "compensatingControls", "reviewerNote"]
    just_rows = [
        {
            "findingId": f.get("id"),
            "cveId": f.get("cveId"),
            "title": f.get("title"),
            "status": f.get("status"),
            "justification": f.get("justification"),
            "compensatingControls": f.get("compensatingControls"),
            "reviewerNote": f.get("reviewerNote"),
        }
        for f in findings
        if f.get("justification") or f.get("compensatingControls") or f.get("reviewerNote")
    ]
    _write_sheet(wb, "Justifications_Comments", just_headers, just_rows)

    # --- Per-finding audit trail (embedded audit[]) ---
    ad_headers = ["findingId", "timestamp", "user", "action", "note"]
    _write_sheet(wb, "Finding_Decision_Log", ad_headers, _finding_audit_log_rows(findings))

    # --- Remediation-style backlog (not formal eMASS POA&M) ---
    def _open(s: str) -> bool:
        return (s or "").strip() not in _ASSET_CLOSED

    poam_headers = [
        "findingId",
        "cveId",
        "ruleId",
        "title",
        "severity",
        "status",
        "slaDue",
        "team",
        "owner",
        "controlRef",
        "component",
        "image",
        "firstDetectedAt",
    ]
    poam_rows = [
        {
            "findingId": f.get("id"),
            "cveId": f.get("cveId"),
            "ruleId": f.get("ruleId"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "status": f.get("status"),
            "slaDue": f.get("slaDue"),
            "team": f.get("team"),
            "owner": f.get("owner"),
            "controlRef": f.get("controlRef"),
            "component": f.get("component"),
            "image": f.get("image"),
            "firstDetectedAt": f.get("firstDetectedAt"),
        }
        for f in findings
        if _open(f.get("status") or "")
    ]
    _write_sheet(wb, "Remediation_Backlog", poam_headers, poam_rows)

    # --- Metrics ---
    _write_sheet(
        wb,
        "Metrics_Summary",
        ["metric", "value"],
        _metrics_summary(findings, generated_at=generated_at),
    )

    # --- STIG files for Viewer / Manager ---
    stig_f_headers = [
        "zipPath",
        "assetId",
        "sourceId",
        "parserId",
        "benchmarkId",
        "benchmarkFamily",
        "profileScope",
        "contentVersion",
        "evidenceSha256",
        "createdAt",
        "importHint",
    ]
    stig_f_rows: list[dict[str, Any]] = []
    for m in stig_file_manifest:
        fn = m.get("filename") or ""
        stig_f_rows.append(
            {
                "zipPath": f"stig/{fn}",
                "assetId": m.get("assetId"),
                "sourceId": m.get("sourceId"),
                "parserId": m.get("parserId"),
                "benchmarkId": m.get("benchmarkId"),
                "benchmarkFamily": m.get("benchmarkFamily"),
                "profileScope": m.get("profileScope"),
                "contentVersion": m.get("contentVersion"),
                "evidenceSha256": m.get("evidenceSha256"),
                "createdAt": m.get("createdAt"),
                "importHint": "DISA STIG Viewer: Import results file (XCCDF or OVAL per tool support).",
            }
        )
    _write_sheet(wb, "STIG_STIGViewer_Files", stig_f_headers, stig_f_rows)

    # --- Rule-level rows from XCCDF ---
    chk_headers = [
        "assetId",
        "sourceId",
        "parserId",
        "benchmarkId",
        "ruleId",
        "result",
        "severity",
    ]
    _write_sheet(wb, "STIG_Check_Results", chk_headers, stig_rule_rows)

    # --- VAT STIG-related findings (normalized) ---
    stig_findings = [f for f in findings if _is_stig_related_finding(f)]
    sf_subset = [
        "id",
        "cveId",
        "ruleId",
        "stableRuleKey",
        "benchmarkId",
        "benchmarkFamily",
        "title",
        "severity",
        "status",
        "source",
        "image",
        "component",
        "filePath",
        "controlRef",
        "suppressionScope",
        "justification",
        "firstDetectedAt",
    ]
    sf_rows = [{k: f.get(k) for k in sf_subset} for f in stig_findings]
    _write_sheet(wb, "STIG_VAT_Findings", sf_subset, sf_rows)

    # --- System audit (same scope as audit-events.json when included) ---
    if audit_events is not None:
        sa_headers = [
            "eventId",
            "createdAt",
            "eventType",
            "findingId",
            "assetId",
            "sourceId",
            "parserId",
            "decisionName",
            "decisionResult",
        ]
        _write_sheet(wb, "System_Audit_Events", sa_headers, _system_audit_rows(audit_events))
    else:
        _write_sheet(
            wb,
            "System_Audit_Events",
            ["note"],
            [
                {
                    "note": "No rows: enable include_audit_events on export bundle to embed audit-events.json and this sheet.",
                }
            ],
        )

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


STIG_VIEWER_README = """DISA STIG Viewer / STIG Manager — importing OpenSCAP results from this ZIP
================================================================================

This folder contains OpenSCAP evaluation results as delivered by VAT:

  *.xccdf.xml       — XCCDF Benchmark result (typical OpenSCAP -xccdf output)
  *.oval-results.xml — OVAL results (when the scan was stored as OVAL results)

HOW TO IMPORT (STIG Viewer)
---------------------------
1. Open DISA STIG Viewer.
2. Use the menu action to import or open **result** / **XCCDF** data (wording varies by version).
3. Select one or more `.xccdf.xml` files from this `stig/` folder.
4. Repeat per asset or scan file as needed.

OVAL-only files may be supported depending on your Viewer version; if import fails,
use the corresponding XCCDF result from the same scan when available.

AUTHORITATIVE DATA
------------------
The XML files in this folder are the authoritative machine format for re-import.
`stig/manifest.json` lists files and metadata. The Excel workbook
`auditor-workbook.xlsx` (in the bundle root) includes sheets
`STIG_STIGViewer_Files`, `STIG_Check_Results`, and `STIG_VAT_Findings` for human review.

For questions on VAT export layout, see `evidence-manifest.json` in the bundle root.
""".strip()
