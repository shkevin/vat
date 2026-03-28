"""Ingest API — single endpoint for all manual sources. PRD §5.1, design doc 2026-02-24."""

import json
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.settings import get_source_config
from app.core.database import get_db
from app.core.ingest_auth import get_ingest_source
from app.models.asset import Asset
from app.parsers import (
    PARSER_IDENTITY_POLICY,
    extract_asset_hint,
    get_parser,
    parser_accepts_input_kind,
)
from app.schemas.vat import VatFindingSchema
from app.services.asset_resolver import (
    resolve_asset_for_payload,
    resolve_ingest_stub_asset_identity,
)
from app.services.asset_aliases import (
    resolve_canonical_asset_id,
    upsert_asset_alias,
)
from app.services.audit_events import emit_audit_event
from app.services.container_ref_normalization import is_safe_tag_only_alias_variant
from app.services.ingest import ingest_finding
from app.services.ingest_enrichment import enrich_payload_for_correlation
from app.services.observability import IngestLatencyTimer
from app.services.openscap_storage import (
    compute_evidence_sha256,
    store_openscap_scan_result,
)
from app.services.sbom import import_sbom
from app.services.sbom_extract import extract_sbom_from_report

router = APIRouter()
logger = logging.getLogger(__name__)


async def _ensure_asset_record(
    db: AsyncSession,
    asset_id: str,
    source_name: str,
    asset_type: str = "package",
) -> bool:
    """Create Asset record if missing so zero-finding scans appear in frontend."""
    if not asset_id or not asset_id.strip():
        return False
    asset_id = asset_id.strip()
    existing = await db.get(Asset, asset_id)
    if existing:
        return False
    db.add(
        Asset(
            id=asset_id,
            name=asset_id,
            type=asset_type or "package",
            source=source_name,
            branch=None,
            tag=None,
        )
    )
    await db.commit()
    return True


def _remap_payload_asset_context(
    payload: VatFindingSchema, *, old_asset_id: str, new_asset_id: str
) -> VatFindingSchema:
    """Rewrite payload asset fields when a manual alias override exists."""
    old_id = (old_asset_id or "").strip()
    new_id = (new_asset_id or "").strip()
    if not old_id or not new_id or old_id == new_id:
        return payload

    updates: dict[str, str] = {}
    if (payload.image or "").strip() == old_id:
        updates["image"] = new_id
    if (payload.component or "").strip() == old_id:
        updates["component"] = new_id
    # package-mode findings often use tag=asset for grouping scope
    if (payload.tag or "").strip() == old_id:
        updates["tag"] = new_id
    return payload.model_copy(update=updates) if updates else payload


def _apply_asset_type_transform(
    payload: VatFindingSchema, asset_type: Optional[str]
) -> VatFindingSchema:
    """
    When asset_type=package, rewrite image→component so VAT infers package instead of container.
    Skip when both image and component are present (container+package): keep image as asset, component as package.
    Schema requires at least one of image/branch/tag; we set tag=asset for validation.
    """
    if not asset_type or str(asset_type).strip().lower() != "package":
        return payload
    img = (payload.image or "").strip()
    comp = (payload.component or "").strip()
    # Preserve container+package hierarchy: image=container, component=package (e.g. Trivy container scan)
    if img and comp and img != comp:
        return payload
    asset_val = img or comp
    if not asset_val:
        return payload
    # Move asset to component; set tag for schema validation; clear image
    return payload.model_copy(
        update={"image": None, "component": asset_val, "tag": asset_val},
        deep=True,
    )


async def _ingest_from_parser(
    db: AsyncSession,
    raw: dict | list,
    parser_id: str,
    source: str,
    source_config: Optional[dict] = None,
    *,
    asset_override: Optional[str] = None,
    tag_override: Optional[str] = None,
    source_image_override: Optional[str] = None,
    image_digest_override: Optional[str] = None,
    trace_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    strict_asset_mapping: bool = False,
    scan_session_id: Optional[str] = None,
    scanner_version: Optional[str] = None,
) -> dict:
    """
    Parse payload with configured parser and ingest findings.
    Returns {created, merged, source, message}.
    """
    parser = get_parser(parser_id)
    trace_id = trace_id or uuid.uuid4().hex
    await emit_audit_event(
        db,
        trace_id=trace_id,
        event_type="ingest.parser.selected",
        actor_type="api_client",
        actor_id=actor_id,
        source_id=source,
        parser_id=parser_id,
        decision_name="parser_selection",
        decision_reason_code="configured_parser",
        decision_confidence="explicit",
        decision_result="selected",
        data={"parser_id": parser_id},
    )
    try:
        payloads = parser.parse(raw)
    except ValueError as e:
        await emit_audit_event(
            db,
            trace_id=trace_id,
            event_type="ingest.parser.failed",
            actor_type="api_client",
            actor_id=actor_id,
            source_id=source,
            parser_id=parser_id,
            decision_name="parser_parse",
            decision_reason_code="parse_error",
            decision_confidence="high",
            decision_result="failed",
            data={"error": str(e)},
        )
        raise HTTPException(status_code=422, detail=f"Parse error: {e}") from e

    sbom_created = 0
    sbom_updated = 0
    sbom_component = source_image_override or asset_override

    if not payloads:
        # Ensure Asset record so zero-finding scans appear in frontend
        base_asset = (
            asset_override
            or source_image_override
            or extract_asset_hint(parser_id, raw)
        )
        asset_type = (
            (source_config or {}).get("asset_type")
            or (source_config or {}).get("assetType")
            or "package"
        )
        if base_asset:
            stub_id, stub_type = await resolve_ingest_stub_asset_identity(
                db,
                asset_hint=base_asset,
                parser_id=parser_id,
                source_asset_type=asset_type,
            )
            if stub_id:
                await _ensure_asset_record(db, stub_id, source, stub_type)
        if parser_id in ("openscap", "openscap_oval"):
            logger.info(
                "OpenSCAP ingest %s: source=%s created=0 merged=0 (no fail results in XML)",
                parser_id,
                source,
            )
            if isinstance(raw, bytes) and base_asset:
                stig_asset_id = (
                    f"{base_asset}_{source_image_override}"[:256]
                    if source_image_override
                    else base_asset
                )
                try:
                    await store_openscap_scan_result(
                        db, raw, parser_id, source, stig_asset_id, tenant_id=None
                    )
                except Exception as e:
                    logger.warning("Failed to store OpenSCAP scan result: %s", e)
        # Still extract and import SBOM from Trivy/Grype/CycloneDX
        sbom_doc = extract_sbom_from_report(parser_id, raw, source)
        if sbom_doc:
            try:
                sbom_created, sbom_updated = await import_sbom(
                    db, sbom_doc, source=source, component=sbom_component
                )
                if sbom_created or sbom_updated:
                    logger.info(
                        "SBOM import: %d created, %d updated from %s",
                        sbom_created,
                        sbom_updated,
                        source,
                    )
            except Exception as e:
                logger.warning("SBOM import failed for %s: %s", source, e)
        return {
            "created": 0,
            "merged": 0,
            "sbomCreated": sbom_created,
            "sbomUpdated": sbom_updated,
            "source": source,
            "traceId": trace_id,
            "message": f"No findings in {parser_id} payload",
        }

    asset_type = (source_config or {}).get("asset_type") or (source_config or {}).get(
        "assetType"
    )
    created = 0
    merged = 0
    raw_evidence_ref: Optional[str] = None
    if parser_id in ("openscap", "openscap_oval") and isinstance(raw, bytes):
        raw_evidence_ref = compute_evidence_sha256(raw)
    for p in payloads:
        try:
            p = enrich_payload_for_correlation(p, parser_id=parser_id, source_id=source)
            policy = PARSER_IDENTITY_POLICY.get(parser_id, {})
            requires_explicit_asset = bool(policy.get("requires_explicit_asset", False))
            p, resolution = resolve_asset_for_payload(
                p,
                parser_id=parser_id,
                source_id=source,
                asset_override=asset_override,
                strict_mode=strict_asset_mapping,
                requires_explicit_asset=requires_explicit_asset,
            )
            raw_asset_id = (resolution.raw_asset_id or "").strip()
            if raw_asset_id and raw_asset_id != resolution.asset_id:
                if is_safe_tag_only_alias_variant(raw_asset_id, resolution.asset_id):
                    await upsert_asset_alias(
                        db,
                        source_asset_id=raw_asset_id,
                        canonical_asset_id=resolution.asset_id,
                        created_by="system:auto-tag-alias",
                    )
                    await emit_audit_event(
                        db,
                        trace_id=trace_id,
                        event_type="asset.alias.auto_created",
                        actor_type="api_client",
                        actor_id=actor_id,
                        source_id=source,
                        parser_id=parser_id,
                        asset_id=resolution.asset_id,
                        decision_name="asset_alias_auto",
                        decision_reason_code="tag_only_variant",
                        decision_confidence="high",
                        decision_result="created",
                        data={
                            "source_asset_id": raw_asset_id,
                            "canonical_asset_id": resolution.asset_id,
                        },
                    )
            canonical_asset_id = await resolve_canonical_asset_id(
                db, resolution.asset_id
            )
            if canonical_asset_id and canonical_asset_id != resolution.asset_id:
                p = _remap_payload_asset_context(
                    p,
                    old_asset_id=resolution.asset_id,
                    new_asset_id=canonical_asset_id,
                )
                resolution.asset_id = canonical_asset_id
                resolution.reason = "manual_asset_alias_override"
                resolution.confidence = "explicit"
            await emit_audit_event(
                db,
                trace_id=trace_id,
                event_type="asset.mapping.resolved",
                actor_type="api_client",
                actor_id=actor_id,
                source_id=source,
                parser_id=parser_id,
                asset_id=resolution.asset_id,
                decision_name="asset_mapping",
                decision_reason_code=resolution.reason,
                decision_confidence=resolution.confidence,
                decision_result=resolution.asset_kind,
                data=resolution.to_api_dict(),
            )
            if asset_override:
                p = p.model_copy(update={"image": asset_override})
            # Prefer per-finding tag from parser (e.g. container image tag) over header when set
            if tag_override:
                existing_tag = getattr(p, "tag", None)
                if not (existing_tag and str(existing_tag).strip()):
                    p = p.model_copy(update={"tag": tag_override})
            if image_digest_override:
                existing_dig = getattr(p, "image_digest", None)
                if not (existing_dig and str(existing_dig).strip()):
                    p = p.model_copy(update={"image_digest": image_digest_override})
            # Bundle scans: source_image identifies which container (redis, metrics-server) failed
            if source_image_override and parser_id in ("openscap", "openscap_oval"):
                comp = (p.component or "").strip()
                if comp and comp != source_image_override:
                    p = p.model_copy(
                        update={"component": f"{source_image_override} ({comp})"}
                    )
                else:
                    p = p.model_copy(update={"component": source_image_override})
            p = _apply_asset_type_transform(p, asset_type)
            finding, is_new = await ingest_finding(
                db,
                p,
                source_name=source,
                trace_id=trace_id,
                parser_id=parser_id,
                scan_session_id=scan_session_id,
                scanner_version=scanner_version,
                raw_evidence_ref=raw_evidence_ref,
            )
            await emit_audit_event(
                db,
                trace_id=trace_id,
                event_type="dedup.replay.new" if is_new else "dedup.replay.merged",
                actor_type="api_client",
                actor_id=actor_id,
                source_id=source,
                parser_id=parser_id,
                asset_id=(p.image or p.component),
                finding_id=getattr(finding, "id", None),
                decision_name="replay_dedup",
                decision_reason_code="fingerprint_lookup",
                decision_confidence="high",
                decision_result="created" if is_new else "merged",
                data={"finding_id": getattr(finding, "id", None)},
            )
            if is_new:
                created += 1
            else:
                merged += 1
        except Exception as e:
            logger.warning("Ingest failed for %s: %s", getattr(p, "cve_id", "?"), e)
            await emit_audit_event(
                db,
                trace_id=trace_id,
                event_type="ingest.finding.failed",
                actor_type="api_client",
                actor_id=actor_id,
                source_id=source,
                parser_id=parser_id,
                decision_name="finding_ingest",
                decision_reason_code="exception",
                decision_confidence="high",
                decision_result="failed",
                data={"cve_id": getattr(p, "cve_id", "?"), "error": str(e)},
            )

    # Extract and import SBOM from Trivy/Grype/CycloneDX reports
    sbom_doc = extract_sbom_from_report(parser_id, raw, source)
    if sbom_doc:
        try:
            sbom_created, sbom_updated = await import_sbom(
                db, sbom_doc, source=source, component=sbom_component
            )
            if sbom_created or sbom_updated:
                logger.info(
                    "SBOM import: %d created, %d updated from %s",
                    sbom_created,
                    sbom_updated,
                    source,
                )
        except Exception as e:
            logger.warning("SBOM import failed for %s: %s", source, e)

    if parser_id in ("openscap", "openscap_oval") and isinstance(raw, bytes):
        base_asset = (
            asset_override
            or source_image_override
            or (payloads[0].image if payloads else None)
            or extract_asset_hint(parser_id, raw)
        )
        # Bundle scans: one XCCDF per container; use composite key so we don't overwrite
        if base_asset and source_image_override:
            asset_id = f"{base_asset}_{source_image_override}"[:256]
        else:
            asset_id = base_asset
        if asset_id:
            try:
                await store_openscap_scan_result(
                    db, raw, parser_id, source, asset_id, tenant_id=None
                )
            except Exception as e:
                logger.warning("Failed to store OpenSCAP scan result: %s", e)

    result = {
        "created": created,
        "merged": merged,
        "sbomCreated": sbom_created,
        "sbomUpdated": sbom_updated,
        "source": source,
        "traceId": trace_id,
        "message": f"Ingested {created} new, {merged} merged findings",
    }
    if parser_id in ("openscap", "openscap_oval"):
        logger.info(
            "OpenSCAP ingest %s: source=%s created=%d merged=%d",
            parser_id,
            source,
            created,
            merged,
        )
    return result


def _is_xml_content(content: bytes) -> bool:
    """Check if content looks like XML (for OpenSCAP parser)."""
    stripped = content.lstrip()
    return stripped.startswith(b"<?xml") or stripped.startswith(b"<")


def _resolve_parser(source_config: dict | None, source_id: str) -> str:
    """Resolve parser from source config. Default sarif for backward compat."""
    if source_config and source_config.get("parser"):
        return str(source_config["parser"]).strip().lower()
    return "sarif"


@router.post("")
async def post_ingest(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ingest_auth: tuple[Optional[str], Optional[str]] = Depends(get_ingest_source),
):
    """
    Single ingest endpoint. Accepts JSON body or file upload.
    Auth required: Authorization: Bearer <key> or X-VAT-API-Key.
    Parser is determined by source config in Settings.
    Optional headers: X-VAT-Asset, X-VAT-Tag, X-VAT-Source-Image, X-VAT-Image-Digest — override asset context for bundle scans.
    X-VAT-Source-Image: container label within bundle (e.g. redis, metrics-server) so component identifies which image failed.
    X-VAT-Image-Digest: canonical ``sha256:…`` for the container artifact (same for all parsers on that image).
    """
    with IngestLatencyTimer():
        auth_source, _ = ingest_auth
        asset_override = (request.headers.get("X-VAT-Asset") or "").strip() or None
        tag_override = (request.headers.get("X-VAT-Tag") or "").strip() or None
        source_image_override = (
            request.headers.get("X-VAT-Source-Image") or ""
        ).strip() or None
        image_digest_override = (
            request.headers.get("X-VAT-Image-Digest") or ""
        ).strip() or None
        trace_id = (
            getattr(request.state, "trace_id", "")
            or request.headers.get("X-Trace-Id")
            or ""
        ).strip() or uuid.uuid4().hex
        strict_asset_mapping = (
            request.headers.get("X-VAT-Strict-Asset-Mapping") or ""
        ).strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )
        scan_session_id = (
            request.headers.get("X-VAT-Scan-Session-ID") or trace_id
        ).strip()
        scanner_version = (
            request.headers.get("X-VAT-Scanner-Version") or ""
        ).strip() or None
        if auth_source is None:
            await emit_audit_event(
                db,
                trace_id=trace_id,
                event_type="ingest.auth.rejected",
                actor_type="api_client",
                actor_id="unknown",
                decision_name="ingest_auth",
                decision_reason_code="missing_api_key",
                decision_confidence="high",
                decision_result="rejected",
                data={},
            )
            raise HTTPException(
                status_code=401,
                detail="Ingest requires API key. Use Authorization: Bearer <key> or X-VAT-API-Key.",
            )

        source_id = auth_source
        await emit_audit_event(
            db,
            trace_id=trace_id,
            event_type="ingest.auth.validated",
            actor_type="api_client",
            actor_id=source_id,
            source_id=source_id,
            decision_name="ingest_auth",
            decision_reason_code="api_key_valid",
            decision_confidence="high",
            decision_result="validated",
            data={"source_id": source_id},
        )
        source_config = await get_source_config(db, source_id)
        parser_id = _resolve_parser(source_config, source_id)

        # Parse request body — JSON, XML (OpenSCAP), or multipart file
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            form = await request.form()
            f = form.get("file")
            if not f or not hasattr(f, "read"):
                raise HTTPException(
                    status_code=400,
                    detail="File upload requires 'file' field in multipart/form-data",
                )
            content = await f.read()
            if parser_id in ("openscap", "openscap_oval") and _is_xml_content(content):
                raw = content
            else:
                try:
                    raw = json.loads(content)
                except json.JSONDecodeError as e:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid JSON in file: {e}"
                    ) from e
        elif "application/json" in content_type:
            try:
                raw = await request.json()
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}") from e
        elif parser_accepts_input_kind(parser_id, "xml") and (
            "application/xml" in content_type or "text/xml" in content_type
        ):
            raw = await request.body()
            if not _is_xml_content(raw):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid XML body for {parser_id} parser",
                )
        else:
            raise HTTPException(
                status_code=400,
                detail="Send JSON body (Content-Type: application/json), XML (application/xml for XML parsers), or file upload (multipart/form-data with 'file' field)",
            )

        if raw is None:
            raise HTTPException(status_code=400, detail="Empty payload")

        return await _ingest_from_parser(
            db,
            raw,
            parser_id,
            source_id,
            source_config,
            asset_override=asset_override,
            tag_override=tag_override,
            source_image_override=source_image_override,
            image_digest_override=image_digest_override,
            trace_id=trace_id,
            actor_id=source_id,
            strict_asset_mapping=strict_asset_mapping,
            scan_session_id=scan_session_id,
            scanner_version=scanner_version,
        )


@router.post("/sarif")
async def post_ingest_sarif_body(
    body: dict,
    source: str = "sarif",
    db: AsyncSession = Depends(get_db),
    ingest_auth: tuple[Optional[str], Optional[str]] = Depends(get_ingest_source),
):
    """
    [Deprecated] Use POST /api/ingest with parser from source config.
    Ingest SARIF JSON from request body.
    """
    auth_source, _ = ingest_auth
    source_name = auth_source or source
    if auth_source is None:
        raise HTTPException(
            status_code=401,
            detail="Ingest requires API key. Use Authorization: Bearer <key> or X-VAT-API-Key.",
        )
    return await _ingest_from_parser(db, body, "sarif", source_name, None)


@router.post("/sarif/file")
async def post_ingest_sarif_file(
    file: UploadFile = File(...),
    source: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    ingest_auth: tuple[Optional[str], Optional[str]] = Depends(get_ingest_source),
):
    """
    [Deprecated] Use POST /api/ingest with file upload.
    Ingest SARIF from file upload.
    """
    if not file.filename or not (
        file.filename.lower().endswith(".sarif")
        or file.filename.lower().endswith(".json")
    ):
        raise HTTPException(status_code=400, detail="Expected .sarif or .json file")

    content = await file.read()
    try:
        body = json.loads(content)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}") from e

    auth_source, _ = ingest_auth
    if auth_source is None:
        raise HTTPException(
            status_code=401,
            detail="Ingest requires API key. Use Authorization: Bearer <key> or X-VAT-API-Key.",
        )
    fallback = source or (
        file.filename.replace(".sarif", "").replace(".json", "") or "sarif"
    )
    source_name = auth_source or fallback
    return await _ingest_from_parser(db, body, "sarif", source_name, None)
