"""Centralized tag policy for ingest flows."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.schemas.vat import VatFindingSchema


def _clean(value: str | None) -> str:
    return str(value or "").strip()


@dataclass(frozen=True)
class IngestTagPolicy:
    """Tag handling policy derived from ingest headers."""

    header_tag: str | None
    authoritative_tag: str | None
    force_override: bool

    @classmethod
    def from_headers(
        cls, *, asset_override: str | None, tag_override: str | None
    ) -> "IngestTagPolicy":
        asset = _clean(asset_override) or None
        tag = _clean(tag_override) or None
        force = bool(asset and tag)
        return cls(
            header_tag=tag,
            authoritative_tag=tag if force else None,
            force_override=force,
        )

    @property
    def has_header_tag(self) -> bool:
        return bool(self.header_tag)

    @property
    def sbom_tag(self) -> str | None:
        return self.header_tag

    def apply_to_payload(self, payload: VatFindingSchema) -> VatFindingSchema:
        """Apply tag policy to one finding payload.

        In single-asset mode (asset + tag header), the header tag is
        authoritative and normalizes every finding to one asset snapshot.
        Otherwise parser-supplied tags win and the header tag only fills the
        field when the parser left it empty.
        """
        if not self.header_tag:
            return payload
        if self.force_override and self.authoritative_tag:
            return payload.model_copy(update={"tag": self.authoritative_tag})
        existing = _clean(getattr(payload, "tag", None))
        if existing:
            return payload
        return payload.model_copy(update={"tag": self.header_tag})

    async def normalize_existing_source_asset_tags(
        self, db: AsyncSession, *, source_name: str, asset_id: str | None
    ) -> int:
        """
        Backfill deduped rows so source+asset converges to one authoritative tag.

        This is intentionally limited to single-asset mode (force_override=True).
        """
        if not self.force_override or not self.authoritative_tag:
            return 0
        source = _clean(source_name)
        asset = _clean(asset_id)
        if not source or not asset:
            return 0
        result = await db.execute(
            update(Finding)
            .where(
                Finding.source == source,
                or_(Finding.image == asset, Finding.component == asset),
                or_(
                    Finding.tag.is_(None),
                    Finding.tag != self.authoritative_tag,
                ),
            )
            .values(tag=self.authoritative_tag)
        )
        return int(result.rowcount or 0)
