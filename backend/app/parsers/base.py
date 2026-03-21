"""Base parser interface for ingest."""

from abc import ABC, abstractmethod

from app.schemas.ingest import CanonicalFindingPayload


class IngestParser(ABC):
    """Base interface for ingest parsers."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Parser identifier (e.g. 'sarif', 'canonical')."""
        pass

    @abstractmethod
    def parse(self, raw: dict | list) -> list[CanonicalFindingPayload]:
        """Transform raw input to canonical payloads. Raises ValueError on parse failure."""
        pass

    def _create_payload(
        self, fields: dict, asset: str | None = None
    ) -> CanonicalFindingPayload:
        """Create a canonical payload with asset context. Injects image=asset when needed for validation."""
        fields = dict(fields)
        # Tag alone must not skip image injection (e.g. container image tag + Target as asset)
        if asset and not fields.get("image") and not fields.get("branch"):
            fields["image"] = asset
        has_asset = any(fields.get(k) for k in ("image", "branch", "tag"))
        if not has_asset:
            raise ValueError(
                "Asset context required: provide asset or set image/branch/tag in fields"
            )
        return CanonicalFindingPayload(**fields)
