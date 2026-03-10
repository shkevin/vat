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

    def _create_payload(self, fields: dict, asset: str | None = None) -> CanonicalFindingPayload:
        """Create a canonical payload with asset context. Injects image=asset when needed for validation."""
        has_asset = any(fields.get(k) for k in ("image", "branch", "tag"))
        if not has_asset:
            if asset:
                fields = {**fields, "image": asset}
            else:
                raise ValueError("Asset context required: provide asset or set image/branch/tag in fields")
        return CanonicalFindingPayload(**fields)
