"""Base adapter interfaces — VAT schema contracts."""

from typing import Optional, Protocol, runtime_checkable

from app.schemas.vat import (
    VatFindingSchema,
    VatSourceIgnoreRequest,
    VatSourceUnignoreRequest,
    VatTrackerCommentUpdate,
    VatTrackerCreateIssueRequest,
    VatTrackerPostDecisionRequest,
    VatTrackerUpdateIssueRequest,
)
from app.adapters.registry import SourceAdapterCapabilities, TrackerAdapterCapabilities


@runtime_checkable
class SourceAdapter(Protocol):
    """Maps source native format ↔ VAT schemas."""

    def get_capabilities(self) -> SourceAdapterCapabilities: ...

    async def to_vat_finding(self, payload: dict) -> VatFindingSchema: ...

    async def ignore_issue(self, request: VatSourceIgnoreRequest) -> None: ...

    async def unignore_issue(self, request: VatSourceUnignoreRequest) -> None: ...


@runtime_checkable
class TrackerAdapter(Protocol):
    """Maps VAT schemas ↔ tracker API."""

    def get_capabilities(self) -> TrackerAdapterCapabilities: ...

    async def create_issue(self, request: VatTrackerCreateIssueRequest) -> str: ...

    async def post_comment(self, request: VatTrackerPostDecisionRequest) -> None: ...

    async def update_issue(self, request: VatTrackerUpdateIssueRequest) -> None: ...

    def to_vat_comment_update(self, payload: dict) -> VatTrackerCommentUpdate | None: ...
