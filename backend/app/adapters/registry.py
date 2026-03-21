"""Adapter registry — source and tracker adapters register here."""

from dataclasses import dataclass
from typing import Callable, TypeVar

# Adapter key -> adapter class
SOURCE_ADAPTER_REGISTRY: dict[str, type] = {}
TRACKER_ADAPTER_REGISTRY: dict[str, type] = {}

T = TypeVar("T")


def register_source_adapter(key: str) -> Callable[[type[T]], type[T]]:
    """Decorator to register a source adapter."""

    def decorator(cls: type[T]) -> type[T]:
        if key in SOURCE_ADAPTER_REGISTRY:
            raise ValueError(f"Source adapter '{key}' already registered")
        SOURCE_ADAPTER_REGISTRY[key] = cls
        return cls

    return decorator


def register_tracker_adapter(key: str) -> Callable[[type[T]], type[T]]:
    """Decorator to register a tracker adapter."""

    def decorator(cls: type[T]) -> type[T]:
        if key in TRACKER_ADAPTER_REGISTRY:
            raise ValueError(f"Tracker adapter '{key}' already registered")
        TRACKER_ADAPTER_REGISTRY[key] = cls
        return cls

    return decorator


@dataclass(frozen=True)
class SourceAdapterCapabilities:
    """Capabilities declared by a source adapter."""

    supports_ignore: bool = False
    supports_unignore: bool = False
    supports_inbound_sync: bool = False  # Can receive updates (webhook/polling)?


@dataclass(frozen=True)
class TrackerAdapterCapabilities:
    """Capabilities declared by a tracker adapter."""

    supports_create_issue: bool = True
    supports_post_comment: bool = True
    supports_update_issue: bool = False  # PATCH labels, status, title, etc.
    supports_list_issues: bool = False
    supports_inbound_sync: bool = False  # Webhook/polling → VAT
