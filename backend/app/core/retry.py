"""Retry with exponential backoff. PRD §7.2 — minimum 3 attempts."""

import asyncio
import logging
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def retry_async(
    fn: Callable[[], "asyncio.coroutine[None, None, T]"],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> T:
    """
    Execute async callable with exponential backoff.
    Raises last exception if all attempts fail.
    """
    last_exc = None
    for attempt in range(max_attempts):
        try:
            return await fn()
        except Exception as e:
            last_exc = e
            if attempt < max_attempts - 1:
                delay = min(base_delay * (2**attempt), max_delay)
                logger.warning(
                    "Attempt %d/%d failed: %s. Retrying in %.1fs",
                    attempt + 1,
                    max_attempts,
                    e,
                    delay,
                )
                await asyncio.sleep(delay)
    raise last_exc
