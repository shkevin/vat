"""Per-request logging context (trace_id / tenant_id / user_id).

Anything emitted from code running on the request tree inherits the
request's trace id without having to pass it explicitly. Implementation:
``contextvars.ContextVar`` set at middleware time + a ``logging.Filter``
that copies the current values onto every ``LogRecord``.

Add the filter to a logger via ``logging.getLogger(...).addFilter(
LogContextFilter())``. The fields land on the record as ``trace_id``,
``tenant_id``, ``user_id`` so a structured handler can serialize them.
The default text formatter is unaffected unless its format string
references those fields.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Optional

_trace_id_var: ContextVar[Optional[str]] = ContextVar("vat_trace_id", default=None)
_tenant_id_var: ContextVar[Optional[str]] = ContextVar("vat_tenant_id", default=None)
_user_id_var: ContextVar[Optional[str]] = ContextVar("vat_user_id", default=None)


def set_trace_id(trace_id: Optional[str]) -> None:
    _trace_id_var.set(trace_id)


def set_tenant_id(tenant_id: Optional[str]) -> None:
    _tenant_id_var.set(tenant_id)


def set_user_id(user_id: Optional[str]) -> None:
    _user_id_var.set(user_id)


def get_trace_id() -> Optional[str]:
    return _trace_id_var.get()


def get_tenant_id() -> Optional[str]:
    return _tenant_id_var.get()


def get_user_id() -> Optional[str]:
    return _user_id_var.get()


class LogContextFilter(logging.Filter):
    """Copy ContextVars onto each LogRecord as attributes.

    Filters are mutators in Python's logging stdlib — returning True
    keeps the record. We always return True; the side effect is the
    attribute set so downstream formatters can reference
    ``%(trace_id)s`` etc. without ``KeyError`` when no context is set.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.trace_id = _trace_id_var.get() or "-"
        record.tenant_id = _tenant_id_var.get() or "-"
        record.user_id = _user_id_var.get() or "-"
        return True
