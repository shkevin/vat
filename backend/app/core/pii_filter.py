"""PII exclusion for logs — PRD §7.3. Redact owner email, approver name from log output."""

import logging
import re

# Patterns to redact from log messages (emails, common PII per PRD §7.3)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_APPROVER_NAME_RE = re.compile(r"approver[:\s\"']+[^\"'\s]+(?:\s+[^\"'\s]+)?", re.I)
_OWNER_RE = re.compile(r"owner[:\s]+['\"]?[^'\"]+@[^'\"]+['\"]?", re.I)
# JSON-style: "approver":"John Doe" or "approver": "Jane"
_APPROVER_JSON_RE = re.compile(r'"(?:approver|approverName|approver_name)"\s*:\s*"[^"]*"', re.I)
_OWNER_JSON_RE = re.compile(r'"(?:owner|ownerEmail|owner_email)"\s*:\s*"[^"]*"', re.I)


def redact_pii(msg: str) -> str:
    """Redact PII from a log message string (owner email, approver name)."""
    if not isinstance(msg, str):
        return str(msg)
    out = _EMAIL_RE.sub("[REDACTED_EMAIL]", msg)
    out = _APPROVER_NAME_RE.sub("approver: [REDACTED]", out)
    out = _OWNER_RE.sub("owner: [REDACTED]", out)
    out = _APPROVER_JSON_RE.sub('"approver": "[REDACTED]"', out)
    out = _OWNER_JSON_RE.sub('"owner": "[REDACTED]"', out)
    return out


class PIIFilter(logging.Filter):
    """Logging filter that redacts PII from log records. Applied to app.* loggers."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_pii(str(record.msg))
        if record.args:
            record.args = tuple(redact_pii(str(a)) for a in record.args)
        return True
