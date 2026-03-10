"""Shared parser utilities. Used by Semgrep, Trivy, SARIF, CodeQL, etc."""

# Key injected by vat-local-scanner for package delineation (scan date/tag)
VAT_SCAN_TAG_KEY = "_vat_scan_tag"

# Key for source image/container when scanning a bundle — use for file_path (provenance)
VAT_SOURCE_IMAGE_KEY = "_vat_source_image"
# Key for original path when scanning filesystem — use for file_path (scanner preserves before overwriting Target)
VAT_SOURCE_PATH_KEY = "_vat_source_path"


def extract_scan_tag(raw: dict | list) -> str | None:
    """Extract scan tag from report (injected by vat-local-scanner). Returns None if absent."""
    if isinstance(raw, dict):
        tag = raw.get(VAT_SCAN_TAG_KEY)
        return str(tag).strip() if tag else None
    return None


def normalize_snippet(s: str | list | None, max_len: int = 500) -> str | None:
    """
    Normalize a line snippet for storage. For general findings (SAST, IaC, SARIF)
    the snippet is stored as-is (no masking). For secrets, callers mask first.
    Returns None if empty.
    """
    if s is None:
        return None
    if isinstance(s, list):
        s = "\n".join(str(x).strip() for x in s if x is not None and str(x).strip())
    elif not isinstance(s, str):
        return None
    else:
        s = s.strip()
    if not s:
        return None
    return s[:max_len]


def extract_cwe_id(cwe_list: list | str | int | None) -> str | None:
    """
    Extract CWE-XXX from metadata. Normalizes all shapes to "CWE-NNN":
    - Semgrep (list): ["CWE-89: SQL Injection", "CWE-943: ..."]
    - Plain string: "CWE-89: SQL Injection" or "CWE-89"
    - Trivy/SARIF (integer): 89 → "CWE-89"

    Returns the first CWE-XXX identifier or None.
    """
    if cwe_list is None:
        return None

    def _normalize(s: str | int) -> str | None:
        if isinstance(s, int):
            return f"CWE-{s}" if s >= 0 else None
        s = str(s).strip()
        if not s:
            return None
        if s.upper().startswith("CWE-"):
            return s.split(":")[0].strip()
        if s.isdigit():
            return f"CWE-{s}"
        return s

    if isinstance(cwe_list, (int, float)):
        return _normalize(int(cwe_list))
    if isinstance(cwe_list, str) and cwe_list.strip():
        return _normalize(cwe_list)
    if isinstance(cwe_list, list) and cwe_list:
        first = cwe_list[0]
        if first is not None:
            return _normalize(first)
    return None
