"""Archive extraction for scan-archive mode. Extracts to temp, caller scans, then cleans up."""

from __future__ import annotations

import shutil
import tarfile
import zipfile
from pathlib import Path

# Supported extensions (lowercase)
ZIP_EXTENSIONS = {".zip", ".jar", ".war", ".ear"}
TAR_EXTENSIONS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"}


def is_archive(path: Path) -> bool:
    """Return True if path looks like a supported archive."""
    if not path.is_file():
        return False
    name = path.name.lower()
    for ext in ZIP_EXTENSIONS | TAR_EXTENSIONS:
        if name.endswith(ext) or name == ext.lstrip("."):
            return True
    return False


def extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """
    Extract archive to dest_dir. Returns path to extracted root (dest_dir or single top-level dir).
    Raises ValueError if format unsupported.
    """
    archive_path = archive_path.resolve()
    dest_dir = dest_dir.resolve()
    if not archive_path.is_file():
        raise ValueError(f"Not a file: {archive_path}")

    name = archive_path.name.lower()

    if any(name.endswith(ext) for ext in ZIP_EXTENSIONS):
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dest_dir)
        return _extracted_root(dest_dir)

    if any(name.endswith(ext) for ext in TAR_EXTENSIONS):
        mode = "r"
        if name.endswith(".xz") or name.endswith(".txz"):
            mode = "r:xz"
        elif name.endswith(".bz2") or name.endswith(".tbz2"):
            mode = "r:bz2"
        elif name.endswith(".gz") or name.endswith(".tgz") or name.endswith(".tar.gz"):
            mode = "r:gz"
        with tarfile.open(archive_path, mode) as tf:
            tf.extractall(dest_dir)
        return _extracted_root(dest_dir)

    raise ValueError(f"Unsupported archive format: {archive_path.name}")


def _extracted_root(dest_dir: Path) -> Path:
    """If dest has single top-level dir, return it; else return dest."""
    entries = [p for p in dest_dir.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest_dir


def remove_extracted(path: Path) -> None:
    """Remove extracted directory tree."""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
