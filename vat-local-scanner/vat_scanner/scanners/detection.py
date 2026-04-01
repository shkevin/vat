"""Content detection: which scanners to run based on folder contents."""

from __future__ import annotations

import json
import fnmatch
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from vat_scanner.container_digest import compute_container_image_digest

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

# PRD §3.2 trigger conditions
GRYPE_INDICATORS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
)
GRYPE_EXTENSIONS = (".rpm", ".deb", ".apk", ".jar")
CONTAINER_EXTENSIONS = (".tar",)
SEMGREP_EXTENSIONS = (
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".sh", ".bash", ".go", ".java", ".rb", ".php",
)
NPM_INDICATORS = ("package.json",)
PIP_INDICATORS = ("requirements.txt", "Pipfile", "pyproject.toml")


def _has_any(
    folder: Path,
    names: tuple[str, ...],
    extensions: tuple[str, ...] = (),
    max_depth: int = 4,
) -> bool:
    """Check if any of these names or extensions exist under folder."""
    for p in folder.rglob("*"):
        try:
            rel = p.relative_to(folder)
        except ValueError:
            continue
        if len(rel.parts) > max_depth:
            continue
        if p.name in names:
            return True
        if extensions and p.suffix.lower() in extensions:
            return True
    return False


def has_grype_content(folder: Path) -> bool:
    """Folder has packages Grype can scan."""
    return (
        _has_any(folder, GRYPE_INDICATORS, GRYPE_EXTENSIONS)
        or (folder / "node_modules").is_dir()
    )


def has_container_tarballs(folder: Path, max_depth: int = 3) -> list[Path]:
    """Return list of .tar files that may be container images."""
    return [
        p
        for p in folder.rglob("*.tar")
        if p.is_file() and len(p.relative_to(folder).parts) <= max_depth
    ]


@dataclass
class ContainerSource:
    """A discoverable container image: docker-save tar or OCI layout dir."""

    path: Path
    format: str  # "docker-save" | "oci-layout"
    label: str  # For asset naming, e.g. "kamiwaza-abc123"
    image_ref: str | None = None  # Best-effort repo/name:tag from source metadata
    # Deterministic digest from disk (see container_digest); same for all scanners on this source
    image_digest: str | None = None


def _with_computed_digest(src: ContainerSource) -> ContainerSource:
    d = compute_container_image_digest(src.path, src.format)
    return replace(src, image_digest=d)


def _tar_listing(archive: Path, cache: dict[tuple[str, int, int], str]) -> str | None:
    """List tar contents once per unique file stat."""
    try:
        stat = archive.stat()
        key = (str(archive), int(stat.st_size), int(stat.st_mtime_ns))
    except OSError:
        return None
    if key in cache:
        return cache[key]
    try:
        result = subprocess.run(
            ["tar", "-tf", str(archive)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    cache[key] = result.stdout
    return result.stdout


def _tar_is_docker_save(listing: str) -> bool:
    """Check if tar listing matches docker save format."""
    for line in listing.strip().splitlines():
        p = line.strip().rstrip("/")
        if p in ("manifest.json", "./manifest.json"):
            return True
    return False


def _tar_has_wrap_files(listing: str) -> bool:
    """Check if tar listing contains .wrap files (Helm/imgpkg bundle)."""
    return ".wrap" in listing


def _docker_save_image_ref(archive: Path) -> str | None:
    """Extract first RepoTag from docker-save tar manifest.json."""
    try:
        result = subprocess.run(
            ["tar", "-xOf", str(archive), "manifest.json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        data = json.loads(result.stdout)
        if not isinstance(data, list) or not data:
            return None
        first = data[0]
        if not isinstance(first, dict):
            return None
        repo_tags = first.get("RepoTags") or []
        if isinstance(repo_tags, list) and repo_tags:
            tag = repo_tags[0]
            if isinstance(tag, str) and tag.strip():
                return tag.strip()
        return None
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def _find_oci_layouts(root: Path) -> list[Path]:
    """Find OCI image layout directories under root (contain oci-layout + index.json)."""
    layouts: list[Path] = []
    for oci_layout in root.rglob("oci-layout"):
        layout_dir = oci_layout.parent
        if (layout_dir / "index.json").exists():
            layouts.append(layout_dir)
    return layouts


def _is_excluded(rel_path: Path, exclude: list[str] | None) -> bool:
    """Return True when relative path matches any exclude pattern."""
    if not exclude:
        return False
    rel = rel_path.as_posix().strip("/")
    if not rel:
        return False
    for raw in exclude:
        p = (raw or "").strip()
        if not p:
            continue
        p = p.replace("\\", "/").lstrip("./")
        candidates = [p]
        if p.endswith("/"):
            candidates.append(f"{p}**")
        if not p.startswith("**/"):
            candidates.append(f"**/{p}")
            if p.endswith("/**"):
                candidates.append(f"**/{p}")
        if p.startswith("**/"):
            candidates.append(p[3:])
        if p.endswith("/**") and not p.endswith("**/**"):
            candidates.append(p[:-3])
        for pat in candidates:
            if fnmatch.fnmatch(rel, pat):
                return True
    return False


def _get_imgpkg_images_lock(wrap_extract: Path) -> dict[str, str]:
    """
    Parse .imgpkg/images.yml (imgpkg ImagesLock) and return digest -> image_ref mapping.
    imgpkg format: image: registry/repo@sha256:digest, annotations.kbld.carvel.dev/id: "name:tag"
    """
    digest_to_ref: dict[str, str] = {}
    if not yaml:
        return digest_to_ref
    for imgpkg_path in wrap_extract.rglob(".imgpkg/images.yml"):
        try:
            data = yaml.safe_load(imgpkg_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            images = data.get("images") or []
            for entry in images:
                if not isinstance(entry, dict):
                    continue
                image = entry.get("image")
                if not isinstance(image, str) or "@sha256:" not in image:
                    continue
                _pre, digest_part = image.rsplit("@sha256:", 1)
                digest = re.sub(r"[^0-9a-f]", "", digest_part.lower())[:64]
                if len(digest) >= 12:
                    ref = (entry.get("annotations") or {}).get("kbld.carvel.dev/id")
                    if isinstance(ref, str) and ref.strip():
                        digest_to_ref[digest] = ref.strip()
                    else:
                        # Extract repo/image from image field: registry/repo/name@sha256:...
                        ref = image.split("@")[0]
                        parts = ref.split("/")
                        if len(parts) >= 2:
                            digest_to_ref[digest] = "/".join(parts[-2:])  # repo/name
                        else:
                            digest_to_ref[digest] = parts[-1] if parts else digest[:12]
        except (OSError, yaml.YAMLError, KeyError):
            continue
    return digest_to_ref


def _get_chart_images_lock(wrap_extract: Path) -> dict[str, str]:
    """
    Parse chart/Images.lock (kajiya/Helm Distribution Tooling format) and return digest -> image_ref.
    Format: images[].image + images[].digests[].digest (sha256:hex)
    Layout dirs are named <full64hex>.layout, so we match on normalized digest.
    """
    digest_to_ref: dict[str, str] = {}
    if not yaml:
        return digest_to_ref
    for lock_path in wrap_extract.rglob("chart/Images.lock"):
        try:
            data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            images = data.get("images") or []
            for entry in images:
                if not isinstance(entry, dict):
                    continue
                image_ref = entry.get("image")
                if not isinstance(image_ref, str) or not image_ref.strip():
                    continue
                digests = entry.get("digests") or []
                for dg in digests:
                    if not isinstance(dg, dict):
                        continue
                    digest_val = dg.get("digest")
                    if not isinstance(digest_val, str) or "sha256:" not in digest_val:
                        continue
                    digest_hex = re.sub(r"[^0-9a-f]", "", digest_val.lower().split("sha256:")[-1])[:64]
                    if len(digest_hex) >= 12:
                        digest_to_ref[digest_hex] = image_ref.strip()
        except (OSError, yaml.YAMLError, KeyError):
            continue
    return digest_to_ref


def _get_oci_image_ref_name(layout_dir: Path) -> str | None:
    """
    Extract human-readable image ref from OCI layout index.json.
    Returns e.g. "redis:7", "vllm-cpu:latest", or None if not found.
    """
    try:
        data = json.loads((layout_dir / "index.json").read_text(encoding="utf-8"))
        manifests = data.get("manifests") or []
        for m in manifests:
            ann = m.get("annotations") or {}
            ref = ann.get("org.opencontainers.image.ref.name")
            if ref and isinstance(ref, str) and ref.strip():
                return ref.strip()
        return None
    except (OSError, json.JSONDecodeError, KeyError):
        return None


def _sanitize_image_ref_for_label(ref: str) -> str:
    """Convert image ref to a safe label: ghcr.io/foo/bar:v1 -> bar-v1."""
    # Strip registry and path, keep last component + tag
    parts = ref.split("/")
    name_tag = parts[-1] if parts else ref
    # Replace : with - for label safety
    return re.sub(r"[^a-zA-Z0-9._-]", "-", name_tag).strip("-") or "image"


def _process_wrap_sources(
    wrap_extract: Path,
    wrap_name: str,
    uid: str,
) -> list[ContainerSource]:
    """
    Process an extracted wrap directory and return container sources.
    Used by collect_container_sources; exposed for testing.
    """
    sources: list[ContainerSource] = []
    digest_to_ref = _get_imgpkg_images_lock(wrap_extract)
    digest_to_ref.update(_get_chart_images_lock(wrap_extract))
    seen_labels: set[str] = set()
    for layout_dir in _find_oci_layouts(wrap_extract):
        digest_raw = layout_dir.name.removesuffix(".layout") if layout_dir.name else ""
        digest_short = digest_raw[:12] if digest_raw else uid
        parent_name = layout_dir.parent.name if layout_dir.parent else ""

        image_ref = _get_oci_image_ref_name(layout_dir)
        if not image_ref and digest_to_ref:
            layout_hex = re.sub(r"[^0-9a-f]", "", digest_raw.lower())
            if layout_hex.startswith("sha256"):
                layout_hex = layout_hex[6:]
            for d, ref in digest_to_ref.items():
                if layout_hex == d or layout_hex.startswith(d) or d.startswith(layout_hex):
                    image_ref = ref
                    break

        if image_ref:
            img_label = _sanitize_image_ref_for_label(image_ref)
            if parent_name == "images":
                label = f"{wrap_name}-images-{img_label}"
            else:
                label = f"{wrap_name}-{img_label}"
            if label in seen_labels:
                label = f"{label}-{digest_short}"
        else:
            if parent_name == "images":
                label = f"{wrap_name}-images-{digest_short}"
            else:
                label = f"{wrap_name}-{digest_short}"
        seen_labels.add(label)
        sources.append(
            _with_computed_digest(
                ContainerSource(
                    path=layout_dir,
                    format="oci-layout",
                    label=label,
                    image_ref=image_ref,
                )
            )
        )
    return sources


def collect_container_sources(
    folder: Path,
    *,
    temp_dir: Path | None = None,
    max_depth: int = 3,
    exclude: list[str] | None = None,
) -> tuple[list[ContainerSource], list[Path]]:
    """
    Discover container images: direct docker-save tars and OCI layouts inside .wrap bundles.
    Returns (sources, extract_dirs_to_cleanup). Caller must rmtree each dir when done.
    """
    sources: list[ContainerSource] = []
    extract_dirs: list[Path] = []
    work = Path(temp_dir) if temp_dir else Path("/tmp")
    work.mkdir(parents=True, exist_ok=True)
    tar_cache: dict[tuple[str, int, int], str] = {}

    for tar_path in folder.rglob("*.tar"):
        if not tar_path.is_file() or len(tar_path.relative_to(folder).parts) > max_depth:
            continue
        rel_tar = tar_path.relative_to(folder)
        if _is_excluded(rel_tar, exclude):
            continue

        tar_listing = _tar_listing(tar_path, tar_cache)
        if not tar_listing:
            continue

        if _tar_is_docker_save(tar_listing):
            sources.append(
                _with_computed_digest(
                    ContainerSource(
                        path=tar_path,
                        format="docker-save",
                        label=tar_path.stem,
                        image_ref=_docker_save_image_ref(tar_path),
                    )
                )
            )
            continue

        if not _tar_has_wrap_files(tar_listing):
            continue

        # Wrap bundle: extract and process .wrap files
        uid = uuid.uuid4().hex[:12]
        extract_dir = work / f"vat-wrap-{uid}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        extract_dirs.append(extract_dir)
        try:
            subprocess.run(
                ["tar", "-xf", str(tar_path), "-C", str(extract_dir)],
                capture_output=True,
                check=True,
                timeout=600,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            shutil.rmtree(extract_dir, ignore_errors=True)
            extract_dirs.remove(extract_dir)
            continue

        for wrap_path in extract_dir.rglob("*.wrap"):
            if not wrap_path.is_file():
                continue
            wrap_name = wrap_path.stem
            wrap_extract = extract_dir / f"wrap-{wrap_name}-{uid}"
            wrap_extract.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["tar", "-xzf", str(wrap_path), "-C", str(wrap_extract)],
                    capture_output=True,
                    check=True,
                    timeout=600,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                shutil.rmtree(wrap_extract, ignore_errors=True)
                continue

            for src in _process_wrap_sources(wrap_extract, wrap_name, uid):
                sources.append(src)

    return (sources, extract_dirs)


def has_npm_content(folder: Path) -> bool:
    """Folder has package.json (root only)."""
    return (folder / "package.json").is_file()


def has_pip_content(folder: Path) -> bool:
    """Folder has Python deps file (root only)."""
    return any((folder / n).is_file() for n in PIP_INDICATORS)


def has_semgrep_content(folder: Path) -> bool:
    """Folder has code files Semgrep can scan."""
    return _has_any(folder, (), SEMGREP_EXTENSIONS)
