"""Scanner subprocess runners."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tarfile
import uuid
from pathlib import Path

# Chainguard OpenSCAP image for STIG scans (DISA-aligned, GPOS SRG)
# Use latest (free) instead of latest-dev which may require Chainguard access
OPENSCAP_IMAGE = "cgr.dev/chainguard/openscap:latest"
STIG_PROFILE = "xccdf_basic_profile_.check"
STIG_DATASTREAM = "/usr/share/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml"


def _docker_rmi_best_effort(image_ref: str, timeout: int = 60) -> None:
    """Cleanup helper: ``docker rmi`` may hang under daemon contention.

    Treat as best-effort — a failed cleanup must not abort the scan, since the
    image is no longer needed by the calling routine. Bumped timeout (60s) and
    swallowed exceptions cover transient daemon stalls during parallel scans.
    """
    try:
        subprocess.run(
            ["docker", "rmi", image_ref],
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def _trivy_skip_args(exclude: list[str] | None) -> list[str]:
    """Build --skip-dirs and --skip-files from exclude patterns."""
    if not exclude:
        return []
    args: list[str] = []
    for p in exclude:
        p = p.strip()
        if not p:
            continue
        # File patterns (e.g. **/*.min.js) -> skip-files; dir patterns -> skip-dirs
        if "*" in p and "." in p.split("*")[-1] and not p.endswith("/**") and not p.endswith("/*"):
            args.extend(["--skip-files", p])
        else:
            # Normalize dir patterns: **/foo/** -> **/foo for Trivy
            dir_p = p.rstrip("/").rstrip("*")
            if dir_p:
                args.extend(["--skip-dirs", dir_p])
    return args


def run_trivy_fs(
    folder: Path,
    *,
    disable_artifact_scanning: bool = False,
    timeout: int = 300,
    exclude: list[str] | None = None,
    temp_dir: Path | None = None,
) -> dict:
    """Run trivy fs and return JSON. Scanners: vuln, secret, license, misconfig."""
    scanners = "vuln,secret,license,misconfig"
    if disable_artifact_scanning:
        # Skip rootfs/package scanning for speed
        scanners = "secret,license,misconfig"

    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    out_file = temp_dir / f"trivy-fs-{uuid.uuid4().hex[:12]}.json"

    cmd = [
        "trivy",
        "fs",
        str(folder),
        "--scanners",
        scanners,
        "--format",
        "json",
        "-o",
        str(out_file),
        "--quiet",
    ]
    cmd[2:2] = _trivy_skip_args(exclude)  # Insert skip args after "fs"
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise ScannerNotFoundError("trivy not found. Install: https://trivy.dev/docs/installation/") from e
    except subprocess.TimeoutExpired as e:
        raise ScannerTimeoutError("trivy timed out") from e

    try:
        if not out_file.exists():
            return {"Results": []}
        with open(out_file) as f:
            return json.load(f)
    finally:
        out_file.unlink(missing_ok=True)


def run_trivy_image(tar_path: Path, timeout: int = 120) -> dict | None:
    """Run trivy image --input on a tar. Returns JSON or None on failure."""
    try:
        result = subprocess.run(
            ["trivy", "image", "--input", str(tar_path), "--format", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def run_trivy_image_ref(
    image_ref: str,
    timeout: int = 120,
    docker_config_path: Path | None = None,
    image_src: str | None = None,
    containerd_address: str | None = None,
    containerd_namespace: str | None = None,
) -> dict | None:
    """Run trivy image on image reference (e.g. myregistry/app:v1). Returns JSON or None."""
    env = os.environ.copy()
    env.setdefault("TRIVY_CACHE_DIR", "/tmp/trivy-cache")
    env.setdefault("XDG_CACHE_HOME", "/tmp")
    if docker_config_path is not None:
        env["DOCKER_CONFIG"] = str(docker_config_path)
    if containerd_address:
        env["CONTAINERD_ADDRESS"] = str(containerd_address)
    if containerd_namespace:
        env["CONTAINERD_NAMESPACE"] = str(containerd_namespace)
    cmd = ["trivy", "image", image_ref, "--format", "json", "--quiet"]
    if image_src:
        cmd.extend(["--image-src", image_src])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def run_trivy_image_ref_cyclonedx(
    image_ref: str,
    timeout: int = 180,
    docker_config_path: Path | None = None,
    image_src: str | None = None,
    containerd_address: str | None = None,
    containerd_namespace: str | None = None,
) -> dict | None:
    """Run trivy image on image reference and return CycloneDX JSON SBOM."""
    env = os.environ.copy()
    env.setdefault("TRIVY_CACHE_DIR", "/tmp/trivy-cache")
    env.setdefault("XDG_CACHE_HOME", "/tmp")
    if docker_config_path is not None:
        env["DOCKER_CONFIG"] = str(docker_config_path)
    if containerd_address:
        env["CONTAINERD_ADDRESS"] = str(containerd_address)
    if containerd_namespace:
        env["CONTAINERD_NAMESPACE"] = str(containerd_namespace)
    cmd = [
        "trivy",
        "image",
        image_ref,
        "--format",
        "cyclonedx",
        "--list-all-pkgs",
        "--quiet",
    ]
    if image_src:
        cmd.extend(["--image-src", image_src])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def _skopeo_copy_oci_to_docker(
    oci_layout_dir: Path,
    image_ref: str,
    timeout: int = 120,
    *,
    verbose: bool = False,
) -> bool:
    """Load OCI layout into Docker via skopeo. Returns True on success."""
    try:
        # Resolve to absolute path so skopeo sees correct path inside container.
        # --retry-times helps with transient "io: read/write on closed pipe" (Docker 26.x)
        oci_path = oci_layout_dir.resolve()
        result = subprocess.run(
            ["skopeo", "copy", "--retry-times", "3", f"oci:{oci_path}", f"docker-daemon:{image_ref}"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and verbose:
            import sys
            err = (result.stderr or "").strip() or (result.stdout or "").strip()
            if err:
                for line in err.splitlines()[:8]:
                    print(f"    skopeo: {line}", file=sys.stderr, flush=True)
        return result.returncode == 0
    except FileNotFoundError:
        if verbose:
            import sys
            print("    skopeo: not found", file=sys.stderr, flush=True)
        return False
    except subprocess.TimeoutExpired:
        if verbose:
            import sys
            print("    skopeo: timeout", file=sys.stderr, flush=True)
        return False


def _docker_load_and_get_image_ref(tar_path: Path, timeout: int = 60) -> str | None:
    """
    Load container image from tar and return image reference for oscap-docker.
    Parses 'Loaded image: repo:tag' or 'Loaded image ID: sha256:xxx'.
    """
    try:
        result = subprocess.run(
            ["docker", "load", "-i", str(tar_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip() + "\n" + result.stderr.strip()
    # "Loaded image: busybox:latest" or "Loaded image ID: sha256:abc123..."
    m = re.search(r"Loaded image:\s+(\S+)", out)
    if m:
        return m.group(1).strip()
    m = re.search(r"Loaded image ID:\s+(sha256:[a-fA-F0-9]+)", out)
    if m:
        return m.group(1)
    return None


def run_stig_image(
    tar_path: Path,
    asset_name: str,
    timeout: int = 180,
    *,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> str | None:
    """
    Run Chainguard OpenSCAP STIG scan on a container image from a tar file.
    Uses Chainguard GPOS STIG profile (DISA-aligned).
    Returns XCCDF results XML as string, or None on failure.
    """
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"stig-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.xml"

    try:
        image_ref = _docker_load_and_get_image_ref(tar_path, timeout=min(60, timeout))
        if not image_ref:
            if verbose:
                import sys
                print("  WARN: docker load failed for", tar_path.name, file=sys.stderr, flush=True)
            return None

        # Run Chainguard openscap container (minimal image, no shell; use oscap-docker directly)
        cmd = [
            "docker",
            "run",
            "-i",
            "--rm",
            "-u",
            "0:0",
            "--pid=host",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{out_dir}:/out",
            "--entrypoint",
            "oscap-docker",
            OPENSCAP_IMAGE,
            "image",
            image_ref,
            "xccdf",
            "eval",
            "--profile",
            STIG_PROFILE,
            "--report",
            "/out/report.html",
            "--results",
            "/out/results.xml",
            STIG_DATASTREAM,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # oscap exit codes: 0=all pass, 1=error, 2=findings (fail/unknown) — treat 0 and 2 as success
        if result.returncode not in (0, 2) or not results_path.exists():
            if verbose and (result.stderr or result.stdout):
                import sys
                err = (result.stderr or "").strip() or (result.stdout or "").strip()
                if err:
                    for line in err.splitlines()[:5]:
                        print(f"    {line}", file=sys.stderr, flush=True)
            return None
        return results_path.read_text(encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys
            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return None
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def run_stig_oci_layout(
    oci_layout_dir: Path,
    asset_name: str,
    timeout: int = 180,
    *,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> str | None:
    """
    Run Chainguard OpenSCAP STIG scan on an OCI image layout (e.g. from .wrap).
    Uses skopeo to load into Docker, then oscap-docker. Returns XCCDF results XML.
    """
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"stig-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.xml"
    image_ref = f"vat-scan-{uuid.uuid4().hex[:12]}:latest"

    try:
        if not _skopeo_copy_oci_to_docker(
            oci_layout_dir, image_ref, timeout=min(300, timeout), verbose=verbose
        ):
            if verbose:
                import sys
                print("  WARN: skopeo copy to docker-daemon failed for", oci_layout_dir.name, file=sys.stderr, flush=True)
            return None

        # Chainguard openscap is minimal (no shell); use oscap-docker directly
        cmd = [
            "docker",
            "run",
            "-i",
            "--rm",
            "-u",
            "0:0",
            "--pid=host",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{out_dir}:/out",
            "--entrypoint",
            "oscap-docker",
            OPENSCAP_IMAGE,
            "image",
            image_ref,
            "xccdf",
            "eval",
            "--profile",
            STIG_PROFILE,
            "--report",
            "/out/report.html",
            "--results",
            "/out/results.xml",
            STIG_DATASTREAM,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        _docker_rmi_best_effort(image_ref)
        # oscap exit codes: 0=all pass, 1=error, 2=findings — treat 0 and 2 as success
        if result.returncode not in (0, 2) or not results_path.exists():
            if verbose and (result.stderr or result.stdout):
                import sys
                err = (result.stderr or "").strip() or (result.stdout or "").strip()
                if err:
                    for line in err.splitlines()[:5]:
                        print(f"    {line}", file=sys.stderr, flush=True)
            return None
        return results_path.read_text(encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys
            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return None
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def run_stig_image_ref(
    image_ref: str,
    asset_name: str,
    timeout: int = 600,
    *,
    docker_host: str | None = None,
    docker_config_path: Path | None = None,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> str | None:
    """
    Run OpenSCAP STIG on an image reference without requiring a Docker daemon.

    Runtime scans run on containerd-only nodes, so this path uses skopeo to copy
    the image to a docker archive, unpacks the root filesystem, and evaluates it
    with oscap-chroot.
    """
    if not image_ref:
        return None
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"stig-ref-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = out_dir / "image.tar"
    rootfs_path = out_dir / "rootfs"
    rootfs_path.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.html"
    results_path = out_dir / "results.xml"
    env = os.environ.copy()
    env["TMPDIR"] = str(out_dir)
    env["TMP"] = str(out_dir)
    env["TEMP"] = str(out_dir)
    if docker_config_path is not None:
        env["DOCKER_CONFIG"] = str(docker_config_path)
    skopeo_cmd = [
        "skopeo",
        "--tmpdir",
        str(out_dir),
        "copy",
        f"docker://{image_ref}",
        f"docker-archive:{archive_path}",
    ]
    authfile = (Path(docker_config_path) / "config.json") if docker_config_path else None
    if authfile is not None and authfile.exists():
        skopeo_cmd[4:4] = ["--src-authfile", str(authfile)]

    try:
        skopeo = subprocess.run(
            skopeo_cmd,
            capture_output=True,
            text=True,
            timeout=min(300, timeout),
            env=env,
        )
        if skopeo.returncode != 0:
            if verbose and (skopeo.stderr or skopeo.stdout):
                import sys

                err = (skopeo.stderr or "").strip() or (skopeo.stdout or "").strip()
                if err:
                    for line in err.splitlines()[:5]:
                        print(f"    {line}", file=sys.stderr, flush=True)
            return None
        if not _extract_docker_archive_rootfs(archive_path, rootfs_path):
            if verbose:
                import sys

                print(f"    unable to extract image rootfs for {image_ref}", file=sys.stderr, flush=True)
            return None
        cmd = [
            "oscap-chroot",
            str(rootfs_path),
            "xccdf",
            "eval",
            "--profile",
            STIG_PROFILE,
            "--report",
            str(report_path),
            "--results",
            str(results_path),
            STIG_DATASTREAM,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if result.returncode not in (0, 2) or not results_path.exists():
            if verbose and (result.stderr or result.stdout):
                import sys

                err = (result.stderr or "").strip() or (result.stdout or "").strip()
                if err:
                    for line in err.splitlines()[:5]:
                        print(f"    {line}", file=sys.stderr, flush=True)
            return None
        return results_path.read_text(encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys

            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return None
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def _safe_member_path(root: Path, name: str) -> Path | None:
    target = (root / name.lstrip("/")).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def _apply_layer_tar(layer_file, rootfs_path: Path) -> None:
    with tarfile.open(fileobj=layer_file, mode="r:*") as layer:
        for member in layer:
            name = member.name
            base = Path(name).name
            if base.startswith(".wh."):
                parent = _safe_member_path(rootfs_path, str(Path(name).parent))
                if parent is None:
                    continue
                if base == ".wh..wh..opq":
                    continue
                target = parent / base.removeprefix(".wh.")
                if target.is_dir() and not target.is_symlink():
                    import shutil

                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
                continue

            target = _safe_member_path(rootfs_path, name)
            if target is None:
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with layer.extractfile(member) as src:
                    if src is None:
                        continue
                    with target.open("wb") as dst:
                        import shutil

                        shutil.copyfileobj(src, dst)
                target.chmod(member.mode & 0o777)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.unlink(missing_ok=True)
                target.symlink_to(member.linkname)


def _extract_docker_archive_rootfs(archive_path: Path, rootfs_path: Path) -> bool:
    """Extract docker-archive layers into a rootfs directory for oscap-chroot."""
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            manifest_member = archive.getmember("manifest.json")
            manifest_file = archive.extractfile(manifest_member)
            if manifest_file is None:
                return False
            manifest = json.loads(manifest_file.read().decode("utf-8"))
            layers = manifest[0].get("Layers") if manifest else None
            if not isinstance(layers, list) or not layers:
                return False
            for layer_name in layers:
                if not isinstance(layer_name, str):
                    continue
                layer_member = archive.getmember(layer_name)
                layer_file = archive.extractfile(layer_member)
                if layer_file is None:
                    continue
                _apply_layer_tar(layer_file, rootfs_path)
        return True
    except (OSError, tarfile.TarError, KeyError, json.JSONDecodeError, IndexError):
        return False


# oscap-docker image-cve emits this when image is not RHEL/Fedora
_OVAL_NOT_RHEL = "is not based on RHEL"


def run_oval_cve_image(
    tar_path: Path,
    asset_name: str,
    timeout: int = 300,
    *,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> tuple[str | None, bool]:
    """
    Run OpenSCAP OVAL CVE scan on a container image from a tar file.
    Uses oscap-docker image-cve (downloads CVE stream for detected OS).
    Returns (xml_content, skip_remaining). skip_remaining=True when image is not
    RHEL-based — caller should skip remaining OVAL CVE scans.
    """
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"oval-cve-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "oval-results.xml"

    try:
        image_ref = _docker_load_and_get_image_ref(tar_path, timeout=min(60, timeout))
        if not image_ref:
            if verbose:
                import sys
                print("  WARN: docker load failed for", tar_path.name, file=sys.stderr, flush=True)
            return (None, False)

        cmd = [
            "docker",
            "run",
            "-i",
            "--rm",
            "-u",
            "0:0",
            "--pid=host",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{out_dir}:/out",
            "--entrypoint",
            "oscap-docker",
            OPENSCAP_IMAGE,
            "image-cve",
            image_ref,
            "--results",
            "/out/oval-results.xml",
            "--report",
            "/out/report.html",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # oscap oval exit codes: 0=no vulns, 1=error, 2=vulns found
        if result.returncode not in (0, 2) or not results_path.exists():
            err = (result.stderr or "").strip() or (result.stdout or "").strip()
            skip = _OVAL_NOT_RHEL in err
            if verbose and err and not skip:
                import sys
                for line in err.splitlines()[:5]:
                    print(f"    {line}", file=sys.stderr, flush=True)
            return (None, skip)
        return (results_path.read_text(encoding="utf-8", errors="replace"), False)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys
            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return (None, False)
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def run_oval_cve_oci_layout(
    oci_layout_dir: Path,
    asset_name: str,
    timeout: int = 300,
    *,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> tuple[str | None, bool]:
    """
    Run OpenSCAP OVAL CVE scan on an OCI image layout (e.g. from .wrap).
    Uses skopeo to load into Docker, then oscap-docker image-cve.
    Returns (xml_content, skip_remaining). skip_remaining=True when image is not
    RHEL-based — caller should skip remaining OVAL CVE scans.
    """
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"oval-cve-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "oval-results.xml"
    image_ref = f"vat-scan-{uuid.uuid4().hex[:12]}:latest"

    try:
        if not _skopeo_copy_oci_to_docker(
            oci_layout_dir, image_ref, timeout=min(300, timeout), verbose=verbose
        ):
            if verbose:
                import sys
                print("  WARN: skopeo copy to docker-daemon failed for", oci_layout_dir.name, file=sys.stderr, flush=True)
            return (None, False)

        cmd = [
            "docker",
            "run",
            "-i",
            "--rm",
            "-u",
            "0:0",
            "--pid=host",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{out_dir}:/out",
            "--entrypoint",
            "oscap-docker",
            OPENSCAP_IMAGE,
            "image-cve",
            image_ref,
            "--results",
            "/out/oval-results.xml",
            "--report",
            "/out/report.html",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        _docker_rmi_best_effort(image_ref)
        if result.returncode not in (0, 2) or not results_path.exists():
            err = (result.stderr or "").strip() or (result.stdout or "").strip()
            skip = _OVAL_NOT_RHEL in err
            if verbose and err and not skip:
                import sys
                for line in err.splitlines()[:5]:
                    print(f"    {line}", file=sys.stderr, flush=True)
            return (None, skip)
        return (results_path.read_text(encoding="utf-8", errors="replace"), False)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys
            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return (None, False)
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def run_node_stig(
    host_root: Path,
    asset_name: str,
    timeout: int = 600,
    *,
    datastream_path: Path | None = None,
    profile: str | None = None,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> str | None:
    """
    Run OpenSCAP STIG evaluation against a mounted host root.

    Node STIG content varies by OS, so the caller must provide a datastream path
    through the argument or ``VAT_NODE_STIG_DATASTREAM``. Missing content is a
    clean skip, not a node-agent failure.
    """
    host_root = Path(host_root)
    raw_datastream = datastream_path or os.environ.get("VAT_NODE_STIG_DATASTREAM", "")
    datastream = Path(raw_datastream) if raw_datastream else None
    if not host_root.exists() or datastream is None or not datastream.exists():
        return None
    profile_id = profile or os.environ.get("VAT_NODE_STIG_PROFILE", STIG_PROFILE)
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"node-stig-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "results.xml"
    try:
        result = subprocess.run(
            [
                "oscap",
                "xccdf",
                "eval",
                "--chroot",
                str(host_root),
                "--profile",
                profile_id,
                "--results",
                str(results_path),
                str(datastream),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode not in (0, 2) or not results_path.exists():
            if verbose and (result.stderr or result.stdout):
                import sys
                err = (result.stderr or result.stdout).strip()
                for line in err.splitlines()[:5]:
                    print(f"    {line}", file=sys.stderr, flush=True)
            return None
        return results_path.read_text(encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys
            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return None
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def run_node_oval_cve(
    host_root: Path,
    asset_name: str,
    timeout: int = 600,
    *,
    definitions_path: Path | None = None,
    temp_dir: Path | None = None,
    verbose: bool = False,
) -> str | None:
    """
    Run OpenSCAP OVAL evaluation against a mounted host root.

    Requires explicit OVAL definitions via argument or
    ``VAT_NODE_OVAL_DEFINITIONS``. Missing content is a clean skip.
    """
    host_root = Path(host_root)
    raw_definitions = definitions_path or os.environ.get("VAT_NODE_OVAL_DEFINITIONS", "")
    definitions = Path(raw_definitions) if raw_definitions else None
    if not host_root.exists() or definitions is None or not definitions.exists():
        return None
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    out_dir = temp_dir / f"node-oval-{uuid.uuid4().hex[:12]}"
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "oval-results.xml"
    try:
        result = subprocess.run(
            [
                "oscap",
                "oval",
                "eval",
                "--chroot",
                str(host_root),
                "--results",
                str(results_path),
                str(definitions),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode not in (0, 2) or not results_path.exists():
            if verbose and (result.stderr or result.stdout):
                import sys
                err = (result.stderr or result.stdout).strip()
                for line in err.splitlines()[:5]:
                    print(f"    {line}", file=sys.stderr, flush=True)
            return None
        return results_path.read_text(encoding="utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        if verbose:
            import sys
            print(f"    {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        return None
    finally:
        import shutil

        shutil.rmtree(out_dir, ignore_errors=True)


def run_trivy_oci_layout(oci_layout_dir: Path, timeout: int = 120) -> dict | None:
    """Run trivy image --input on an OCI layout directory. Returns JSON or None."""
    try:
        result = subprocess.run(
            ["trivy", "image", "--input", str(oci_layout_dir), "--format", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def run_trivy_fs_cyclonedx(
    folder: Path,
    *,
    timeout: int = 300,
    exclude: list[str] | None = None,
    temp_dir: Path | None = None,
) -> dict | None:
    """Run trivy fs --format cyclonedx and return JSON SBOM."""
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    out_file = temp_dir / f"trivy-fs-sbom-{uuid.uuid4().hex[:12]}.json"
    cmd = [
        "trivy",
        "fs",
        str(folder),
        "--format",
        "cyclonedx",
        "--list-all-pkgs",
        "-o",
        str(out_file),
        "--quiet",
    ]
    cmd[2:2] = _trivy_skip_args(exclude)
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None
    try:
        if not out_file.exists():
            return None
        with open(out_file) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    finally:
        out_file.unlink(missing_ok=True)


def run_trivy_image_cyclonedx(
    tar_path: Path,
    timeout: int = 180,
    *,
    mode_stats: dict[str, int] | None = None,
) -> dict | None:
    """Run trivy image --input --format cyclonedx and return JSON SBOM."""
    def _scan_ref(image_ref: str) -> dict | None:
        try:
            result = subprocess.run(
                ["trivy", "image", image_ref, "--format", "cyclonedx", "--list-all-pkgs", "--quiet"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return None
        if result.returncode != 0 or not result.stdout.strip():
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None

    # Fast path for direct tar input.
    try:
        result = subprocess.run(
            ["trivy", "image", "--input", str(tar_path), "--format", "cyclonedx", "--list-all-pkgs", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        result = None
    if result and result.returncode == 0 and result.stdout.strip():
        try:
            if mode_stats is not None:
                mode_stats["trivy_image_input_ok"] = mode_stats.get("trivy_image_input_ok", 0) + 1
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    # Fallback path: load tar into Docker and scan by image ref.
    image_ref = _docker_load_and_get_image_ref(tar_path, timeout=min(60, timeout))
    if not image_ref:
        return None
    try:
        if mode_stats is not None:
            mode_stats["trivy_image_docker_fallback"] = mode_stats.get("trivy_image_docker_fallback", 0) + 1
        return _scan_ref(image_ref)
    finally:
        _docker_rmi_best_effort(image_ref)


def run_trivy_oci_layout_cyclonedx(
    oci_layout_dir: Path,
    timeout: int = 180,
    *,
    mode_stats: dict[str, int] | None = None,
) -> dict | None:
    """Run trivy image --input on OCI layout in CycloneDX format."""
    def _scan_ref(image_ref: str) -> dict | None:
        try:
            result = subprocess.run(
                ["trivy", "image", image_ref, "--format", "cyclonedx", "--list-all-pkgs", "--quiet"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return None
        if result.returncode != 0 or not result.stdout.strip():
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None

    # Fast path for direct OCI layout input.
    try:
        result = subprocess.run(
            ["trivy", "image", "--input", str(oci_layout_dir), "--format", "cyclonedx", "--list-all-pkgs", "--quiet"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        result = None
    if result and result.returncode == 0 and result.stdout.strip():
        try:
            if mode_stats is not None:
                mode_stats["trivy_oci_input_ok"] = mode_stats.get("trivy_oci_input_ok", 0) + 1
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

    # Fallback path: copy OCI layout to Docker daemon and scan by image ref.
    image_ref = f"vat-sbom-{uuid.uuid4().hex[:12]}:latest"
    if not _skopeo_copy_oci_to_docker(oci_layout_dir, image_ref, timeout=min(300, timeout)):
        return None
    try:
        if mode_stats is not None:
            mode_stats["trivy_oci_skopeo_fallback"] = mode_stats.get("trivy_oci_skopeo_fallback", 0) + 1
        return _scan_ref(image_ref)
    finally:
        _docker_rmi_best_effort(image_ref)


def run_gitleaks(
    folder: Path,
    timeout: int = 120,
    *,
    temp_dir: Path | None = None,
) -> dict | None:
    """Run gitleaks detect. Returns JSON or None if not installed. --no-git scans filesystem."""
    temp_dir = Path(temp_dir) if temp_dir else Path("/tmp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    out_file = temp_dir / f"gitleaks-{uuid.uuid4().hex[:12]}.json"
    try:
        subprocess.run(
            ["gitleaks", "detect", "--no-git", "--report-format", "json", "--report-path", str(out_file)],
            capture_output=True,
            timeout=timeout,
            cwd=folder,
        )
    except FileNotFoundError:
        return None
    try:
        if out_file.exists():
            with open(out_file) as f:
                return json.load(f)
    finally:
        out_file.unlink(missing_ok=True)
    return None


def run_grype(
    folder: Path,
    timeout: int = 120,
    *,
    exclude: list[str] | None = None,
) -> dict | None:
    """Run grype dir. Returns JSON or None if not installed."""
    cmd = ["grype", f"dir:{folder}", "-o", "json"]
    if exclude:
        for p in exclude:
            p = p.strip()
            if p:
                cmd.extend(["--exclude", p])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def run_npm_audit(folder: Path, timeout: int = 60) -> dict | None:
    """Run npm audit --json in folder. Returns JSON or None."""
    if not (folder / "package.json").is_file():
        return None
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=folder,
        )
    except FileNotFoundError:
        return None
    if not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)
        if data.get("error"):
            return None
        return data
    except json.JSONDecodeError:
        return None


def run_pip_audit(folder: Path, timeout: int = 60) -> dict | list | None:
    """Run pip-audit --format json. Returns JSON or None."""
    if not any((folder / n).is_file() for n in ("requirements.txt", "Pipfile", "pyproject.toml")):
        return None
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=folder,
        )
    except FileNotFoundError:
        return None
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def run_semgrep(
    folder: Path,
    timeout: int = 180,
    *,
    exclude: list[str] | None = None,
) -> dict | None:
    """Run semgrep scan --json. Returns JSON or None."""
    cmd = ["semgrep", "scan", "--json", str(folder)]
    if exclude:
        for p in exclude:
            p = p.strip()
            if p:
                cmd.extend(["--exclude", p])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return None
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


class ScannerNotFoundError(Exception):
    """Scanner binary not found."""

    pass


class ScannerTimeoutError(Exception):
    """Scanner timed out."""

    pass
