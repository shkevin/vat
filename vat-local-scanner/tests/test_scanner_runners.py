from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from vat_scanner.scanners import runners


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_trivy_skip_args_splits_dirs_and_files() -> None:
    args = runners._trivy_skip_args(["**/*.min.js", "node_modules/**", "  ", "dist/*"])
    assert args == [
        "--skip-files",
        "**/*.min.js",
        "--skip-dirs",
        "node_modules/",
        "--skip-dirs",
        "dist/",
    ]


def test_run_trivy_fs_reads_output_file(monkeypatch, tmp_path: Path) -> None:
    def _fake_run(cmd, capture_output=True, check=False, timeout=300):
        out_idx = cmd.index("-o") + 1
        out_path = Path(cmd[out_idx])
        out_path.write_text(json.dumps({"Results": [{"Target": "x"}]}), encoding="utf-8")
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    report = runners.run_trivy_fs(tmp_path, exclude=["dist/**"], temp_dir=tmp_path)
    assert report["Results"][0]["Target"] == "x"


def test_run_trivy_fs_disable_artifact_scanning_changes_scanners(monkeypatch, tmp_path: Path) -> None:
    seen: list[str] = []

    def _fake_run(cmd, capture_output=True, check=False, timeout=300):
        seen.extend(cmd)
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(json.dumps({"Results": []}), encoding="utf-8")
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    runners.run_trivy_fs(tmp_path, disable_artifact_scanning=True, temp_dir=tmp_path)
    idx = seen.index("--scanners")
    assert seen[idx + 1] == "secret,license,misconfig"


def test_run_trivy_fs_returns_empty_when_missing_output(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(0))
    report = runners.run_trivy_fs(tmp_path, temp_dir=tmp_path)
    assert report == {"Results": []}


def test_run_trivy_fs_raises_not_found(monkeypatch, tmp_path: Path) -> None:
    def _raise(*args, **kwargs):
        raise FileNotFoundError("trivy")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    with pytest.raises(runners.ScannerNotFoundError):
        runners.run_trivy_fs(tmp_path, temp_dir=tmp_path)


def test_run_trivy_fs_raises_timeout(monkeypatch, tmp_path: Path) -> None:
    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="trivy", timeout=1)

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    with pytest.raises(runners.ScannerTimeoutError):
        runners.run_trivy_fs(tmp_path, temp_dir=tmp_path)


def test_run_trivy_image_success_and_failures(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")

    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout=json.dumps({"Results": []})),
    )
    assert runners.run_trivy_image(tar) == {"Results": []}

    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1, stdout=""))
    assert runners.run_trivy_image(tar) is None

    def _raise(*args, **kwargs):
        raise FileNotFoundError("trivy")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert runners.run_trivy_image(tar) is None


def test_run_trivy_image_ref_success(monkeypatch) -> None:
    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout=json.dumps({"ok": True})),
    )
    assert runners.run_trivy_image_ref("ghcr.io/acme/app:v1") == {"ok": True}


def test_run_trivy_image_ref_not_found(monkeypatch) -> None:
    def _raise(*args, **kwargs):
        raise FileNotFoundError("trivy")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert runners.run_trivy_image_ref("ghcr.io/acme/app:v1") is None


def test_run_trivy_image_ref_nonzero_or_empty(monkeypatch) -> None:
    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1, stdout=""))
    assert runners.run_trivy_image_ref("ghcr.io/acme/app:v1") is None


def test_safe_member_path_returns_none_for_symlink_loop(tmp_path: Path) -> None:
    root = tmp_path / "rootfs"
    loop_dir = root / "usr" / "lib"
    loop_dir.mkdir(parents=True)
    (loop_dir / "loop").symlink_to("loop")

    assert runners._safe_member_path(root, "usr/lib/loop/file") is None


def test_skopeo_copy_oci_to_docker_paths(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()

    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(0))
    assert runners._skopeo_copy_oci_to_docker(oci, "img:latest")

    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1, stderr="boom"))
    assert not runners._skopeo_copy_oci_to_docker(oci, "img:latest", verbose=True)

    def _raise(*args, **kwargs):
        raise FileNotFoundError("skopeo")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert not runners._skopeo_copy_oci_to_docker(oci, "img:latest", verbose=True)

    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="skopeo", timeout=1)

    monkeypatch.setattr(runners.subprocess, "run", _timeout)
    assert not runners._skopeo_copy_oci_to_docker(oci, "img:latest", verbose=True)


def test_docker_load_and_get_image_ref_parses_output(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")

    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout="Loaded image: busybox:latest\n"),
    )
    assert runners._docker_load_and_get_image_ref(tar) == "busybox:latest"

    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout="", stderr="Loaded image ID: sha256:abcdef"),
    )
    assert runners._docker_load_and_get_image_ref(tar) == "sha256:abcdef"

    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1))
    assert runners._docker_load_and_get_image_ref(tar) is None


def test_run_stig_image_success(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")
    monkeypatch.setattr(runners, "_docker_load_and_get_image_ref", lambda *args, **kwargs: "repo:tag")

    def _fake_run(cmd, capture_output=True, text=True, timeout=180):
        if cmd[:2] == ["docker", "run"]:
            out_mount = [part for part in cmd if part.endswith(":/out")][0]
            out_dir = Path(out_mount.split(":", 1)[0])
            (out_dir / "results.xml").write_text("<xml/>", encoding="utf-8")
            return _Completed(2)
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    assert runners.run_stig_image(tar, "asset", temp_dir=tmp_path) == "<xml/>"


def test_run_stig_image_ref_uses_skopeo_and_oscap_chroot(monkeypatch, tmp_path: Path) -> None:
    commands: list[list[str]] = []
    subprocess_envs: list[dict[str, str]] = []

    def _fake_run(cmd, **kwargs):
        commands.append(cmd)
        subprocess_envs.append(kwargs.get("env") or {})
        if cmd and cmd[0] == "oscap-chroot":
            results_path = Path(cmd[cmd.index("--results") + 1])
            results_path.write_text("<xml/>", encoding="utf-8")
            return _Completed(2)
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    monkeypatch.setattr(runners, "_extract_docker_archive_rootfs", lambda *args, **kwargs: True)
    # OS-aware datastream/profile selection is tested separately; here fix it to the
    # chainguard baseline so we assert the skopeo + oscap-chroot orchestration.
    monkeypatch.setattr(
        runners, "resolve_stig_content_for_rootfs",
        lambda *a, **k: (Path(runners.STIG_DATASTREAM), runners.STIG_PROFILE),
    )

    assert (
        runners.run_stig_image_ref(
            "ghcr.io/acme/app:v1",
            "asset",
            temp_dir=tmp_path,
        )
        == "<xml/>"
    )

    assert commands[0][:3] == ["skopeo", "--tmpdir", subprocess_envs[0]["TMPDIR"]]
    assert commands[0][3:5] == ["copy", "docker://ghcr.io/acme/app:v1"]
    assert commands[0][5].startswith("docker-archive:")
    chroot_cmd = commands[1]
    assert chroot_cmd[0] == "oscap-chroot"
    assert Path(chroot_cmd[1]).name == "rootfs"
    assert chroot_cmd[2:4] == ["xccdf", "eval"]
    assert chroot_cmd[chroot_cmd.index("--profile") + 1] == runners.STIG_PROFILE
    assert Path(chroot_cmd[chroot_cmd.index("--report") + 1]).name == "report.html"
    assert Path(chroot_cmd[chroot_cmd.index("--results") + 1]).name == "results.xml"
    assert chroot_cmd[-1] == runners.STIG_DATASTREAM
    assert Path(subprocess_envs[0]["TMPDIR"]).parent == tmp_path
    assert Path(subprocess_envs[0]["TMP"]).parent == tmp_path
    assert Path(subprocess_envs[0]["TEMP"]).parent == tmp_path


def test_run_stig_rootfs_uses_oscap_chroot(monkeypatch, tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    commands: list[list[str]] = []

    def _fake_run(cmd, capture_output=True, text=True, timeout=600, env=None):
        commands.append(cmd)
        results_path = Path(cmd[cmd.index("--results") + 1])
        results_path.write_text("<xccdf/>", encoding="utf-8")
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    monkeypatch.setattr(
        runners, "resolve_stig_content_for_rootfs",
        lambda *a, **k: (Path(runners.STIG_DATASTREAM), runners.STIG_PROFILE),
    )

    assert runners.run_stig_rootfs(rootfs, "asset", temp_dir=tmp_path) == "<xccdf/>"

    assert commands[0][:4] == ["oscap-chroot", str(rootfs), "xccdf", "eval"]
    assert commands[0][commands[0].index("--profile") + 1] == runners.STIG_PROFILE


def test_run_stig_image_handles_missing_loaded_image(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")
    monkeypatch.setattr(runners, "_docker_load_and_get_image_ref", lambda *args, **kwargs: None)
    assert runners.run_stig_image(tar, "asset", temp_dir=tmp_path) is None


def test_run_stig_oci_layout_success_and_failure(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()

    monkeypatch.setattr(runners, "_skopeo_copy_oci_to_docker", lambda *args, **kwargs: True)

    def _ok_run(cmd, capture_output=True, text=True, timeout=180):
        if cmd[:2] == ["docker", "run"]:
            out_mount = [part for part in cmd if part.endswith(":/out")][0]
            out_dir = Path(out_mount.split(":", 1)[0])
            (out_dir / "results.xml").write_text("<stig/>", encoding="utf-8")
            return _Completed(0)
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _ok_run)
    assert runners.run_stig_oci_layout(oci, "asset", temp_dir=tmp_path) == "<stig/>"

    monkeypatch.setattr(runners, "_skopeo_copy_oci_to_docker", lambda *args, **kwargs: False)
    assert runners.run_stig_oci_layout(oci, "asset", temp_dir=tmp_path, verbose=True) is None


def test_run_oval_cve_image_success_and_skip(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")
    monkeypatch.setattr(runners, "_docker_load_and_get_image_ref", lambda *args, **kwargs: "repo:tag")

    def _ok_run(cmd, capture_output=True, text=True, timeout=300):
        out_mount = [part for part in cmd if part.endswith(":/out")][0]
        out_dir = Path(out_mount.split(":", 1)[0])
        (out_dir / "oval-results.xml").write_text("<oval/>", encoding="utf-8")
        return _Completed(2)

    monkeypatch.setattr(runners.subprocess, "run", _ok_run)
    xml, skip = runners.run_oval_cve_image(tar, "asset", temp_dir=tmp_path)
    assert xml == "<oval/>"
    assert skip is False

    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(1, stderr=f"base image {runners._OVAL_NOT_RHEL}"),
    )
    xml, skip = runners.run_oval_cve_image(tar, "asset", temp_dir=tmp_path)
    assert xml is None
    assert skip is True


def test_run_oval_cve_oci_layout_success(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()
    monkeypatch.setattr(runners, "_skopeo_copy_oci_to_docker", lambda *args, **kwargs: True)

    def _fake_run(cmd, capture_output=True, text=True, timeout=300):
        if cmd[:2] == ["docker", "run"]:
            out_mount = [part for part in cmd if part.endswith(":/out")][0]
            out_dir = Path(out_mount.split(":", 1)[0])
            (out_dir / "oval-results.xml").write_text("<oval/>", encoding="utf-8")
            return _Completed(0)
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    xml, skip = runners.run_oval_cve_oci_layout(oci, "asset", temp_dir=tmp_path)
    assert xml == "<oval/>"
    assert skip is False


def test_run_trivy_oci_layout_success(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()
    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout=json.dumps({"Artifacts": []})),
    )
    assert runners.run_trivy_oci_layout(oci) == {"Artifacts": []}


def test_run_trivy_oci_layout_failure_paths(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()
    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1, stdout=""))
    assert runners.run_trivy_oci_layout(oci) is None

    def _raise(*args, **kwargs):
        raise FileNotFoundError("trivy")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert runners.run_trivy_oci_layout(oci) is None


def test_run_trivy_fs_cyclonedx_success_and_bad_json(monkeypatch, tmp_path: Path) -> None:
    def _good_run(cmd, capture_output=True, check=False, timeout=300):
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _good_run)
    assert runners.run_trivy_fs_cyclonedx(tmp_path, temp_dir=tmp_path) == {"bomFormat": "CycloneDX"}

    def _bad_run(cmd, capture_output=True, check=False, timeout=300):
        out_path = Path(cmd[cmd.index("-o") + 1])
        out_path.write_text("{", encoding="utf-8")
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _bad_run)
    assert runners.run_trivy_fs_cyclonedx(tmp_path, temp_dir=tmp_path) is None


def test_run_trivy_fs_cyclonedx_not_found(monkeypatch, tmp_path: Path) -> None:
    def _raise(*args, **kwargs):
        raise FileNotFoundError("trivy")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert runners.run_trivy_fs_cyclonedx(tmp_path, temp_dir=tmp_path) is None


def test_run_trivy_image_cyclonedx_fast_path_and_fallback(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")
    mode_stats: dict[str, int] = {}

    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout=json.dumps({"bomFormat": "CycloneDX"})),
    )
    assert runners.run_trivy_image_cyclonedx(tar, mode_stats=mode_stats) == {"bomFormat": "CycloneDX"}
    assert mode_stats["trivy_image_input_ok"] == 1

    calls: list[list[str]] = []

    def _fallback_run(cmd, capture_output=True, text=True, timeout=180):
        calls.append(cmd)
        if cmd[:3] == ["trivy", "image", "--input"]:
            return _Completed(1, stdout="")
        if cmd[:2] == ["trivy", "image"] and "--input" not in cmd:
            return _Completed(0, stdout=json.dumps({"components": []}))
        if cmd[:2] == ["docker", "rmi"]:
            return _Completed(0)
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fallback_run)
    monkeypatch.setattr(runners, "_docker_load_and_get_image_ref", lambda *args, **kwargs: "repo:tag")
    out = runners.run_trivy_image_cyclonedx(tar, mode_stats=mode_stats)
    assert out == {"components": []}
    assert mode_stats["trivy_image_docker_fallback"] == 1
    assert any(c[:2] == ["docker", "rmi"] for c in calls)


def test_run_trivy_image_cyclonedx_returns_none_when_no_docker_ref(monkeypatch, tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_text("x", encoding="utf-8")
    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1))
    monkeypatch.setattr(runners, "_docker_load_and_get_image_ref", lambda *args, **kwargs: None)
    assert runners.run_trivy_image_cyclonedx(tar) is None


def test_run_trivy_oci_layout_cyclonedx_fast_path_and_fallback(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()
    stats: dict[str, int] = {}

    monkeypatch.setattr(
        runners.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, stdout=json.dumps({"bomFormat": "CycloneDX"})),
    )
    out = runners.run_trivy_oci_layout_cyclonedx(oci, mode_stats=stats)
    assert out == {"bomFormat": "CycloneDX"}
    assert stats["trivy_oci_input_ok"] == 1

    calls: list[list[str]] = []

    def _fallback_run(cmd, capture_output=True, text=True, timeout=180):
        calls.append(cmd)
        if cmd[:3] == ["trivy", "image", "--input"]:
            return _Completed(1)
        if cmd[:2] == ["trivy", "image"] and "--input" not in cmd:
            return _Completed(0, stdout=json.dumps({"components": [{"name": "openssl"}]}))
        if cmd[:2] == ["docker", "rmi"]:
            return _Completed(0)
        return _Completed(0)

    monkeypatch.setattr(runners.subprocess, "run", _fallback_run)
    monkeypatch.setattr(runners, "_skopeo_copy_oci_to_docker", lambda *args, **kwargs: True)
    out = runners.run_trivy_oci_layout_cyclonedx(oci, mode_stats=stats)
    assert out == {"components": [{"name": "openssl"}]}
    assert stats["trivy_oci_skopeo_fallback"] == 1
    assert any(c[:2] == ["docker", "rmi"] for c in calls)


def test_run_trivy_oci_layout_cyclonedx_returns_none_when_skopeo_fails(monkeypatch, tmp_path: Path) -> None:
    oci = tmp_path / "oci"
    oci.mkdir()
    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(1))
    monkeypatch.setattr(runners, "_skopeo_copy_oci_to_docker", lambda *args, **kwargs: False)
    assert runners.run_trivy_oci_layout_cyclonedx(oci) is None


def test_run_gitleaks_reads_report_file(monkeypatch, tmp_path: Path) -> None:
    def _fake_run(cmd, capture_output=True, timeout=120, cwd=None):
        out_idx = cmd.index("--report-path") + 1
        Path(cmd[out_idx]).write_text(json.dumps([{"Description": "secret"}]), encoding="utf-8")
        return _Completed(1)

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    out = runners.run_gitleaks(tmp_path, temp_dir=tmp_path)
    assert isinstance(out, list)
    assert out[0]["Description"] == "secret"


def test_run_gitleaks_not_found(monkeypatch, tmp_path: Path) -> None:
    def _raise(*args, **kwargs):
        raise FileNotFoundError("gitleaks")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert runners.run_gitleaks(tmp_path, temp_dir=tmp_path) is None


def test_run_gitleaks_missing_report_returns_none(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(0))
    assert runners.run_gitleaks(tmp_path, temp_dir=tmp_path) is None


def test_run_grype_includes_excludes_and_parses(monkeypatch, tmp_path: Path) -> None:
    seen_cmd: list[str] = []

    def _fake_run(cmd, capture_output=True, text=True, timeout=120):
        seen_cmd.extend(cmd)
        return _Completed(0, stdout=json.dumps({"matches": []}))

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    out = runners.run_grype(tmp_path, exclude=["node_modules/**"])
    assert out == {"matches": []}
    assert "--exclude" in seen_cmd


def test_run_grype_not_found(monkeypatch, tmp_path: Path) -> None:
    def _raise(*args, **kwargs):
        raise FileNotFoundError("grype")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    assert runners.run_grype(tmp_path) is None


def test_run_npm_audit_and_pip_audit_and_semgrep(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask", encoding="utf-8")

    def _ok_json(cmd, capture_output=True, text=True, timeout=60, cwd=None):
        if cmd[:2] == ["npm", "audit"]:
            return _Completed(0, stdout=json.dumps({"metadata": {"vulnerabilities": {}}}))
        if cmd[:2] == ["pip-audit", "--format"]:
            return _Completed(0, stdout=json.dumps([{"name": "flask"}]))
        if cmd[:2] == ["semgrep", "scan"]:
            return _Completed(0, stdout=json.dumps({"results": []}))
        raise AssertionError("unexpected command")

    monkeypatch.setattr(runners.subprocess, "run", _ok_json)
    assert runners.run_npm_audit(tmp_path) == {"metadata": {"vulnerabilities": {}}}
    assert runners.run_pip_audit(tmp_path) == [{"name": "flask"}]
    assert runners.run_semgrep(tmp_path) == {"results": []}


def test_run_semgrep_excludes_are_added(monkeypatch, tmp_path: Path) -> None:
    seen: list[str] = []

    def _fake_run(cmd, capture_output=True, text=True, timeout=180):
        seen.extend(cmd)
        return _Completed(0, stdout=json.dumps({"results": []}))

    monkeypatch.setattr(runners.subprocess, "run", _fake_run)
    out = runners.run_semgrep(tmp_path, exclude=["vendor/**"])
    assert out == {"results": []}
    assert "--exclude" in seen


def test_runner_json_decode_and_timeout_paths(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask", encoding="utf-8")

    monkeypatch.setattr(runners.subprocess, "run", lambda *args, **kwargs: _Completed(0, stdout="{"))
    assert runners.run_npm_audit(tmp_path) is None
    assert runners.run_pip_audit(tmp_path) is None
    assert runners.run_semgrep(tmp_path) is None
    with pytest.raises(json.JSONDecodeError):
        runners.run_grype(tmp_path)

    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="trivy", timeout=1)

    monkeypatch.setattr(runners.subprocess, "run", _timeout)
    assert runners.run_trivy_fs_cyclonedx(tmp_path, temp_dir=tmp_path) is None


def test_run_npm_pip_semgrep_preconditions_and_not_found(monkeypatch, tmp_path: Path) -> None:
    assert runners.run_npm_audit(tmp_path) is None
    assert runners.run_pip_audit(tmp_path) is None

    def _raise(*args, **kwargs):
        raise FileNotFoundError("scanner")

    monkeypatch.setattr(runners.subprocess, "run", _raise)
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask", encoding="utf-8")
    assert runners.run_npm_audit(tmp_path) is None
    assert runners.run_pip_audit(tmp_path) is None
    assert runners.run_semgrep(tmp_path) is None
