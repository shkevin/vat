"""Container STIG: pick the SSG datastream + DISA STIG profile by the image's base OS."""

from __future__ import annotations

import types
from pathlib import Path

from vat_scanner.scanners import runners


def _rootfs(base: Path, os_release: str | None) -> Path:
    (base / "etc").mkdir(parents=True)
    if os_release is not None:
        (base / "etc" / "os-release").write_text(os_release, encoding="utf-8")
    return base


def _content(base: Path, names: list[str]) -> Path:
    base.mkdir()
    for n in names:
        (base / n).write_text("<ds/>", encoding="utf-8")
    return base


def _fake_profiles(*ids: str):
    out = "\n".join(f"{i}:Title" for i in ids)
    return lambda *a, **k: types.SimpleNamespace(stdout=out, returncode=0)


def test_rhel_family_maps_to_disa_stig(tmp_path, monkeypatch):
    content = _content(tmp_path / "content", ["ssg-rhel9-ds.xml", "ssg-chainguard-gpos-ds.xml"])
    monkeypatch.setattr(
        runners.subprocess, "run",
        _fake_profiles("xccdf_org.ssgproject.content_profile_cis", "xccdf_org.ssgproject.content_profile_stig"),
    )
    for os_id in ("rhel", "rocky", "almalinux", "centos"):
        root = _rootfs(tmp_path / f"rf-{os_id}", f'ID={os_id}\nVERSION_ID="9.3"\n')
        ds, prof = runners.resolve_stig_content_for_rootfs(root, content_dir=str(content))
        assert ds == content / "ssg-rhel9-ds.xml"
        assert prof.endswith("_profile_stig"), f"{os_id} -> {prof}"


def test_ubuntu2204_maps_to_stig(tmp_path, monkeypatch):
    content = _content(tmp_path / "content", ["ssg-ubuntu2204-ds.xml"])
    monkeypatch.setattr(runners.subprocess, "run", _fake_profiles("xccdf_org.ssgproject.content_profile_stig"))
    root = _rootfs(tmp_path / "rf", 'ID=ubuntu\nVERSION_ID="22.04"\n')
    ds, prof = runners.resolve_stig_content_for_rootfs(root, content_dir=str(content))
    assert ds == content / "ssg-ubuntu2204-ds.xml"
    assert prof.endswith("_profile_stig")


def test_alpine_and_debian_have_no_stig(tmp_path):
    content = _content(tmp_path / "content", ["ssg-rhel9-ds.xml", "ssg-chainguard-gpos-ds.xml"])
    for i, osr in enumerate(('ID=alpine\nVERSION_ID="3.20"\n', 'ID=debian\nVERSION_ID="12"\n')):
        root = _rootfs(tmp_path / f"rf-{i}", osr)
        assert runners.resolve_stig_content_for_rootfs(root, content_dir=str(content)) == (None, None)


def test_chainguard_uses_basic_profile(tmp_path):
    content = _content(tmp_path / "content", ["ssg-chainguard-gpos-ds.xml"])
    root = _rootfs(tmp_path / "rf", "ID=chainguard\n")
    ds, prof = runners.resolve_stig_content_for_rootfs(root, content_dir=str(content))
    assert ds == content / "ssg-chainguard-gpos-ds.xml"
    assert prof == runners.STIG_PROFILE


def test_distroless_falls_back_to_chainguard(tmp_path):
    content = _content(tmp_path / "content", ["ssg-chainguard-gpos-ds.xml"])
    root = _rootfs(tmp_path / "rf", None)  # no os-release
    ds, prof = runners.resolve_stig_content_for_rootfs(root, content_dir=str(content))
    assert ds == content / "ssg-chainguard-gpos-ds.xml"
    assert prof == runners.STIG_PROFILE


def test_missing_datastream_skips(tmp_path):
    content = _content(tmp_path / "content", ["ssg-chainguard-gpos-ds.xml"])  # no rhel9 bundled
    root = _rootfs(tmp_path / "rf", 'ID=rhel\nVERSION_ID="9.0"\n')
    assert runners.resolve_stig_content_for_rootfs(root, content_dir=str(content)) == (None, None)
