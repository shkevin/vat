from __future__ import annotations

import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from vat_scanner import archive, gating, openscap_utils, sarif_output


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_gating_severity_helpers() -> None:
    assert gating._normalize_severity("CRITICAL-ish") == "critical"
    assert gating._normalize_severity("none") == "unknown"
    assert gating._severity_level("high") > gating._severity_level("low")
    assert gating._severity_level("weird") == 0


def test_get_changed_files_success_and_failures(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        gating.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(0, "a.py\nb/c.py\n"),
    )
    assert gating.get_changed_files(tmp_path, "base", "head") == {"a.py", "b/c.py"}

    monkeypatch.setattr(gating.subprocess, "run", lambda *args, **kwargs: _Completed(1, ""))
    assert gating.get_changed_files(tmp_path, "base", "head") == set()

    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(gating.subprocess, "run", _raise)
    assert gating.get_changed_files(tmp_path, "base", "head") == set()


def test_extractors_and_evaluate_gating() -> None:
    reports = {
        "trivy": {
            "Results": [
                {
                    "Target": "src/a.py",
                    "Vulnerabilities": [{"Severity": "HIGH", "VulnerabilityID": "CVE-1"}],
                    "Misconfigurations": [{"Severity": "LOW", "ID": "MIS-1", "File": "iac.tf"}],
                    "Secrets": [{"severity": "critical", "File": "secret.env"}],
                }
            ]
        },
        "grype": {"matches": [{"vulnerability": {"severity": "medium"}, "artifact": {"locations": [{"path": "pkg.lock"}]}}]},
        "npm_audit": {"vulnerabilities": {"lodash": {"severity": "high"}}},
        "pip_audit": [{"name": "flask", "vulns": [{"id": "PYSEC-1"}]}],
        "semgrep": {"results": [{"path": "src/main.py", "extra": {"severity": "warning"}}]},
        "gitleaks": [{"File": "secrets.txt"}],
    }
    findings = gating.extract_gating_findings(reports, Path("."))
    assert len(findings) >= 6

    diffed = gating.filter_findings_in_diff(findings, {"src/main.py", "src/a.py"})
    assert all(f["path"] in {"src/main.py", "src/a.py"} for f in diffed)

    should_fail, exceeding = gating.evaluate_gating(findings, "medium")
    assert should_fail is True
    assert len(exceeding) >= 1

    assert gating.evaluate_gating(findings, "bad-threshold") == (False, [])


def test_partial_fingerprints_for_static_result_stable() -> None:
    a = sarif_output.partial_fingerprints_for_static_result("rule-1", "src/App.PY", 10)
    b = sarif_output.partial_fingerprints_for_static_result("rule-1", "src/app.py", 10)
    assert a == b
    assert "primaryLocationLineHash/v1" in a
    assert len(a["primaryLocationLineHash/v1"]) == 64


def test_sarif_level_and_converters() -> None:
    assert sarif_output._level("critical") == "error"
    assert sarif_output._level("unknown-value") == "warning"

    trivy_report = {
        "Results": [
            {
                "Target": "src/a.py",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "high", "Title": "bad"}],
                "Misconfigurations": [{"ID": "MIS-1", "Severity": "low", "Title": "weak"}],
                "Secrets": [{"RuleID": "SEC-1", "StartLine": 3}],
            }
        ]
    }
    results, rules = sarif_output._trivy_to_sarif_results(trivy_report, "asset")
    assert len(results) == 3
    assert len(rules) == 3
    for row in results:
        assert "partialFingerprints" in row
        assert "primaryLocationLineHash/v1" in row["partialFingerprints"]

    grype_results, _ = sarif_output._grype_to_sarif_results(
        {"matches": [{"vulnerability": {"id": "CVE-2", "severity": "medium"}, "artifact": {"name": "pkg", "locations": [{"path": "p.txt"}]}}]},
        "asset",
    )
    assert len(grype_results) == 1
    assert "partialFingerprints" in grype_results[0]

    npm_results, _ = sarif_output._npm_to_sarif_results({"vulnerabilities": {"x": {"severity": "low"}}}, "asset")
    assert len(npm_results) == 1
    assert "partialFingerprints" in npm_results[0]

    pip_results, _ = sarif_output._pip_to_sarif_results([{"name": "flask", "vulns": [{"id": "PYSEC-1"}]}], "asset")
    assert len(pip_results) == 1
    assert "partialFingerprints" in pip_results[0]

    semgrep_results, _ = sarif_output._semgrep_to_sarif_results(
        {"results": [{"check_id": "R1", "path": "a.py", "start": {"line": 8}, "extra": {"message": "x"}}]},
        "asset",
    )
    assert len(semgrep_results) == 1
    assert "partialFingerprints" in semgrep_results[0]

    gitleaks_results, _ = sarif_output._gitleaks_to_sarif_results(
        [{"RuleID": "GL-1", "File": "secret.env", "StartLine": 5, "Description": "secret"}],
        "asset",
    )
    assert len(gitleaks_results) == 1
    assert "partialFingerprints" in gitleaks_results[0]


def test_reports_to_sarif_handles_unknown_and_converter_exceptions(monkeypatch) -> None:
    reports = {"unknown": {"x": 1}, "trivy": {"Results": []}}

    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(sarif_output, "_trivy_to_sarif_results", _boom)
    out = sarif_output.reports_to_sarif(reports, "asset")
    assert out["version"] == "2.1.0"
    assert out["runs"] == []


def test_archive_helpers_and_extract_remove(tmp_path: Path) -> None:
    zip_src = tmp_path / "x.zip"
    with zipfile.ZipFile(zip_src, "w") as zf:
        zf.writestr("root/a.txt", "a")
    assert archive.is_archive(zip_src)
    zip_dest = tmp_path / "unz"
    zip_dest.mkdir()
    extracted_root = archive.extract_archive(zip_src, zip_dest)
    assert extracted_root.exists()

    tar_src = tmp_path / "y.tar.gz"
    tar_root = tmp_path / "tarroot"
    tar_root.mkdir()
    (tar_root / "b.txt").write_text("b", encoding="utf-8")
    with tarfile.open(tar_src, "w:gz") as tf:
        tf.add(tar_root, arcname="single")
    tar_dest = tmp_path / "unt"
    tar_dest.mkdir()
    extracted_tar = archive.extract_archive(tar_src, tar_dest)
    assert extracted_tar.name in {"single", "unt"}

    multi = tmp_path / "multi"
    multi.mkdir()
    (multi / "a").mkdir()
    (multi / "b").mkdir()
    assert archive._extracted_root(multi) == multi

    archive.remove_extracted(multi)
    assert not multi.exists()

    with pytest.raises(ValueError):
        archive.extract_archive(tmp_path / "not-real.zip", tmp_path / "d")


def test_openscap_utils_counting_and_save(tmp_path: Path) -> None:
    xccdf = """
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
  <rule-result idref="r1"><result>fail</result></rule-result>
  <rule-result idref="r2"><result>pass</result></rule-result>
</Benchmark>
"""
    assert openscap_utils.count_openscap_findings(xccdf) == 1
    assert openscap_utils.count_openscap_findings("{") == 0
    assert openscap_utils.count_openscap_findings("") == 0

    oval = """
<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">
  <results><system><definitions>
    <definition definition_id="d1" result="true" />
    <definition definition_id="d2" result="false" />
  </definitions></system></results>
</oval_results>
"""
    assert openscap_utils.count_openscap_oval_findings(oval) == 1
    assert openscap_utils.count_openscap_oval_findings("{") == 0

    saved = openscap_utils.save_openscap_xml("<x/>", tmp_path, "openscap", 1, "label/unsafe")
    assert saved.exists()
    assert "label_unsafe" in saved.name
