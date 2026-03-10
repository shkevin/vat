"""Tests for grouping service."""

import json
from pathlib import Path

import pytest

from app.models.finding import Finding, FindingType, Severity, Status
from app.services.grouping import get_finding_group_key, normalize_package_name


def _mk_finding(
    id: str = "f-abc123",
    finding_type: FindingType = FindingType.SCA,
    cve_id: str = "CVE-2024-1234",
    component: str | None = None,
    component_base: str | None = None,
    title: str | None = None,
    ecosystem: str | None = None,
    rule_id: str | None = None,
    cwe_id: str | None = None,
    secret_type: str | None = None,
    image: str | None = None,
    branch: str | None = None,
    tag: str | None = None,
) -> Finding:
    f = Finding(
        id=id,
        finding_type=finding_type,
        fingerprint_id="fp1",
        cve_id=cve_id,
        severity=Severity.High,
        status=Status.Open,
        component=component,
        component_base=component_base,
        title=title,
    )
    if ecosystem is not None:
        f.ecosystem = ecosystem
    if rule_id is not None:
        f.rule_id = rule_id
    if cwe_id is not None:
        f.cwe_id = cwe_id
    if secret_type is not None:
        f.secret_type = secret_type
    if image is not None:
        f.image = image
    if branch is not None:
        f.branch = branch
    if tag is not None:
        f.tag = tag
    return f


def test_cve_groups_by_package():
    """SCA: same package, same asset, different CVEs = one group."""
    f1 = _mk_finding(id="f-1", cve_id="CVE-2024-8385", component="firefox-esr 115.0", component_base="firefox-esr", ecosystem="debian")
    f2 = _mk_finding(id="f-2", cve_id="CVE-2024-8381", component="firefox-esr 115.0", component_base="firefox-esr", ecosystem="debian")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert get_finding_group_key(f1) == "sca:debian|firefox-esr#||"


def test_cve_fallback_to_cve_id_when_no_package():
    """CVE: no component_base → fallback to cve_id."""
    f = _mk_finding(cve_id="CVE-2024-1234", component=None, component_base=None)
    assert get_finding_group_key(f) == "cve:cve-2024-1234#||"


def test_sast_groups_by_rule_id():
    """SAST: same rule_id = one group."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, cve_id="python.dangerous-assert", rule_id="python.dangerous-assert", title="Dangerous assert")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, cve_id="python.dangerous-assert", rule_id="python.dangerous-assert", title="Dangerous assert in other.py")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "sast:" in get_finding_group_key(f1)


def test_secret_groups_by_secret_type():
    """Secret: same secret_type = one group."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.Secret, cve_id="gitleaks-aws", rule_id="gitleaks-aws", secret_type="AWS Key")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.Secret, cve_id="gitleaks-aws", rule_id="gitleaks-aws", secret_type="AWS Key")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "secret:" in get_finding_group_key(f1)


def test_secret_different_files_different_groups():
    """Secret: when secret_type/rule_id empty, title includes path — each file = separate group."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.Secret, cve_id="aikido", title="Leaked secret in install.sh", rule_id=None, secret_type=None)
    f2 = _mk_finding(id="f-2", finding_type=FindingType.Secret, cve_id="aikido", title="Leaked secret in postlaunch.sh", rule_id=None, secret_type=None)
    assert get_finding_group_key(f1) != get_finding_group_key(f2)
    assert get_finding_group_key(f1) == "secret:leaked secret in install.sh#||"
    assert get_finding_group_key(f2) == "secret:leaked secret in postlaunch.sh#||"


def test_license_groups_by_ecosystem_and_package():
    """License: ecosystem + package = one group (within same asset)."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.License, cve_id="license:MIT", component="pkg 1.0", component_base="pkg", ecosystem="npm")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.License, cve_id="license:MIT", component="pkg 2.0", component_base="pkg", ecosystem="npm")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert get_finding_group_key(f1) == "license:npm|pkg#||"


def test_iac_groups_by_rule_id():
    """IaC: same rule_id = one group."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.IaC, cve_id="AVD-123", rule_id="AVD-123", title="S3 bucket public")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.IaC, cve_id="AVD-123", rule_id="AVD-123", title="S3 bucket public in other.tf")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_npm_yarn_pnpm_same_group_key():
    """npm, yarn, pnpm share registry — same package from different managers = one group (within asset)."""
    f_npm = _mk_finding(id="f-1", component="lodash 4.17.21", component_base="lodash", ecosystem="npm")
    f_yarn = _mk_finding(id="f-2", component="lodash 4.17.22", component_base="lodash", ecosystem="yarn")
    f_pnpm = _mk_finding(id="f-3", component="lodash 4.17.23", component_base="lodash", ecosystem="pnpm")
    assert get_finding_group_key(f_npm) == get_finding_group_key(f_yarn) == get_finding_group_key(f_pnpm)
    assert get_finding_group_key(f_npm) == "sca:npm|lodash#||"


def test_component_base_fallback_from_component():
    """When component_base is missing, extract from component 'name version' format."""
    f = _mk_finding(id="f-1", component="lodash 4.17.21", component_base=None, ecosystem="npm")
    assert get_finding_group_key(f) == "sca:npm|lodash#||"


def test_grouping_scoped_within_asset():
    """Same package in different assets = different groups."""
    f1 = _mk_finding(id="f-1", component="urllib3 1.0", component_base="urllib3", ecosystem="pypi")
    f2 = _mk_finding(id="f-2", component="urllib3 1.0", component_base="urllib3", ecosystem="pypi")
    f1.image = "repo-a"
    f1.branch = "main"
    f2.image = "repo-b"
    f2.branch = "main"
    assert get_finding_group_key(f1) != get_finding_group_key(f2)
    assert get_finding_group_key(f1) == "sca:pypi|urllib3#repo-a|main|"
    assert get_finding_group_key(f2) == "sca:pypi|urllib3#repo-b|main|"


def test_sast_rule_title_strips_extensionless_paths():
    """Rule title normalization strips Dockerfile, Makefile, .dockerignore, .gitignore."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", title="Dangerous assert")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", title="Dangerous assert in Dockerfile")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_normalize_package_name():
    """Package name normalization per ecosystem. PyPI follows PEP 503."""
    assert normalize_package_name("npm", "Lodash") == "lodash"
    assert normalize_package_name("npm", "lodash") == "lodash"
    # PEP 503: collapse [-_.]+ to single -, lowercase
    assert normalize_package_name("pypi", "my_package") == "my-package"
    assert normalize_package_name("pypi", "my-package") == "my-package"
    assert normalize_package_name("pypi", "My.Weird_Package") == "my-weird-package"
    assert normalize_package_name("pypi", "my___package") == "my-package"
    # Maven: full groupId:artifactId, do not strip
    assert normalize_package_name("maven", "org.springframework:spring-core") == "org.springframework:spring-core"
    assert normalize_package_name(None, "SomePkg") == "somepkg"


def test_normalize_package_name_maven_fallback():
    """Maven prefers groupId:artifactId; malformed names fall back to lowercase (Aikido/external data)."""
    assert normalize_package_name("maven", "org.springframework:spring-core") == "org.springframework:spring-core"
    assert normalize_package_name("maven", "spring-core") == "spring-core"
    assert normalize_package_name("gradle", "apache hadoop 1.1.1") == "apache hadoop 1.1.1"


# --- SCA edge cases ---


def test_sca_different_ecosystems_different_groups():
    """SCA: same package name in different ecosystems = different groups."""
    f_debian = _mk_finding(id="f-1", component="firefox 115", component_base="firefox", ecosystem="debian")
    f_pypi = _mk_finding(id="f-2", component="firefox 1.0", component_base="firefox", ecosystem="pypi")
    assert get_finding_group_key(f_debian) != get_finding_group_key(f_pypi)
    assert get_finding_group_key(f_debian) == "sca:debian|firefox#||"
    assert get_finding_group_key(f_pypi) == "sca:pypi|firefox#||"


def test_sca_component_extraction_at_version():
    """SCA: component_base from component 'name@version' format (npm style)."""
    f = _mk_finding(id="f-1", component="lodash@4.17.21", component_base=None, ecosystem="npm")
    assert get_finding_group_key(f) == "sca:npm|lodash#||"


def test_sca_empty_ecosystem_fallback():
    """SCA: empty ecosystem still produces valid key (lowercase fallback)."""
    f = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="")
    key = get_finding_group_key(f)
    assert key.startswith("sca:")
    assert "pkg" in key


def test_sca_pip_pipenv_poetry_use_pypi_package_normalization():
    """SCA: pip, pipenv, poetry use PyPI-style package normalization (collapse [-_.] to -)."""
    f_pip = _mk_finding(id="f-1", component="my_pkg 1.0", component_base="my_pkg", ecosystem="pip")
    f_pypi = _mk_finding(id="f-2", component="my_pkg 2.0", component_base="my_pkg", ecosystem="pypi")
    # Ecosystem prefix differs (pip vs pypi) but package part uses same normalization
    assert "my-pkg" in get_finding_group_key(f_pip)
    assert "my-pkg" in get_finding_group_key(f_pypi)
    assert get_finding_group_key(f_pip) == "sca:pip|my-pkg#||"
    assert get_finding_group_key(f_pypi) == "sca:pypi|my-pkg#||"


# --- SAST edge cases ---


def test_sast_fallback_to_cwe_id_when_no_rule_id():
    """SAST: cwe_id used when rule_id empty."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", cwe_id="CWE-89", title="SQL injection")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", cwe_id="CWE-89", title="SQL injection in other.py")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "cwe-89" in get_finding_group_key(f1)


def test_sast_fallback_to_title_when_no_rule_or_cwe():
    """SAST: normalized title used when rule_id and cwe_id empty."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", cwe_id="", title="Dangerous assert in foo.py")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", cwe_id="", title="Dangerous assert in bar.py")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "dangerous assert" in get_finding_group_key(f1)


def test_sast_fallback_to_id_when_all_empty():
    """SAST: f.id used when rule_id, cwe_id, title all empty."""
    f = _mk_finding(id="f-unique-123", finding_type=FindingType.SAST, cve_id="", rule_id="", cwe_id="", title="")
    key = get_finding_group_key(f)
    assert key == "sast:f-unique-123#||"


def test_sast_title_strips_at_line_in_path():
    """SAST: title normalization strips ' at line N in path' when path has no standard extension."""
    # Note: " at line N in file.py" is partially stripped (in file.py removed first), leaving " at line N".
    # Use path without extension so the full " at line N in path" pattern matches.
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", title="SQL injection at line 42 in db")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", title="SQL injection")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_sast_title_at_line_in_path_with_extension_partial_strip():
    """SAST: ' at line N in file.py' — ' in file.py' stripped first, ' at line N' remains (regex order)."""
    # Documents current behavior: path-with-extension regex runs before at-line regex.
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", title="SQL injection at line 42 in db.py")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", title="SQL injection")
    # They do NOT group together due to regex application order
    assert get_finding_group_key(f1) != get_finding_group_key(f2)


def test_sast_title_strips_path_and_n_others():
    """SAST: title normalization strips ', path and N others'."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", title="XSS, foo.py and 3 others")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", title="XSS")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_sast_rule_id_takes_precedence_over_cwe_and_title():
    """SAST: rule_id > cwe_id > title in precedence."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="custom.rule", cwe_id="CWE-79", title="XSS in a.py")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="custom.rule", cwe_id="CWE-89", title="SQL in b.py")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "custom.rule" in get_finding_group_key(f1)


# --- IaC edge cases ---


def test_iac_fallback_to_title_when_no_rule_id():
    """IaC: normalized title used when rule_id empty."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.IaC, rule_id="", title="S3 bucket public in main.tf")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.IaC, rule_id="", title="S3 bucket public in other.tf")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "s3 bucket public" in get_finding_group_key(f1)


def test_iac_fallback_to_id_when_all_empty():
    """IaC: f.id used when rule_id and title empty."""
    f = _mk_finding(id="f-iac-xyz", finding_type=FindingType.IaC, cve_id="", rule_id="", title="")
    assert get_finding_group_key(f) == "iac:f-iac-xyz#||"


def test_iac_title_strips_makefile_dockerfile():
    """IaC: title normalization strips ' in Dockerfile', ' in Makefile'."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.IaC, rule_id="", title="Hardcoded secret in Dockerfile")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.IaC, rule_id="", title="Hardcoded secret")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


# --- Secret edge cases ---


def test_secret_rule_id_takes_precedence_over_title():
    """Secret: rule_id used when present, even if title has path."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.Secret, rule_id="gitleaks-aws", title="Leaked secret in install.sh", secret_type=None)
    f2 = _mk_finding(id="f-2", finding_type=FindingType.Secret, rule_id="gitleaks-aws", title="Leaked secret in postlaunch.sh", secret_type=None)
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "gitleaks-aws" in get_finding_group_key(f1)


def test_secret_secret_type_takes_precedence_over_rule_id():
    """Secret: secret_type > rule_id > title in precedence."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.Secret, rule_id="r1", secret_type="AWS Key", title="X")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.Secret, rule_id="r2", secret_type="AWS Key", title="Y")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)
    assert "aws" in get_finding_group_key(f1)


def test_secret_fallback_to_id_when_all_empty():
    """Secret: f.id used when secret_type, rule_id, title all empty."""
    f = _mk_finding(id="f-secret-xyz", finding_type=FindingType.Secret, cve_id="", rule_id="", secret_type=None, title="")
    assert get_finding_group_key(f) == "secret:f-secret-xyz#||"


def test_secret_groups_across_scanners():
    """Secret: 'private-key' (Gitleaks rule_id) and 'Private Key' (Trivy secret_type) group together."""
    f_gitleaks = _mk_finding(
        id="f-1",
        finding_type=FindingType.Secret,
        rule_id="private-key",
        secret_type=None,
        title="private-key",
    )
    f_trivy = _mk_finding(
        id="f-2",
        finding_type=FindingType.Secret,
        rule_id="private-key",
        secret_type="Private Key",
        title="private-key",
    )
    assert get_finding_group_key(f_gitleaks) == get_finding_group_key(f_trivy)
    assert get_finding_group_key(f_gitleaks) == "secret:private-key#||"


def test_secret_title_preserves_path_when_no_type_or_rule():
    """Secret: title with ' in path' kept when falling back to title (per-file grouping)."""
    f = _mk_finding(id="f-1", finding_type=FindingType.Secret, title="Leaked secret in local_store.py", rule_id=None, secret_type=None)
    key = get_finding_group_key(f)
    assert "local_store.py" in key
    assert key == "secret:leaked secret in local_store.py#||"


# --- License edge cases ---


def test_license_fallback_to_id_when_no_package():
    """License: f.id used when no component_base and no extractable component."""
    f = _mk_finding(id="f-lic-abc", finding_type=FindingType.License, component=None, component_base=None, ecosystem="npm")
    assert get_finding_group_key(f) == "license:f-lic-abc#||"


def test_license_different_ecosystems_different_groups():
    """License: same package in different ecosystems = different groups."""
    f_npm = _mk_finding(id="f-1", finding_type=FindingType.License, component="pkg 1.0", component_base="pkg", ecosystem="npm")
    f_pypi = _mk_finding(id="f-2", finding_type=FindingType.License, component="pkg 1.0", component_base="pkg", ecosystem="pypi")
    assert get_finding_group_key(f_npm) != get_finding_group_key(f_pypi)
    assert "npm" in get_finding_group_key(f_npm)
    assert "pypi" in get_finding_group_key(f_pypi)


# --- Asset variations ---


def test_asset_empty_produces_double_pipe():
    """Asset: empty image/branch/tag produces #|| suffix."""
    f = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="npm")
    assert get_finding_group_key(f).endswith("#||")


def test_asset_image_only():
    """Asset: image set, branch/tag empty."""
    f = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="npm", image="api-server:latest")
    assert get_finding_group_key(f).endswith("#api-server:latest||")


def test_asset_branch_only():
    """Asset: branch set, image/tag empty."""
    f = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="npm", branch="main")
    assert get_finding_group_key(f).endswith("#|main|")


def test_asset_tag_only():
    """Asset: tag set, image/branch empty."""
    f = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="npm", tag="v1.0")
    assert get_finding_group_key(f).endswith("#||v1.0")


def test_asset_full_image_branch_tag():
    """Asset: image, branch, tag all set."""
    f = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="npm", image="repo", branch="develop", tag="v2")
    assert get_finding_group_key(f).endswith("#repo|develop|v2")


def test_asset_case_normalized():
    """Asset: image/branch/tag normalized to lowercase."""
    f1 = _mk_finding(id="f-1", component="pkg 1.0", component_base="pkg", ecosystem="npm", image="Repo", branch="Main")
    f2 = _mk_finding(id="f-2", component="pkg 1.0", component_base="pkg", ecosystem="npm", image="repo", branch="main")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_asset_different_tag_same_package_different_groups():
    """Asset: same package, different tag = different groups (container images)."""
    f1 = _mk_finding(id="f-1", component="openssl 1.1", component_base="openssl", ecosystem="debian", image="base", tag="v1")
    f2 = _mk_finding(id="f-2", component="openssl 1.1", component_base="openssl", ecosystem="debian", image="base", tag="v2")
    assert get_finding_group_key(f1) != get_finding_group_key(f2)


# --- Key format validation ---


def test_all_known_types_produce_valid_key_format():
    """All FindingType values produce keys with format {prefix}:{key}#{asset}."""
    for ft in FindingType:
        f = _mk_finding(id="f-x", finding_type=ft, cve_id="CVE-1", component="pkg 1.0", component_base="pkg", ecosystem="npm")
        if ft == FindingType.SCA or ft == FindingType.License:
            f.rule_id = None
        elif ft == FindingType.SAST:
            f.rule_id = "r1"
        elif ft == FindingType.IaC:
            f.rule_id = "r1"
        elif ft == FindingType.Secret:
            f.secret_type = "AWS Key"
        key = get_finding_group_key(f)
        assert "#" in key, f"Key for {ft} missing asset separator: {key}"
        prefix, rest = key.split("#", 1)
        assert ":" in prefix, f"Key for {ft} missing type prefix: {key}"
        assert rest, f"Key for {ft} has empty asset part: {key}"


# --- Title normalization edge cases ---


def test_sast_title_strips_extensionless_gitignore_dockerignore():
    """SAST: title normalization strips .gitignore, .dockerignore paths."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", title="Hardcoded value in .gitignore")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", title="Hardcoded value")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_iac_title_uses_cve_id_fallback_when_title_empty():
    """IaC: cve_id used when title empty (e.g. AVD-123 as cve_id)."""
    f = _mk_finding(id="f-1", finding_type=FindingType.IaC, cve_id="AVD-AWS-001", rule_id="", title=None)
    assert get_finding_group_key(f) == "iac:avd-aws-001#||"


def test_sast_title_uses_cve_id_fallback_when_title_empty():
    """SAST: cve_id used when title empty."""
    f = _mk_finding(id="f-1", finding_type=FindingType.SAST, cve_id="python.dangerous-assert", rule_id="", cwe_id="", title=None)
    assert get_finding_group_key(f) == "sast:python.dangerous-assert#||"


def test_whitespace_in_title_normalized():
    """Titles with leading/trailing whitespace are trimmed and lowercased."""
    f1 = _mk_finding(id="f-1", finding_type=FindingType.SAST, rule_id="", title="  SQL Injection  ")
    f2 = _mk_finding(id="f-2", finding_type=FindingType.SAST, rule_id="", title="sql injection")
    assert get_finding_group_key(f1) == get_finding_group_key(f2)


def test_sca_cve_id_normalized_lowercase():
    """SCA: cve_id fallback is lowercased."""
    f = _mk_finding(id="f-1", cve_id="CVE-2024-1234", component=None, component_base=None)
    assert get_finding_group_key(f) == "cve:cve-2024-1234#||"


def test_secret_title_case_normalized():
    """Secret: title used as key is lowercased when no secret_type/rule_id."""
    f = _mk_finding(id="f-1", finding_type=FindingType.Secret, title="Leaked Secret In Config.Env", rule_id=None, secret_type=None)
    assert get_finding_group_key(f) == "secret:leaked secret in config.env#||"


def test_component_base_extraction_name_space_version():
    """SCA: component_base from 'name version' when component_base missing."""
    f = _mk_finding(id="f-1", component="vllm 0.8.5.post1+cpu", component_base=None, ecosystem="pypi")
    key = get_finding_group_key(f)
    assert "vllm" in key
    assert "0.8.5" not in key  # version stripped


def test_fixture_covers_all_finding_types():
    """
    CI guard: every finding_type that parsers can emit must have a fixture entry.
    Prevents fixture from becoming stale when a new parser or finding type is added.
    """
    from app.models.finding import FindingType

    fixture_path = Path(__file__).parent / "fixtures" / "grouping_keys.json"
    data = json.loads(fixture_path.read_text())
    fixture_types = {f["findingType"].upper() for f in data["fixtures"]}
    # All FindingType enum values must have at least one fixture
    for ft in FindingType:
        assert ft.value.upper() in fixture_types, (
            f"Fixture missing entry for finding_type={ft.value}. "
            "Add a fixture to grouping_keys.json when adding new parsers or types."
        )


def test_group_key_fixture_parity():
    """
    Backend must produce keys matching fixtures/grouping_keys.json.
    Frontend getFindingGroupKey() should add a test that loads this fixture
    and asserts identical keys — protects against drift.
    """
    fixture_path = Path(__file__).parent / "fixtures" / "grouping_keys.json"
    data = json.loads(fixture_path.read_text())
    for item in data["fixtures"]:
        f = Finding(
            id=item["id"],
            finding_type=FindingType(item["findingType"]),
            fingerprint_id="fp",
            cve_id=item["cveId"],
            severity=Severity.High,
            status=Status.Open,
            component=item.get("component"),
            component_base=item.get("componentBase"),
            title=item.get("title"),
        )
        if item.get("ecosystem") is not None:
            f.ecosystem = item["ecosystem"]
        if item.get("ruleId") is not None:
            f.rule_id = item["ruleId"]
        if item.get("cweId") is not None:
            f.cwe_id = item["cweId"]
        if item.get("secretType") is not None:
            f.secret_type = item["secretType"]
        key = get_finding_group_key(f)
        assert key == item["expectedKey"], f"Fixture {item['id']}: got {key}, expected {item['expectedKey']}"
