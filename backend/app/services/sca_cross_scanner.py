"""SCA identity normalization across scanners (OpenSCAP CPE vs Aikido/Trivy packages).

Compliance tools often emit short CPE product names (e.g. ``ssl``) without an ecosystem;
CVE scanners emit distro packages (``openssl``) with ``debian`` / ``rpm``. We normalize
both for:
- ``correlation_key_for_payload`` (DefectDojo-style cross-source linking)
- ``get_finding_group_key`` (dashboard grouping parity)
"""

from __future__ import annotations

# CPE / vendor short names → common package name used by distro SCA tools
_SCA_PACKAGE_ALIASES: dict[str, str] = {
    "ssl": "openssl",
    "libssl": "openssl",
    "libssl3": "openssl",
    "libssl1.1": "openssl",
    "libssl1.0.0": "openssl",
    "openssl": "openssl",
}


def normalize_ecosystem_token(ecosystem: str | None) -> str:
    """Match grouping: npm/yarn/pnpm share one registry bucket."""
    e = (ecosystem or "").lower().strip()
    if e in ("npm", "yarn", "pnpm"):
        return "npm"
    return e


def infer_sca_ecosystem_from_container_ref(image: str | None, tag: str | None) -> str:
    """
    Infer likely distro package namespace from image reference / tag when scanners omit ``ecosystem``.

    Examples: ``kafka:3.6.1-debian-12-r12`` → debian; ``app:ubi9`` → rpm.
    """
    blob = f"{image or ''} {tag or ''}".lower()
    if not blob.strip():
        return ""
    if any(
        x in blob
        for x in (
            "debian",
            "ubuntu",
            "-deb",
            "deb12",
            "deb11",
            "bookworm",
            "bullseye",
            "jammy",
            "focal",
        )
    ):
        return "debian"
    if any(
        x in blob
        for x in (
            "rhel",
            "ubi",
            "alma",
            "rocky",
            "centos",
            "fedora",
            "amzn",
            "amazonlinux",
        )
    ):
        return "rpm"
    return ""


def infer_sca_ecosystem_from_benchmark_family(benchmark_family: str | None) -> str:
    """
    When SCA payload omits ``ecosystem``, infer from OpenSCAP / SCAP benchmark family.

    Conservative substring rules on normalized family strings (see ``openscap_identity``
    families like ``RHEL_9_STIG``).
    """
    if not benchmark_family or not isinstance(benchmark_family, str):
        return ""
    bf = benchmark_family.lower()
    if any(
        x in bf
        for x in (
            "rhel",
            "red_hat",
            "centos",
            "rocky",
            "alma",
            "fedora",
            "ol_",
            "_ol_",
        )
    ):
        return "rpm"
    if any(x in bf for x in ("ubuntu", "debian", "u_ubuntu")):
        return "debian"
    return ""


def effective_sca_ecosystem(
    ecosystem: str | None,
    benchmark_family: str | None,
    *,
    image: str | None = None,
    tag: str | None = None,
) -> str:
    """Resolved ecosystem for SCA correlation/grouping (explicit beats inferred)."""
    eco = normalize_ecosystem_token(ecosystem)
    if eco:
        return eco
    eco = infer_sca_ecosystem_from_benchmark_family(benchmark_family)
    if eco:
        return eco
    return infer_sca_ecosystem_from_container_ref(image, tag)


def normalize_sca_package_for_cross_scanner(name: str) -> str:
    """
    Map CPE-style product tokens to names that match distro/CVE scanner packages.

    ``name`` should already be a single token / base (e.g. from ``component_base``).
    """
    n = (name or "").strip().lower()
    if not n:
        return ""
    if n in _SCA_PACKAGE_ALIASES:
        return _SCA_PACKAGE_ALIASES[n]
    if n.startswith("libssl"):
        return "openssl"
    return n
