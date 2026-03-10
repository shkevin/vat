"""Configuration loading: vat-scanner.yaml, env vars, CLI overrides."""

from __future__ import annotations

import os
from datetime import datetime, timezone
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

DEFAULT_TEMP_DIR = tempfile.gettempdir()

# Default exclude patterns (PRD §2.2 US-5)
DEFAULT_EXCLUDES = [
    "**/node_modules/**",
    "**/.git/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/.venv/**",
]

# Scan type → parser mapping (PRD §3.2)
SCAN_TYPE_TO_PARSER: dict[str, str] = {
    "code": "semgrep",
    "dependencies": "grype",  # also npm_audit, pip_audit
    "secrets": "trivy",  # also gitleaks
    "iac": "trivy",
    "license": "trivy",
    "container": "trivy",
    "stig": "openscap",  # Chainguard GPOS STIG for containers
    "oval_cve": "openscap_oval",  # OpenSCAP OVAL CVE scan (oscap-docker image-cve)
}

# All scan types
ALL_SCAN_TYPES = ["code", "dependencies", "secrets", "iac", "license", "container", "stig", "oval_cve"]

# Default scan types (oval_cve is opt-in; add to scan_types to enable)
DEFAULT_SCAN_TYPES = [t for t in ALL_SCAN_TYPES if t != "oval_cve"]


def _expand_env(value: str) -> str:
    """Expand ${VAR} and $VAR in string."""
    if not isinstance(value, str):
        return value

    def replacer(match: re.Match[str]) -> str:
        var = match.group(1) or match.group(2)
        return os.environ.get(var, match.group(0))

    return re.sub(r"\$\{([^}]+)\}|\$([a-zA-Z_][a-zA-Z0-9_]*)", replacer, value)


def _expand_env_in_dict(obj: Any) -> Any:
    """Recursively expand env vars in dict/list/str."""
    if isinstance(obj, dict):
        return {k: _expand_env_in_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_in_dict(v) for v in obj]
    if isinstance(obj, str):
        return _expand_env(obj)
    return obj


def find_config_file(path: Path | None, explicit: Path | None) -> Path | None:
    """Find vat-scanner.yaml or .vat-scanner.yaml in repo root or explicit path."""
    if explicit and explicit.exists():
        return explicit

    search_dirs: list[Path] = []
    if path and path.is_dir():
        search_dirs.append(path)
        # Also check parent (repo root)
        if (path / ".git").exists():
            search_dirs.append(path)
        else:
            # Walk up to find .git or vat-scanner.yaml
            current = path
            for _ in range(5):
                if (current / "vat-scanner.yaml").exists() or (current / ".vat-scanner.yaml").exists():
                    search_dirs.append(current)
                    break
                if (current / ".git").exists():
                    search_dirs.append(current)
                    break
                parent = current.parent
                if parent == current:
                    break
                current = parent
            search_dirs.append(path)

    for d in search_dirs:
        for name in ("vat-scanner.yaml", ".vat-scanner.yaml"):
            candidate = d / name
            if candidate.exists():
                return candidate

    return None


def load_config_file(config_path: Path) -> dict[str, Any]:
    """Load and parse YAML config. Expands env vars in values."""
    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}
    return _expand_env_in_dict(raw)


def load_ignore_file(repo_root: Path) -> list[str]:
    """Load .vatignore or .vat-scanner-ignore patterns from repo root."""
    for name in (".vatignore", ".vat-scanner-ignore"):
        path = repo_root / name
        if path.exists():
            patterns = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
            return patterns
    return []


class ScannerConfig:
    """Effective scanner configuration (config file + env + CLI overrides)."""

    def __init__(
        self,
        *,
        vat_url: str = "",
        api_key: str = "",
        admin_token: str = "",
        asset: str = "",
        scan_types: list[str] | None = None,
        exclude: list[str] | None = None,
        dry_run: bool = False,
        gating_mode: str = "",
        fail_on: str = "",
        base_commit_id: str = "",
        head_commit_id: str = "",
        scan_timeout_ms: int = 900_000,
        disable_artifact_scanning: bool = False,
        reset_keys: bool = False,
        gating_result_output: str = "",
        no_snippets: bool = False,
        sarif_output: str = "",
        debug: bool = False,
        verbose: bool = False,
        temp_dir: str = "",
        tag: str = "",
        dev_limit: int = 0,
        save_openscap_xml: str = "",
    ):
        self.vat_url = vat_url or os.environ.get("VAT_URL", "").strip()
        self.api_key = api_key or os.environ.get("VAT_API_KEY", "").strip()
        self.admin_token = admin_token or os.environ.get("VAT_ADMIN_TOKEN", "").strip()
        self.asset = asset
        self.scan_types = scan_types or list(DEFAULT_SCAN_TYPES)
        self.exclude = exclude or list(DEFAULT_EXCLUDES)
        self.dry_run = dry_run
        self.gating_mode = gating_mode
        self.fail_on = fail_on
        self.base_commit_id = base_commit_id
        self.head_commit_id = head_commit_id
        self.scan_timeout_ms = scan_timeout_ms
        self.disable_artifact_scanning = disable_artifact_scanning
        self.reset_keys = reset_keys
        self.gating_result_output = gating_result_output
        self.no_snippets = no_snippets
        self.sarif_output = sarif_output
        self.debug = debug
        self.verbose = verbose
        self.temp_dir = (temp_dir or os.environ.get("VAT_SCANNER_TEMP_DIR", "") or DEFAULT_TEMP_DIR).strip()
        # Tag for package delineation (default: date+time to support multiple scans per day)
        self.tag = tag or datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        # Dev mode: limit container scans to N items (0 = no limit)
        self.dev_limit = max(0, int(dev_limit)) if dev_limit else 0
        # Save OpenSCAP XML to dir for debugging (empty = don't save)
        self.save_openscap_xml = (save_openscap_xml or "").strip()

    @classmethod
    def from_file(cls, config_path: Path, scan_path: Path | None = None) -> "ScannerConfig":
        """Build config from YAML file."""
        raw = load_config_file(config_path)
        gating = raw.get("gating") or {}

        exclude = raw.get("exclude")
        if isinstance(exclude, list):
            exclude = [str(x) for x in exclude]
        else:
            exclude = list(DEFAULT_EXCLUDES)

        # Merge .vatignore if present
        if scan_path and scan_path.is_dir():
            ignore_patterns = load_ignore_file(scan_path)
            if ignore_patterns:
                exclude = list(set(exclude) | set(ignore_patterns))

        return cls(
            vat_url=str(raw.get("vat_url", "")),
            asset=str(raw.get("asset", scan_path.name if scan_path else "")),
            tag=str(raw.get("tag", "")),
            dev_limit=int(raw.get("dev_limit", 0)),
            scan_types=raw.get("scan_types") or list(DEFAULT_SCAN_TYPES),
            exclude=exclude,
            gating_mode=str(gating.get("mode", "")),
            fail_on=str(gating.get("fail_on", "")),
            base_commit_id=str(gating.get("base_commit_id", "")),
            head_commit_id=str(gating.get("head_commit_id", "")),
            scan_timeout_ms=int(raw.get("scan_timeout_ms", 900_000)),
            disable_artifact_scanning=bool(raw.get("disable_artifact_scanning", False)),
            temp_dir=str(raw.get("temp_dir", "")),
        )

    def merge_cli(
        self,
        *,
        vat_url: str | None = None,
        api_key: str | None = None,
        admin_token: str | None = None,
        asset: str | None = None,
        scan_types: list[str] | None = None,
        exclude: list[str] | None = None,
        dry_run: bool | None = None,
        gating_mode: str | None = None,
        fail_on: str | None = None,
        base_commit_id: str | None = None,
        head_commit_id: str | None = None,
        scan_timeout_ms: int | None = None,
        disable_artifact_scanning: bool | None = None,
        reset_keys: bool | None = None,
        gating_result_output: str | None = None,
        no_snippets: bool | None = None,
        sarif_output: str | None = None,
        debug: bool | None = None,
        verbose: bool | None = None,
        temp_dir: str | None = None,
        tag: str | None = None,
        dev_limit: int | None = None,
        save_openscap_xml: str | None = None,
    ) -> "ScannerConfig":
        """Return new config with CLI overrides applied."""
        return ScannerConfig(
            vat_url=vat_url if vat_url is not None else self.vat_url,
            api_key=api_key if api_key is not None else self.api_key,
            admin_token=admin_token if admin_token is not None else self.admin_token,
            asset=asset if asset is not None else self.asset,
            scan_types=scan_types if scan_types is not None else self.scan_types,
            exclude=exclude if exclude is not None else self.exclude,
            dry_run=dry_run if dry_run is not None else self.dry_run,
            gating_mode=gating_mode if gating_mode is not None else self.gating_mode,
            fail_on=fail_on if fail_on is not None else self.fail_on,
            base_commit_id=base_commit_id if base_commit_id is not None else self.base_commit_id,
            head_commit_id=head_commit_id if head_commit_id is not None else self.head_commit_id,
            scan_timeout_ms=scan_timeout_ms if scan_timeout_ms is not None else self.scan_timeout_ms,
            disable_artifact_scanning=(
                disable_artifact_scanning
                if disable_artifact_scanning is not None
                else self.disable_artifact_scanning
            ),
            reset_keys=reset_keys if reset_keys is not None else self.reset_keys,
            gating_result_output=(
                gating_result_output if gating_result_output is not None else self.gating_result_output
            ),
            no_snippets=no_snippets if no_snippets is not None else self.no_snippets,
            sarif_output=sarif_output if sarif_output is not None else self.sarif_output,
            debug=debug if debug is not None else self.debug,
            verbose=verbose if verbose is not None else self.verbose,
            temp_dir=temp_dir if temp_dir is not None else self.temp_dir,
            tag=tag if tag is not None else self.tag,
            dev_limit=dev_limit if dev_limit is not None else self.dev_limit,
            save_openscap_xml=save_openscap_xml if save_openscap_xml is not None else self.save_openscap_xml,
        )
