"""Minimal in-cluster Kubernetes client for ScanRequest CRs (Phase 3 worker queue).

Dependency-free: talks to the API server over urllib with the pod's service
account token, mirroring ``_fetch_kubernetes_secret`` in cli.py. The worker uses
this to pull pending ScanRequests, claim them (optimistic concurrency on the
status subresource), and report done/failed.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path

GROUP = "vat.io"
VERSION = "v1alpha1"
PLURAL = "scanrequests"

_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
_NS_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


class K8sConflict(Exception):
    """HTTP 409 — lost the optimistic-concurrency race; another worker won the claim."""


class K8sError(Exception):
    """Any other API error (auth, not-found, transport)."""


class ScanRequestClient:
    """Tiny ScanRequest CR client over the in-cluster API."""

    def __init__(self, namespace: str | None = None):
        host = os.environ.get("VAT_KUBERNETES_API_HOST", "kubernetes.default.svc").strip()
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443").strip() or "443"
        self._base = f"https://{host}:{port}"
        self._token = _TOKEN_PATH.read_text(encoding="utf-8").strip() if _TOKEN_PATH.exists() else ""
        self._ctx = (
            ssl.create_default_context(cafile=str(_CA_PATH))
            if _CA_PATH.exists()
            else ssl.create_default_context()
        )
        self.namespace = (
            namespace
            or os.environ.get("POD_NAMESPACE", "").strip()
            or (_NS_PATH.read_text(encoding="utf-8").strip() if _NS_PATH.exists() else "")
            or "vat-operator"
        )

    def available(self) -> bool:
        """True when running in-cluster with a service account token."""
        return bool(self._token)

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self._base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            if e.code == 409:
                raise K8sConflict() from e
            raise K8sError(f"{method} {path}: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise K8sError(f"{method} {path}: {e}") from e

    def _collection_path(self) -> str:
        return f"/apis/{GROUP}/{VERSION}/namespaces/{self.namespace}/{PLURAL}"

    def list(self) -> list[dict]:
        """All ScanRequests in the namespace."""
        return (self._request("GET", self._collection_path()) or {}).get("items", [])

    def update_status(self, obj: dict) -> dict:
        """PUT the object's status subresource. Requires metadata.resourceVersion;
        a stale version yields K8sConflict (the atomic-claim primitive)."""
        name = obj["metadata"]["name"]
        return self._request("PUT", f"{self._collection_path()}/{name}/status", obj)
