# Container Scanning: Nested Helm Bundles & SCAP Compliance

## Executive Summary

Your `kamiwaza-helm.00.tar` contains **container images** inside `.wrap` files. The `.wrap` format is an imgpkg/Carvel-style bundle: gzipped tars with Helm charts plus **OCI image layouts** embedded. The current VAT scanner does not extract or discover these; it only looks for top-level `.tar` files and passes them to `docker load`, which fails on this structure.

This document summarizes industry practice and recommends a generalized approach.

---

## 1. What Your Artifacts Contain

### Structure

```
kamiwaza-helm.00.tar                    # Outer tar (generic, not docker save)
└── kamiwaza-helm/
    ├── cert-manager.wrap              # gzipped tar
    ├── extension-operator.wrap
    ├── grafana.wrap                    # Chart-only (no images)
    ├── kamiwaza.wrap                   # Chart + OCI images (~5.8GB)
    ├── kuberay.wrap
    └── metrics-server.wrap
```

### .wrap File Contents (e.g. kamiwaza.wrap)

- **Chart**: `kamiwaza-0.2.0/chart/` — Helm chart (Chart.yaml, templates, etc.)
- **Images**: `kamiwaza-0.2.0/images/<digest>.layout/` — OCI image layout per image

Each `.layout` directory follows the [OCI Image Layout spec](https://github.com/opencontainers/image-spec/blob/main/image-layout.md):

```
<digest>.layout/
├── oci-layout
├── index.json
└── blobs/
    └── sha256/
        ├── <config-hash>
        ├── <layer-hash>
        └── ...
```

This is the same format used by **imgpkg** (Carvel), **relok8s**, and similar Helm offline bundle tools.

---

## 2. Industry Practice for SCAP/Compliance Scans

### 2.1 OpenSCAP / oscap-docker

- **Standard flow**: `oscap-docker image <image-ref>` — requires the image to be in the Docker daemon.
- **Saved images**: Either `docker load -i <tar>` first, or use **skopeo** to load OCI layout:
  ```bash
  skopeo copy oci:/path/to/layout docker-daemon:vat-scan-xyz:tag
  oscap-docker image vat-scan-xyz:tag xccdf eval ...
  ```
- **oscap-dockerless**: A wrapper exists for scanning saved Docker images without Docker, but it targets `docker save` tarballs; OCI layout support is unclear.

### 2.2 Trivy

- **Docker save tar**: `trivy image --input /path/to/image.tar`
- **OCI layout**: `trivy image --input /path/to/oci-layout-dir` — Trivy accepts OCI layout directories directly; no Docker required.

### 2.3 Bundle Formats (werf, imgpkg, Helm offline)

| Tool      | Format                         | Images stored as        |
|-----------|--------------------------------|--------------------------|
| werf      | OCI registry or `archive:*.tar.gz` | OCI images in registry   |
| imgpkg    | OCI bundle                     | OCI layout in bundle     |
| relok8s   | Chart + images tar             | OCI layout per image     |
| kajiya    | `.wrap` (gzipped tar)          | OCI layout in `images/<digest>.layout/`; image refs in `chart/Images.lock` |

Common pattern: **extract archive → walk for OCI layouts → scan each layout**.

---

## 3. Recommended Generalized Approach

### 3.1 Discovery Pipeline

1. **Find candidate archives** under the scan path:
   - `.tar`, `.tar.gz`, `.tgz`, `.wrap`
   - Optionally: split archives (`.00`, `.01`, …) — concatenate or extract part 1 only if format allows

2. **Extract** each archive to a temp directory (avoid re-extracting same file).

3. **Recurse** the extracted tree to find image sources:
   - **Docker save**: file with top-level `manifest.json` and layer tars (e.g. `*.tar` in same dir)
   - **OCI layout**: directory containing `oci-layout` and `index.json` (and `blobs/sha256/`)

4. **Validate** before scanning:
   - Docker save: `manifest.json` exists and is valid
   - OCI layout: `oci-layout` + `index.json` present

### 3.2 Scan Pipeline (per discovered image)

| Format       | Trivy                          | STIG (OpenSCAP)                                      |
|--------------|--------------------------------|-------------------------------------------------------|
| Docker save  | `trivy image --input <tar>`    | `docker load -i <tar>` → `oscap-docker image <ref>`  |
| OCI layout   | `trivy image --input <dir>`    | `skopeo copy oci:<dir> docker-daemon:<ref>` → `oscap-docker image <ref>` |

Use a unique temporary image ref (e.g. `vat-scan-<uuid>:tag`) to avoid collisions and clean up after STIG.

### 3.3 Implementation Outline

```
collect_container_sources(path: Path) -> list[ContainerSource]:
    sources = []
    for archive in find_archives(path, [".tar", ".tar.gz", ".tgz", ".wrap"]):
        with extract_to_temp(archive) as ext_dir:
            for candidate in walk_for_images(ext_dir):
                if is_docker_save(candidate):
                    sources.append(ContainerSource(path=candidate, format="docker-save"))
                elif is_oci_layout(candidate):
                    sources.append(ContainerSource(path=candidate, format="oci-layout"))

walk_for_images(dir):
    # Docker save: single tar with manifest.json
    for f in dir.rglob("manifest.json"):
        parent = f.parent
        if looks_like_docker_save(parent):
            yield parent  # or the tar that was extracted from
    # OCI layout: directory with oci-layout + index.json
    for d in dir.rglob("oci-layout"):
        layout_dir = d.parent
        if (layout_dir / "index.json").exists():
            yield layout_dir
```

**Note**: For `.wrap` files, the OCI layout is *inside* the extracted directory (e.g. `kamiwaza-0.2.0/images/<digest>.layout/`). Each `.layout` directory is one image.

### 3.4 Dependencies

- **skopeo**: For `oci:` → `docker-daemon:` when running STIG on OCI layouts.
- **Trivy**: Already used; supports both docker save and OCI layout.
- **Docker**: Required for `oscap-docker` (Chainguard image); used for STIG only.

---

## 4. Handling Split Archives

`kamiwaza-helm.00.tar` suggests a split archive (`.00`, possibly `.01`, …). Options:

1. **Extract `.00` only** — if the format is “first part contains metadata + first chunk” and is self-contained for the images you need.
2. **Concatenate** — `cat kamiwaza-helm.*.tar | tar -xf -` if it’s a simple split tar.
3. **Document** — If the build uses a custom split format, document the expected layout and extraction steps.

---

## 5. ATO / Compliance Caveats

**Chainguard GPOS STIG status**: The Chainguard GPOS STIG may not yet be a DISA-published STIG — it is vendor-submitted and may still be in DISA's review pipeline. This matters for:

- **FedRAMP**: SSP typically requires DoD STIGs, then CIS Level 2, then custom baselines. Chainguard's STIG could qualify as a custom baseline if not yet DISA-published.
- **DoD RMF / eMASS**: Your AO may require a DISA-published STIG specifically — confirm before building around this.
- **Profile**: The `xccdf_basic_profile_.check` profile in the example is a basic check profile — ensure you use the right profile for your compliance requirement.

**False positives**: The Chainguard GPOS documentation includes a section on expected false positives (auditd, ASLR, firewall, filesystem controls as host-level responsibilities). These rationales are useful for POA&M when documenting N/A findings.

---

## 6. Summary

| Question                         | Answer                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| Are containers in your artifacts? | Yes — inside `.wrap` files as OCI image layouts.                        |
| Why doesn’t it work today?       | Scanner only considers top-level `.tar` and runs `docker load` on them. |
| How is this usually handled?     | Extract archives, find OCI layouts and docker-save tars, scan each.     |
| Trivy                            | Use `--input` with OCI layout dir or docker save tar.                   |
| STIG/OpenSCAP                    | Load into Docker via `docker load` or `skopeo copy oci:... docker-daemon:...`, then `oscap-docker`. |
| Generalization                    | One discovery pipeline for archives + OCI layouts + docker save; one scan pipeline per format. |
