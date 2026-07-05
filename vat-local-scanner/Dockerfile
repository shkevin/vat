# VAT Local Scanner — self-contained image with Trivy, Grype, npm, pip-audit
# Run: docker run -v $(pwd)/repo:/scan -e VAT_URL=... -e VAT_ADMIN_TOKEN=... vat-scanner scan /scan [--asset NAME] [--dry-run]

FROM cgr.dev/chainguard/openscap:latest AS openscap-content

FROM python:3.11-slim-bookworm

# Docker CLI from official repo (API 1.44+); docker.io is too old for Docker 26.x hosts
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    nodejs \
    npm \
    gnupg \
    openscap-scanner \
    openscap-utils \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/xml/scap/ssg/content
COPY --from=openscap-content /usr/share/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml /usr/share/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml

# ComplianceAsCode SSG datastreams for DISA STIG scanning of non-chainguard base
# images (RHEL/Rocky/Alma/Oracle, Ubuntu, SLE). run_stig_image_ref auto-selects
# ssg-<os><ver>-ds.xml + the `stig` profile from the scanned image's os-release.
# Non-fatal: a download hiccup leaves those images skipping; the chainguard path
# (and everything else) still builds and works.
ARG SSG_VERSION=0.1.73
RUN (curl -fsSL -o /tmp/ssg.zip "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip" \
    && python3 -c "import zipfile; z=zipfile.ZipFile('/tmp/ssg.zip'); [z.extract(m,'/tmp/ssg') for m in z.namelist() if m.endswith('-ds.xml')]" \
    && find /tmp/ssg -type f \( -name 'ssg-rhel[89]-ds.xml' -o -name 'ssg-ubuntu2[024]04-ds.xml' -o -name 'ssg-sle15-ds.xml' -o -name 'ssg-ol[89]-ds.xml' \) -exec cp {} /usr/share/xml/scap/ssg/content/ \; \
    && rm -rf /tmp/ssg /tmp/ssg.zip) \
    || echo "WARN: SSG STIG content unavailable for v${SSG_VERSION}; non-chainguard STIG will skip"

# Skopeo 1.20.0 from felipecrs/skopeo-bin (newer than apt; fixes "io: read/write on closed pipe" with Docker 26.x)
ARG TARGETARCH=amd64
RUN SKOPEO_VERSION=1.20.0 && \
    case "${TARGETARCH}" in \
        amd64) SKOPEO_ARCH=linux-amd64 ;; \
        arm64) SKOPEO_ARCH=linux-arm64 ;; \
        *) SKOPEO_ARCH=linux-amd64 ;; \
    esac && \
    curl -fsSL "https://github.com/felipecrs/skopeo-bin/releases/download/v${SKOPEO_VERSION}/skopeo.${SKOPEO_ARCH}" -o /usr/local/bin/skopeo && \
    chmod +x /usr/local/bin/skopeo

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# crictl for node runtime inventory enumeration (containerd/CRI)
RUN CRICTL_VERSION="$(python3 -c "import json, urllib.request; print(json.load(urllib.request.urlopen('https://api.github.com/repos/kubernetes-sigs/cri-tools/releases/latest'))['tag_name'])")" && \
    case "${TARGETARCH}" in \
        amd64) CRICTL_ARCH=amd64 ;; \
        arm64) CRICTL_ARCH=arm64 ;; \
        *) CRICTL_ARCH=amd64 ;; \
    esac && \
    curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${CRICTL_ARCH}.tar.gz" -o /tmp/crictl.tar.gz && \
    tar -xzf /tmp/crictl.tar.gz -C /usr/local/bin crictl && \
    rm /tmp/crictl.tar.gz

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks (secrets)
RUN GITLEAKS_VERSION=8.27.2 && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin && rm /tmp/gitleaks.tar.gz

# pip-audit (Python) and Semgrep (SAST; requires >=1.50 for pre-built wheels)
RUN pip install --no-cache-dir pip-audit "semgrep>=1.50"

WORKDIR /app

# Install vat-scanner package
COPY pyproject.toml README.md ./
COPY vat_scanner ./vat_scanner
RUN pip install --no-cache-dir .

# Default: run scan --help (override with docker run ... scan /scan)
ENTRYPOINT ["python", "-m", "vat_scanner.cli"]
CMD ["scan", "--help"]
