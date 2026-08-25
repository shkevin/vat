# Security Policy

VAT is a vulnerability management tool, so we take reports against it seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub:

1. Go to the [Security tab](https://github.com/shkevin/vat/security/advisories/new)
2. Click **Report a vulnerability**

That opens a private advisory visible only to you and the maintainers.

Please include:

- what the issue is and roughly how severe you think it is
- the steps or a proof of concept needed to reproduce it
- affected version or commit
- anything you already know about a fix or workaround

You can expect an acknowledgement within about a week. If a report is confirmed,
we will agree a disclosure timeline with you and credit you in the advisory
unless you would rather stay anonymous.

## Supported versions

VAT has not reached 1.0. Only the `main` branch receives security fixes.

## Scope

In scope: the backend API, the frontend, the local scanner, the Kubernetes
operator, and the deployment manifests in this repository.

Out of scope:

- vulnerabilities in the scanners VAT integrates with (Trivy, Grype, Semgrep,
  Gitleaks, …) — report those to their own maintainers
- findings that require an already-compromised host or database
- missing hardening in the `docker-compose.yml`, which is a development
  convenience and is not intended for production

## Operational notes

- The first migration creates an `admin` user with a randomly generated
  password, printed once. Set `VAT_ADMIN_BOOTSTRAP_PASSWORD` to choose it.
  Change it after first login.
- `VAT_SECRET_KEY` must be set to a strong random value in any real deployment.
- The `docker-compose.yml` defaults (`POSTGRES_PASSWORD: vat`, Grafana
  `admin`) are for local development only.
