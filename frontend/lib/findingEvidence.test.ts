import { describe, expect, it } from "vitest";

import { buildFindingEvidence } from "./findingEvidence";
import type { Finding } from "@/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f-test",
    findingType: "SCA",
    fingerprintId: "fp-test",
    cveId: "CVE-2026-0001",
    severity: "High",
    status: "Open",
    sources: [{ name: "trivy", importedAt: "2026-06-26T00:00:00Z" }],
    audit: [],
    ...overrides,
  };
}

describe("buildFindingEvidence", () => {
  it("builds source-backed proof from file location and masked snippet", () => {
    const evidence = buildFindingEvidence(
      finding({
        findingType: "Secret",
        cveId: "private-key",
        title: "Private key detected",
        filePath: "src/config.ts",
        line: 12,
        sourceFileUrl:
          "https://github.example.local/acme/app/blob/main/src/config.ts#L12",
        snippetMasked: "const token = \"***REDACTED***\";",
        ruleId: "gitleaks-private-key",
        secretType: "Private Key",
        description: "A private key was detected in source control.",
      }),
    );

    expect(evidence.summary).toContainEqual({
      label: "Location",
      value: "src/config.ts:12",
      href: "https://github.example.local/acme/app/blob/main/src/config.ts#L12",
    });
    expect(evidence.summary).toContainEqual({
      label: "Secret type",
      value: "Private Key",
    });
    expect(evidence.proof).toEqual({
      label: "Masked line preview",
      language: "text",
      content: "const token = \"***REDACTED***\";",
      masked: true,
    });
    expect(evidence.explanation).toBe(
      "A private key was detected in source control.",
    );
    expect(evidence.warnings).toContain(
      "Rotate the exposed credential and verify it has not been used.",
    );
  });

  it("builds package evidence for SCA findings without pretending a snippet exists", () => {
    const evidence = buildFindingEvidence(
      finding({
        findingType: "SCA",
        cveId: "CVE-2026-1234",
        title: "openssl vulnerable to example attack",
        component: "openssl 3.0.1",
        componentBase: "openssl",
        ecosystem: "debian",
        image: "containers/images/api",
        tag: "1.2.3",
        imageDigest: "sha256:abc123",
        cvss: "9.8",
        epss: "0.42",
        description: "Upgrade OpenSSL to a patched version.",
      }),
    );

    expect(evidence.summary).toContainEqual({
      label: "Package",
      value: "openssl 3.0.1",
    });
    expect(evidence.summary).toContainEqual({
      label: "Image",
      value: "containers/images/api:1.2.3",
    });
    expect(evidence.summary).toContainEqual({
      label: "Image digest",
      value: "sha256:abc123",
    });
    expect(evidence.summary).toContainEqual({ label: "CVSS", value: "9.8" });
    expect(evidence.summary).toContainEqual({ label: "EPSS", value: "0.42" });
    expect(evidence.proof).toBeUndefined();
    expect(evidence.remediation).toBe(
      "Upgrade or replace the affected package in the image, rebuild it, and rescan the asset.",
    );
  });

  it("builds a dedicated risk scoring section from source, threat, context, and environmental fields", () => {
    const evidence = buildFindingEvidence(
      finding({
        findingType: "SCA",
        component: "ecdsa 0.19.2",
        image: "ghcr.io/kamiwaza-internal/kamiwaza/images/core",
        tag: "release-0.13.5",
        cveId: "CVE-2024-23342",
        title: "python-ecdsa: vulnerable to the Minerva attack",
        cvss: "7.4",
        epss: "0.012",
        riskScoring: {
          source: {
            source: "trivy",
            cvssVersion: "3.1",
            vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            score: "7.4",
            severity: "High",
            scannerTitle: "python-ecdsa: vulnerable to the Minerva attack",
            fixedVersion: "NONE",
          },
          threat: {
            epss: "0.012",
            knownExploited: false,
            exploitMaturity: "No known exploit",
          },
          context: {
            reachability: "No path found",
            fixAvailable: false,
            assetCriticality: "Production",
            internetExposure: "Internal",
          },
          environmental: {
            cvssVersion: "3.1",
            vector:
              "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/MC:N/MI:N/MA:N",
            score: "0.0",
            rationale: "The vulnerable ECDSA signing path is not reachable.",
            knownScannerException: "Trivy reports one High in the core image.",
            scopeNote: "Generated container image scan set.",
          },
        },
      }),
    );

    expect(evidence.riskScoring).toContainEqual({
      label: "Source CVSS",
      value: "7.4 High",
    });
    expect(evidence.riskScoring).toContainEqual({
      label: "Source vector",
      value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    });
    expect(evidence.riskScoring).toContainEqual({
      label: "Fixed version",
      value: "NONE",
    });
    expect(evidence.riskScoring).toContainEqual({
      label: "Environmental score",
      value: "0.0",
    });
    expect(evidence.riskScoring).toContainEqual({
      label: "Reachability",
      value: "No path found",
    });
    expect(evidence.riskScoringNotes).toContainEqual({
      label: "Environmental Scoring Rationale",
      value: "The vulnerable ECDSA signing path is not reachable.",
    });
  });

  it("uses OpenSCAP benchmark fields and check output as evidence", () => {
    const evidence = buildFindingEvidence(
      finding({
        findingType: "SCA",
        cveId: "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        title: "Disable SSH root login",
        source: "openscap",
        component: "sshd_config",
        filePath: "/etc/ssh/sshd_config",
        snippetMasked: "PermitRootLogin yes",
        ruleId: "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        benchmarkId: "xccdf_org.ssgproject.content_benchmark_RHEL-9",
        benchmarkFamily: "stig",
        description: "**Disable SSH root login**\n\nRule: `xccdf...`",
      }),
    );

    expect(evidence.summary).toContainEqual({
      label: "Benchmark",
      value: "xccdf_org.ssgproject.content_benchmark_RHEL-9",
    });
    expect(evidence.summary).toContainEqual({
      label: "Benchmark family",
      value: "stig",
    });
    expect(evidence.summary).toContainEqual({
      label: "Rule",
      value: "xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
    });
    expect(evidence.proof).toEqual({
      label: "Check output",
      language: "text",
      content: "PermitRootLogin yes",
      masked: false,
    });
    expect(evidence.remediation).toBe(
      "Review the benchmark rule, apply the required configuration change, and rescan the host or image.",
    );
  });
});
