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
