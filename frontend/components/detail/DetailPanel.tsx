"use client";

import { useState, useEffect, useCallback } from "react";

/** Collapsible section for supporting metadata */
function CollapsibleSection({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="detail-panel-collapsible">
      <button
        type="button"
        className="detail-panel-collapsible-header"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {title}
        <span className="chevron" aria-hidden>
          ▼
        </span>
      </button>
      {open && <div className="detail-panel-collapsible-body">{children}</div>}
    </div>
  );
}
import { TypeTag, SevTag, StTag, SrcTag, Btn, Field } from "@/components/atoms";
import { mono, sans } from "@/lib/styles";
import {
  formatFileLocation,
  getRepoFileUrl,
  parseFileLocation,
} from "@/lib/repoFileUrl";
import { effectiveGroupKey } from "@/lib/findingGroupUtils";
import { SEV_ORDER } from "@/lib/constants";
import { syncFindingToTracker } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import {
  daysLeft,
  displayTitle,
  displaySourceName,
  fmtDt as fmtDtUtil,
  now,
} from "@/lib/utils";
import type { Finding } from "@/types";
import type { Source } from "@/types";
import type { Tracker } from "@/types";
import { FindingDescription } from "@/components/detail/FindingDescription";

interface DetailPanelProps {
  finding: Finding;
  allFindings?: Finding[];
  sources: Source[];
  tracker: Tracker;
  trackers?: Tracker[];
  onClose: () => void;
  onUpdate: (upd: Finding) => void | Promise<void>;
  onArchive: (id: string, reason: string) => void | Promise<void>;
  onUnarchive: (id: string) => void | Promise<void>;
  onRevert: (id: string, reason: string) => void | Promise<void>;
  onOverrideFingerprint?: (id: string) => void | Promise<void>;
  /** When true, hide all edit/action controls. Default from user.role === 'read_only'. */
  readOnly?: boolean;
  /** When true, show admin-only actions (fingerprint override, revert, archive). Default from user.role === 'admin'. */
  isAdmin?: boolean;
  /** Base URL for repo file links (e.g. https://github.com/org). When set, Component links to repo file at line. */
  repoBaseUrl?: string;
  /** Repo URL format: github | gitlab. Default: github. */
  repoUrlType?: "github" | "gitlab";
  /** When true, show Subissues section with grouped instances (Aikido-style). Default false. */
  groupFindings?: boolean;
  /** When in instance mode, which source to show (index into finding.sources). Hides group view. */
  selectedSourceIndex?: number;
}

export function DetailPanel({
  finding,
  allFindings = [],
  sources,
  tracker,
  trackers = [],
  onClose,
  onUpdate,
  onArchive,
  onUnarchive,
  onRevert,
  onOverrideFingerprint,
  readOnly = false,
  isAdmin = false,
  repoBaseUrl,
  repoUrlType = "github",
  groupFindings = false,
  selectedSourceIndex,
}: DetailPanelProps) {
  const descriptionText =
    (finding.description ?? "").trim() || displayTitle(finding);
  const [jus, setJus] = useState(finding.justification ?? "");
  const [comp, setComp] = useState(finding.compensatingControls ?? "");
  const [rvNote, setRvNote] = useState(finding.reviewerNote ?? "");
  const [attApprover, setAttApprover] = useState(
    finding.attestation?.approver ?? "",
  );
  const [attTitle, setAttTitle] = useState(
    finding.attestation?.approverTitle ?? "",
  );
  const [attExpiry, setAttExpiry] = useState(
    finding.attestation?.expiresAt ?? "",
  );
  const [attRef, setAttRef] = useState(finding.attestation?.waiverRef ?? "");
  const [suppScope, setSuppScope] = useState<"global" | "contextual">(
    (finding.suppressionScope as "global" | "contextual") ?? "contextual",
  );
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState("");
  const [showRevert, setShowRevert] = useState(false);
  const [revertReason, setRevertReason] = useState("");
  const [showArchiveForm, setShowArchiveForm] = useState(false);
  const [archiveReason, setArchiveReason] = useState("");
  const [overrideFpLoading, setOverrideFpLoading] = useState(false);
  const [savingNotes, setSavingNotes] = useState(false);
  const [syncToTrackerLoading, setSyncToTrackerLoading] = useState(false);
  const [syncToTrackerMessage, setSyncToTrackerMessage] = useState<
    string | null
  >(null);
  const [activeTab, setActiveTab] = useState<
    "details" | "decision" | "history"
  >("details");

  const { token } = useAuth();
  const canEdit = !readOnly;
  const showAdminActions = canEdit && isAdmin;
  const repoFileUrl = getRepoFileUrl(finding, repoBaseUrl, repoUrlType);

  useEffect(() => {
    setJus(finding.justification ?? "");
    setComp(finding.compensatingControls ?? "");
    setRvNote(finding.reviewerNote ?? "");
    setAttApprover(finding.attestation?.approver ?? "");
    setAttTitle(finding.attestation?.approverTitle ?? "");
    setAttExpiry(finding.attestation?.expiresAt ?? "");
    setAttRef(finding.attestation?.waiverRef ?? "");
    setSuppScope(
      (finding.suppressionScope as "global" | "contextual") ?? "contextual",
    );
    const needsTriage = ![
      "Resolved",
      "False Positive",
      "Suppressed",
      "Not Applicable",
      "Approved",
      "Duplicate",
      "Mitigated",
      "Risk Accepted",
    ].includes(finding.status);
    setActiveTab(canEdit && needsTriage ? "decision" : "details");
  }, [finding.id, finding.status, canEdit]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const doSaveNotes = useCallback(async () => {
    if (rvNote === (finding.reviewerNote ?? "")) return;
    setSavingNotes(true);
    try {
      await onUpdate({ ...finding, reviewerNote: rvNote });
      setToast("✓ Notes saved");
      setTimeout(() => setToast(""), 2500);
    } finally {
      setSavingNotes(false);
    }
  }, [finding, rvNote, onUpdate]);

  const tName = tracker?.name ?? "Tracker";
  const tIcon = tracker?.icon ?? "◈";
  const allTrackers = trackers?.length
    ? trackers
    : tracker?.name
      ? [tracker]
      : [];
  const trackerLinks = (finding.externalLinks ?? []).filter(
    (l) => l.kind === "tracker",
  );
  const TERMINAL_STATUSES = [
    "Resolved",
    "False Positive",
    "Suppressed",
    "Not Applicable",
    "Approved",
    "Duplicate",
    "Mitigated",
    "Risk Accepted",
  ];
  const canAct = !TERMINAL_STATUSES.includes(finding.status);
  const d = daysLeft(finding.slaDue);
  const priorFindings = (finding.regressionOf ?? [])
    .map((id) => allFindings.find((f) => f.id === id))
    .filter(Boolean) as Finding[];

  const doUpdate = async (status: string, extra: Partial<Finding> = {}) => {
    setSaving(true);
    const updated: Finding = {
      ...finding,
      status,
      justification: jus,
      compensatingControls: comp,
      reviewerNote: rvNote,
      ...extra,
      audit: [
        ...(finding.audit ?? []),
        {
          ts: now(),
          user: "reviewer",
          action: `Status → ${status}`,
          note: rvNote || null,
        },
      ],
    };
    try {
      await onUpdate(updated);
      setToast(`✓ ${status}`);
    } catch {
      setToast("Update failed");
    } finally {
      setSaving(false);
      setTimeout(() => setToast(""), 2500);
    }
  };

  const doRiskAccept = () => {
    const attestation = {
      approver: attApprover,
      approverTitle: attTitle,
      approvedAt: now(),
      waiverRef: attRef,
      expiresAt: attExpiry || undefined,
    };
    doUpdate("Risk Accepted", { attestation });
  };

  const doSuppress = () =>
    doUpdate("Suppressed", { suppressionScope: suppScope });
  const doFP = () => doUpdate("False Positive", { suppressionScope: "global" });

  const H = ({ children }: { children: React.ReactNode }) => (
    <h3 className="detail-panel-section-title">{children}</h3>
  );

  return (
    <div
      role="dialog"
      aria-label={`Finding details: ${finding.cveId}`}
      className="detail-panel"
    >
      {finding.archived && (
        <div className="detail-panel-alert detail-panel-alert-archived">
          <span>🗄</span>
          <div style={{ flex: 1 }}>
            <span
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 700,
                color: "var(--app-accent)",
              }}
            >
              ARCHIVED
            </span>
            {finding.archivedAt && (
              <span
                style={{
                  ...sans,
                  fontSize: 11,
                  color: "var(--app-accent)",
                  marginLeft: 8,
                }}
              >
                {fmtDtUtil(finding.archivedAt)}
              </span>
            )}
            {finding.archivedReason && (
              <div
                style={{
                  ...sans,
                  fontSize: 11,
                  color: "var(--app-accent)",
                  marginTop: 2,
                  fontStyle: "italic",
                }}
              >
                &quot;{finding.archivedReason}&quot;
              </div>
            )}
          </div>
          {showAdminActions && (
            <Btn
              size="sm"
              variant="ghost"
              onClick={async () => {
                try {
                  await onUnarchive(finding.id);
                  setToast("✓ Unarchived");
                } catch {
                  setToast("Unarchive failed");
                }
                setTimeout(() => setToast(""), 2500);
              }}
            >
              ↩ Unarchive
            </Btn>
          )}
        </div>
      )}

      {finding.status === "Reopened" && (
        <div className="detail-panel-alert detail-panel-alert-regression">
          <span style={{ fontSize: 14 }}>🔁</span>
          <div style={{ flex: 1 }}>
            <span
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 700,
                color: "var(--app-warning)",
              }}
            >
              REGRESSION — #{finding.regressionCount ?? 0}
            </span>
            <span
              style={{
                ...sans,
                fontSize: 11,
                color: "var(--app-warning)",
                marginLeft: 8,
              }}
            >
              This finding was previously resolved and has re-appeared in a
              scan.
            </span>
          </div>
        </div>
      )}

      <div className="detail-panel-header">
        <div className="detail-panel-hero">
          <div className="detail-panel-hero-content">
            <div className="detail-panel-badges">
              <TypeTag type={finding.findingType} />
              <span
                style={{
                  ...mono,
                  fontSize: 13,
                  fontWeight: 700,
                  color: "var(--app-accent)",
                }}
              >
                {finding.cveId}
              </span>
              <SevTag sev={finding.severity} />
              <StTag status={finding.status} />
              {(finding.sources?.length ?? 0) >= 1 &&
                finding.sources
                  ?.slice(0, 2)
                  .map((s, i) => (
                    <SrcTag key={i} source={s.name} sources={sources} />
                  ))}
            </div>
            <h2 className="detail-panel-title">{displayTitle(finding)}</h2>
            <div className="detail-panel-meta">
              {repoFileUrl && finding.component ? (
                <>
                  <a
                    href={repoFileUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: "var(--app-accent)",
                      textDecoration: "none",
                    }}
                  >
                    {finding.component}
                  </a>
                  {" · "}
                  {finding.image}
                </>
              ) : (
                <>
                  {finding.component ?? "—"} ·{" "}
                  {finding.image ?? finding.tag ?? "—"}
                </>
              )}
              {finding.cvss && finding.cvss !== "—"
                ? ` · CVSS ${finding.cvss}`
                : ""}
              {finding.epss && finding.epss !== "—"
                ? ` · EPSS ${finding.epss}`
                : ""}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="detail-panel-close"
          >
            ×
          </button>
        </div>
      </div>

      <nav
        role="tablist"
        aria-label="Finding detail sections"
        className="detail-panel-tabs"
      >
        {[
          { id: "details" as const, label: "Details" },
          { id: "decision" as const, label: "Decision" },
          { id: "history" as const, label: "History" },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            aria-controls={`panel-${tab.id}`}
            id={`tab-${tab.id}`}
            onClick={() => setActiveTab(tab.id)}
            className="detail-panel-tab"
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="detail-panel-body">
        {activeTab === "details" && (
          <div id="panel-details" role="tabpanel" aria-labelledby="tab-details">
            {/* Risk metrics bar — visual callouts for key metrics */}
            <div className="detail-panel-risk-bar">
              {finding.cvss && finding.cvss !== "—" && (
                <div className="detail-panel-metric-pill">
                  <span className="metric-label">CVSS</span>
                  <span className="metric-value">{finding.cvss}</span>
                </div>
              )}
              {finding.epss && finding.epss !== "—" && (
                <div className="detail-panel-metric-pill">
                  <span className="metric-label">EPSS</span>
                  <span className="metric-value">{finding.epss}</span>
                </div>
              )}
              {finding.slaDue && (
                <div
                  className={`detail-panel-metric-pill ${
                    d !== null && d < 0
                      ? "sla-urgent"
                      : d !== null && d < 7
                        ? "sla-warning"
                        : "sla-ok"
                  }`}
                >
                  <span className="metric-label">SLA</span>
                  <span className="metric-value">
                    {d !== null ? `${d}d` : "—"}
                  </span>
                </div>
              )}
              {(finding.owner?.trim() ?? "") !== "" && (
                <div className="detail-panel-metric-pill">
                  <span className="metric-label">Owner</span>
                  <span className="metric-value" style={{ fontSize: 12 }}>
                    {finding.owner}
                  </span>
                </div>
              )}
            </div>

            {/* Description first — the narrative */}
            <div className="detail-panel-section">
              <H>Description</H>
              <FindingDescription text={descriptionText} />
            </div>

            {/* Context — where and what */}
            <div className="detail-panel-section">
              <H>Finding Scope</H>
              {(() => {
                const locStr = formatFileLocation(finding);
                const locRow: [string, React.ReactNode] | null = locStr
                  ? [
                      "Location",
                      <div
                        key="loc"
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 8,
                          flexWrap: "wrap",
                        }}
                      >
                        {repoFileUrl ? (
                          <a
                            href={repoFileUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="detail-panel-kv-item value"
                            style={{ display: "inline" }}
                          >
                            {locStr}
                          </a>
                        ) : (
                          <span className="detail-panel-kv-item value">
                            {locStr}
                          </span>
                        )}
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(locStr);
                            setToast("Copied to clipboard");
                            setTimeout(() => setToast(""), 2000);
                          }}
                          style={{
                            ...mono,
                            fontSize: 10,
                            padding: "4px 8px",
                            background: "var(--app-input-bg)",
                            border: "1px solid var(--app-border)",
                            borderRadius: 4,
                            color: "var(--app-muted)",
                            cursor: "pointer",
                          }}
                        >
                          Copy
                        </button>
                      </div>,
                    ]
                  : null;

                const scopeRows: Array<[string, React.ReactNode]> = [
                  [
                    "Component",
                    repoFileUrl && finding.component ? (
                      <a
                        href={repoFileUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          color: "var(--app-accent)",
                          textDecoration: "none",
                        }}
                      >
                        {finding.component}
                      </a>
                    ) : (
                      finding.component ?? "—"
                    ),
                  ],
                  ["Asset", finding.image ?? finding.tag ?? "—"],
                  ["CVE / ID", finding.cveId],
                  ["Type", finding.findingType],
                  ...(locRow ? [locRow] : []),
                ];
                const groupKey = effectiveGroupKey(finding);
                const sameGroup =
                  groupFindings && allFindings.length > 0
                    ? allFindings.filter(
                        (f) => effectiveGroupKey(f) === groupKey,
                      )
                    : [];
                const hasSubissues = sameGroup.length > 1;
                const hasSources = (finding.sources?.length ?? 0) >= 1;
                const isInstanceView = selectedSourceIndex != null;
                const showScopeLinePreview =
                  finding.snippetMasked &&
                  !hasSubissues &&
                  (!hasSources || isInstanceView);
                const snippetRow: [string, React.ReactNode] | null =
                  showScopeLinePreview
                    ? [
                        "Line preview",
                        <pre key="snippet" className="detail-panel-snippet">
                          {finding.snippetMasked}
                        </pre>,
                      ]
                    : null;
                const allScopeRows = snippetRow
                  ? [...scopeRows, snippetRow]
                  : scopeRows;
                return (
                  <div className="detail-panel-card">
                    <div className="detail-panel-kv-grid">
                      {allScopeRows.map(([k, v]) => (
                        <div key={String(k)} className="detail-panel-kv-item">
                          <label>{k}</label>
                          <div className="value">{v}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}
            </div>

            {groupFindings &&
              selectedSourceIndex == null &&
              allFindings.length > 0 &&
              (() => {
                const groupKey = effectiveGroupKey(finding);
                const sameGroup = allFindings.filter(
                  (f) => effectiveGroupKey(f) === groupKey,
                );
                if (sameGroup.length <= 1) return null;

                /** Context label for grouping: asset/repo + branch or image + tag */
                const getContextLabel = (f: Finding): string => {
                  const img = f.image?.trim() ?? "";
                  const branch = f.branch?.trim();
                  const tag =
                    f.tag ??
                    (img.includes(":") ? img.split(":")[1] : undefined);
                  if (branch) return img ? `${img} - ${branch}` : branch;
                  if (tag) return img ? `${img}:${tag}` : tag;
                  return img || "—";
                };

                const byContext = new Map<string, Finding[]>();
                for (const f of sameGroup) {
                  const ctx = getContextLabel(f);
                  const list = byContext.get(ctx) ?? [];
                  list.push(f);
                  byContext.set(ctx, list);
                }

                const sevIndex = (f: Finding) => {
                  const i = SEV_ORDER.indexOf(
                    f.severity as (typeof SEV_ORDER)[number],
                  );
                  return i >= 0 ? i : 999;
                };
                const byContextSorted = Array.from(byContext.entries())
                  .map(
                    ([ctxLabel, list]) =>
                      [
                        ctxLabel,
                        [...list].sort((a, b) => sevIndex(a) - sevIndex(b)),
                      ] as const,
                  )
                  .sort(([, a], [, b]) => {
                    const worstA = a.reduce((w, f) =>
                      sevIndex(f) < sevIndex(w) ? f : w,
                    );
                    const worstB = b.reduce((w, f) =>
                      sevIndex(f) < sevIndex(w) ? f : w,
                    );
                    return sevIndex(worstA) - sevIndex(worstB);
                  });

                const totalSubissues = sameGroup.length;
                return (
                  <div className="detail-panel-section">
                    <H>Subissues {totalSubissues}</H>
                    <p
                      className="detail-panel-prose"
                      style={{ marginBottom: 16 }}
                    >
                      Same finding across {byContext.size} context
                      {byContext.size !== 1 ? "s" : ""}. Each instance may
                      require a separate fix.
                    </p>
                    {byContextSorted.map(([ctxLabel, list]) => (
                      <div
                        key={ctxLabel}
                        className="detail-panel-card"
                        style={{
                          marginBottom: 16,
                          overflow: "hidden",
                          padding: 0,
                        }}
                      >
                        <div
                          style={{
                            ...mono,
                            fontSize: 11,
                            fontWeight: 700,
                            color: "var(--app-fg)",
                            background: "var(--app-pane-header-bg)",
                            padding: "12px 16px",
                            borderBottom: "1px solid var(--app-border)",
                          }}
                        >
                          {ctxLabel}
                        </div>
                        <div style={{ padding: 0 }}>
                          {list.map((f) => {
                            const loc =
                              f.filePath ??
                              parseFileLocation(f)?.filePath ??
                              f.component ??
                              "—";
                            const fileUrl = getRepoFileUrl(
                              f,
                              repoBaseUrl,
                              repoUrlType,
                            );
                            const lineInfo =
                              f.line != null ? `Line ${f.line}` : null;
                            const locDisplay =
                              lineInfo && loc !== "—"
                                ? `${lineInfo} in ${loc}`
                                : lineInfo || loc;
                            return (
                              <div
                                key={f.id}
                                style={{
                                  display: "flex",
                                  flexDirection: "column",
                                  gap: 8,
                                  padding: "12px 14px",
                                  borderBottom:
                                    list.indexOf(f) < list.length - 1
                                      ? "1px solid var(--app-border-subtle)"
                                      : "none",
                                }}
                              >
                                <div style={{ flex: 1, minWidth: 0 }}>
                                  <div
                                    style={{
                                      display: "flex",
                                      gap: 8,
                                      alignItems: "center",
                                      flexWrap: "wrap",
                                    }}
                                  >
                                    <span
                                      style={{
                                        ...mono,
                                        fontSize: 11,
                                        fontWeight: 700,
                                        color: "var(--app-accent)",
                                      }}
                                    >
                                      {f.cveId}
                                    </span>
                                    <SevTag sev={f.severity} />
                                  </div>
                                  <div
                                    style={{
                                      ...mono,
                                      fontSize: 10,
                                      color: "var(--app-muted)",
                                      marginTop: 4,
                                    }}
                                  >
                                    {fileUrl && loc !== "—" ? (
                                      <a
                                        href={fileUrl}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        style={{
                                          color: "var(--app-accent)",
                                          textDecoration: "underline",
                                        }}
                                      >
                                        {locDisplay}
                                      </a>
                                    ) : (
                                      locDisplay
                                    )}
                                  </div>
                                  {f.snippetMasked && (
                                    <pre
                                      className="detail-panel-snippet"
                                      style={{ marginTop: 8 }}
                                    >
                                      {f.snippetMasked}
                                    </pre>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })()}

            {finding.findingType === "Secret" && (
              <div className="detail-panel-section">
                <div
                  className="detail-panel-card detail-panel-alert-secret"
                  style={{
                    border:
                      "1px solid color-mix(in srgb, var(--app-danger) 30%, transparent)",
                  }}
                >
                  <div className="detail-panel-alert-secret-title">
                    🔑 SECRET FINDING — SLA: 24 HOURS
                  </div>
                  <p className="detail-panel-alert-secret-body">
                    Leaked secrets require immediate credential rotation
                    regardless of whether the secret has been accessed.
                  </p>
                </div>
              </div>
            )}

            <CollapsibleSection title="Tracking & Sources" defaultOpen>
              {(finding.sources?.length ?? 0) >= 1 &&
                (() => {
                  const sourcesToShow =
                    selectedSourceIndex != null && finding.sources?.length
                      ? [finding.sources[selectedSourceIndex]].filter(Boolean)
                      : finding.sources ?? [];
                  if (sourcesToShow.length === 0) return null;
                  return (
                    <div className="detail-panel-section">
                      <H>
                        Source
                        {sourcesToShow.length > 1
                          ? ` Attribution (${sourcesToShow.length} sources)`
                          : ""}
                      </H>
                      {showAdminActions &&
                        onOverrideFingerprint &&
                        sourcesToShow.length > 1 && (
                          <div
                            style={{
                              marginTop: 8,
                              padding: "8px 10px",
                              background: "var(--app-input-bg)",
                              border: "1px solid var(--app-border)",
                              borderRadius: 4,
                            }}
                          >
                            <div
                              style={{
                                ...sans,
                                fontSize: 11,
                                color: "var(--app-muted)",
                                marginBottom: 6,
                              }}
                            >
                              Incorrectly merged? Override fingerprint to
                              prevent future dedup with this finding.
                            </div>
                            <Btn
                              size="sm"
                              variant="ghost"
                              disabled={overrideFpLoading}
                              onClick={async () => {
                                if (!onOverrideFingerprint) return;
                                setOverrideFpLoading(true);
                                try {
                                  await onOverrideFingerprint(finding.id);
                                  setToast("✓ Fingerprint overridden");
                                  setTimeout(() => setToast(""), 2500);
                                } finally {
                                  setOverrideFpLoading(false);
                                }
                              }}
                            >
                              {overrideFpLoading ? "…" : "Override fingerprint"}
                            </Btn>
                          </div>
                        )}
                      <div
                        style={{
                          display: "flex",
                          flexDirection: "column",
                          gap: 8,
                        }}
                      >
                        {sourcesToShow.map((s, i) => {
                          const sourceLink = finding.externalLinks?.find(
                            (l) =>
                              l.kind === "source" &&
                              l.adapterKey?.toLowerCase() ===
                                s.name?.toLowerCase(),
                          );
                          const sourceUrl = sourceLink?.url;
                          const displayName =
                            displaySourceName(s.name) || s.name || "";
                          const locStr =
                            formatFileLocation(finding) ??
                            finding.filePath ??
                            finding.component ??
                            "—";
                          return (
                            <div
                              key={i}
                              style={{
                                background: "var(--app-card-bg)",
                                border: "1px solid var(--app-border-subtle)",
                                borderRadius: 6,
                                padding: "12px 14px",
                              }}
                            >
                              <div
                                style={{
                                  display: "flex",
                                  flexDirection: "column",
                                  gap: 8,
                                }}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: 8,
                                    flexWrap: "wrap",
                                  }}
                                >
                                  <SrcTag source={s.name} sources={sources} />
                                  <SevTag sev={finding.severity} />
                                  <span
                                    style={{
                                      ...mono,
                                      fontSize: 9,
                                      color: "var(--app-muted)",
                                    }}
                                  >
                                    {fmtDtUtil(s.importedAt)}
                                  </span>
                                  {sourceUrl && (
                                    <a
                                      href={sourceUrl}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      style={{
                                        ...mono,
                                        fontSize: 9,
                                        color: "var(--app-accent)",
                                        textDecoration: "none",
                                      }}
                                    >
                                      View in {displayName} →
                                    </a>
                                  )}
                                </div>
                                <div
                                  style={{
                                    ...mono,
                                    fontSize: 10,
                                    color: "var(--app-muted)",
                                  }}
                                >
                                  {repoFileUrl && locStr !== "—" ? (
                                    <a
                                      href={repoFileUrl}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      style={{
                                        color: "var(--app-accent)",
                                        textDecoration: "underline",
                                      }}
                                    >
                                      {locStr}
                                    </a>
                                  ) : (
                                    locStr
                                  )}
                                </div>
                                {finding.snippetMasked && (
                                  <pre
                                    style={{
                                      ...mono,
                                      fontSize: 10,
                                      color: "var(--app-fg)",
                                      background: "var(--app-input-bg)",
                                      border:
                                        "1px solid var(--app-border-subtle)",
                                      borderRadius: 4,
                                      padding: "8px 10px",
                                      margin: 0,
                                      overflowX: "auto",
                                      whiteSpace: "pre-wrap",
                                      wordBreak: "break-all",
                                    }}
                                  >
                                    {finding.snippetMasked}
                                  </pre>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })()}

              <div className="detail-panel-section">
                <H>Tracking</H>
                <div className="detail-panel-card">
                  <div
                    className="detail-panel-kv-grid"
                    style={{ gridTemplateColumns: "repeat(3, 1fr)" }}
                  >
                    {(() => {
                      const baseRows: Array<[string, string, string | null]> = [
                        ["Owner", finding.owner ?? "—", null],
                        ["Team", finding.team ?? "—", null],
                        [
                          "SLA Due",
                          finding.slaDue
                            ? `${fmtDtUtil(finding.slaDue)} (${
                                d !== null ? `${d}d` : "—"
                              })`
                            : "—",
                          null,
                        ],
                      ];
                      const trackerRows: Array<
                        [string, string, string | null]
                      > =
                        trackerLinks.length > 0
                          ? trackerLinks.map((link) => {
                              const t =
                                allTrackers.find(
                                  (x) => x.id === link.adapterKey,
                                ) ??
                                (link.adapterKey === "linear" ||
                                !link.adapterKey
                                  ? tracker
                                  : allTrackers.find(
                                      (x) => (x.type || "linear") === "linear",
                                    )) ??
                                null;
                              const label =
                                t?.name ?? link.adapterKey ?? "Tracker";
                              const issueId = link.issueId ?? "—";
                              const href =
                                link.url ??
                                (t?.baseUrl &&
                                issueId !== "—" &&
                                !issueId.startsWith("http")
                                  ? `${String(t.baseUrl).replace(
                                      /\/$/,
                                      "",
                                    )}/${issueId}`
                                  : issueId.startsWith("http")
                                    ? issueId
                                    : null);
                              return [label, issueId, href];
                            })
                          : [
                              [
                                tName,
                                finding.trackerId ?? "—",
                                tracker?.baseUrl && finding.trackerId
                                  ? `${String(tracker.baseUrl).replace(
                                      /\/$/,
                                      "",
                                    )}/${finding.trackerId}`
                                  : null,
                              ],
                            ];
                      const tailRows: Array<[string, string, string | null]> = [
                        ["Control Ref", finding.controlRef ?? "—", null],
                        ["Imported", fmtDtUtil(finding.created), null],
                      ];
                      return [...baseRows, ...trackerRows, ...tailRows].map(
                        ([k, v, href], idx) => (
                          <div key={idx} className="detail-panel-kv-item">
                            <label>{k}</label>
                            <div
                              className="value"
                              style={{ ...mono, fontSize: 12 }}
                            >
                              {v !== "—" && href ? (
                                <a
                                  href={v.startsWith("http") ? v : href}
                                  target="_blank"
                                  rel="noreferrer"
                                  style={{
                                    color: "var(--app-accent)",
                                    textDecoration: "none",
                                  }}
                                >
                                  {tIcon} {v}
                                </a>
                              ) : (
                                v
                              )}
                            </div>
                          </div>
                        ),
                      );
                    })()}
                  </div>
                </div>
              </div>

              {showAdminActions &&
                tracker?.type === "linear" &&
                (finding.status === "Open" || finding.status === "Reopened") &&
                !finding.trackerId && (
                  <div style={{ marginTop: 10, marginBottom: 10 }}>
                    <button
                      type="button"
                      onClick={async () => {
                        setSyncToTrackerLoading(true);
                        setSyncToTrackerMessage(null);
                        try {
                          const res = await syncFindingToTracker(finding.id, {
                            token,
                          });
                          setSyncToTrackerMessage(
                            res.enqueued ? res.message : res.message,
                          );
                          if (res.enqueued)
                            onUpdate({
                              ...finding,
                              syncStatus: "pending_sync",
                            });
                        } catch (e) {
                          setSyncToTrackerMessage(
                            e instanceof Error ? e.message : "Sync failed",
                          );
                        } finally {
                          setSyncToTrackerLoading(false);
                        }
                      }}
                      disabled={syncToTrackerLoading}
                      style={{
                        ...mono,
                        padding: "6px 12px",
                        background: syncToTrackerLoading
                          ? "var(--app-border)"
                          : "var(--app-accent)",
                        border: "none",
                        borderRadius: 4,
                        color: "var(--app-fg)",
                        cursor: syncToTrackerLoading
                          ? "not-allowed"
                          : "pointer",
                        fontSize: 10,
                        fontWeight: 600,
                        opacity: syncToTrackerLoading ? 0.7 : 1,
                      }}
                    >
                      {syncToTrackerLoading ? "Syncing…" : "Sync to Linear"}
                    </button>
                    {syncToTrackerMessage && (
                      <span
                        style={{
                          ...sans,
                          fontSize: 11,
                          marginLeft: 10,
                          color: syncToTrackerMessage
                            .toLowerCase()
                            .includes("enqueued")
                            ? "var(--app-success)"
                            : syncToTrackerMessage
                                  .toLowerCase()
                                  .includes("not configured") ||
                                syncToTrackerMessage
                                  .toLowerCase()
                                  .includes("not found")
                              ? "var(--app-danger)"
                              : "var(--app-muted)",
                        }}
                      >
                        {syncToTrackerMessage}
                      </span>
                    )}
                  </div>
                )}
            </CollapsibleSection>

            {(finding.regressionCount ?? 0) > 0 && (
              <div className="detail-panel-section">
                <H>Regression History ({finding.regressionCount}x)</H>
                <div
                  className="detail-panel-card"
                  style={{
                    background:
                      "color-mix(in srgb, var(--app-warning) 10%, transparent)",
                    border:
                      "1px solid color-mix(in srgb, var(--app-warning) 25%, transparent)",
                  }}
                >
                  {priorFindings.map((p) => (
                    <div
                      key={p.id}
                      style={{
                        ...mono,
                        fontSize: 10,
                        color: "var(--app-muted)",
                        marginBottom:
                          priorFindings.indexOf(p) < priorFindings.length - 1
                            ? 6
                            : 0,
                      }}
                    >
                      <span
                        style={{ color: "var(--app-accent)", fontWeight: 600 }}
                      >
                        {p.cveId}
                      </span>
                      {p.component ? ` · ${p.component}` : ""} — {p.id}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {(finding.justification || finding.compensatingControls) &&
              !canAct && (
                <div className="detail-panel-section">
                  <H>Resolution</H>
                  <div className="detail-panel-card">
                    {finding.justification && (
                      <>
                        <div
                          style={{
                            ...mono,
                            fontSize: 9,
                            color: "var(--app-muted)",
                            textTransform: "uppercase",
                            marginBottom: 4,
                          }}
                        >
                          Justification
                          {finding.trackerComment ? " (from tracker)" : ""}
                        </div>
                        <p
                          style={{
                            ...sans,
                            fontSize: 12,
                            color: "var(--app-muted)",
                            margin: 0,
                            lineHeight: 1.65,
                          }}
                        >
                          {finding.justification}
                        </p>
                      </>
                    )}
                    {finding.compensatingControls && (
                      <div
                        style={{
                          marginTop: 10,
                          paddingTop: 10,
                          borderTop: "1px solid var(--app-border-subtle)",
                        }}
                      >
                        <div
                          style={{
                            ...mono,
                            fontSize: 9,
                            color: "var(--app-muted)",
                            textTransform: "uppercase",
                            marginBottom: 4,
                          }}
                        >
                          Compensating Controls
                        </div>
                        <p
                          style={{
                            ...sans,
                            fontSize: 12,
                            color: "var(--app-muted)",
                            margin: 0,
                          }}
                        >
                          {finding.compensatingControls}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}

            {finding.attestation && (
              <div className="detail-panel-section">
                <H>Attestation / Sign-off</H>
                <div
                  className="detail-panel-card"
                  style={{
                    background:
                      "color-mix(in srgb, var(--app-accent) 8%, transparent)",
                    border:
                      "1px solid color-mix(in srgb, var(--app-accent) 30%, transparent)",
                  }}
                >
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: 10,
                    }}
                  >
                    {[
                      ["Approver", finding.attestation.approver ?? "—"],
                      ["Title", finding.attestation.approverTitle ?? "—"],
                      [
                        "Approved At",
                        fmtDtUtil(finding.attestation.approvedAt),
                      ],
                      ["Waiver Ref", finding.attestation.waiverRef ?? "—"],
                      ["Expires", fmtDtUtil(finding.attestation.expiresAt)],
                      [
                        "Days Remaining",
                        (() => {
                          const exp = finding.attestation.expiresAt;
                          if (!exp) return "—";
                          const d = daysLeft(exp);
                          if (d === null) return "—";
                          if (d < 0) return `Expired (${Math.abs(d)}d ago)`;
                          return `${d}d`;
                        })(),
                      ],
                    ].map(([k, v]) => (
                      <div key={String(k)}>
                        <div
                          style={{
                            ...mono,
                            fontSize: 9,
                            color: "var(--app-muted)",
                            textTransform: "uppercase",
                            marginBottom: 2,
                          }}
                        >
                          {k}
                        </div>
                        <div
                          style={{
                            ...mono,
                            fontSize: 11,
                            color: "var(--app-accent)",
                          }}
                        >
                          {v}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === "decision" && (
          <div
            id="panel-decision"
            role="tabpanel"
            aria-labelledby="tab-decision"
          >
            {/* Status card — current state at a glance */}
            <div className="detail-panel-status-card">
              <div className="detail-panel-status-card-main">
                <div className="status-label">Current Status</div>
                <StTag status={finding.status} />
              </div>
              {canAct && (
                <p className="detail-panel-status-card-hint">
                  Choose an action below to classify
                </p>
              )}
            </div>

            <div className="detail-panel-section">
              <H>Reviewer Notes</H>
              {readOnly ? (
                <div className="detail-panel-card">
                  <p
                    style={{
                      ...sans,
                      fontSize: 12,
                      color: "var(--app-muted)",
                      margin: 0,
                      lineHeight: 1.65,
                    }}
                  >
                    {finding.reviewerNote || "—"}
                  </p>
                </div>
              ) : (
                <div className="detail-panel-reviewer-notes">
                  <Field
                    label={undefined}
                    value={rvNote}
                    onChange={setRvNote}
                    rows={2}
                    placeholder="Document approval rationale, conditions, or reason for rejection."
                  />
                  <div className="detail-panel-save-notes-btn-wrap">
                    <Btn
                      size="sm"
                      variant="secondary"
                      disabled={
                        savingNotes || rvNote === (finding.reviewerNote ?? "")
                      }
                      onClick={doSaveNotes}
                    >
                      {savingNotes ? "…" : "Save"}
                    </Btn>
                  </div>
                </div>
              )}
            </div>

            {canEdit && canAct && (
              <>
                <div className="detail-panel-form-card">
                  <div className="detail-panel-form-card-title">
                    Justification & Controls
                  </div>
                  <Field
                    label="Justification"
                    value={jus}
                    onChange={setJus}
                    rows={2}
                    placeholder="Engineer rationale or reviewer-provided justification for this decision."
                  />
                  <div style={{ marginTop: 12 }}>
                    <Field
                      label="Compensating Controls"
                      value={comp}
                      onChange={setComp}
                      rows={2}
                      placeholder="Optional compensating controls or mitigations."
                    />
                  </div>
                </div>

                <div className="detail-panel-form-card">
                  <div className="detail-panel-form-card-title">
                    Risk Acceptance Attestation
                  </div>
                  <div className="detail-panel-form-grid detail-panel-form-grid-first">
                    <Field
                      label="Approver Name *"
                      value={attApprover}
                      onChange={setAttApprover}
                      placeholder="Jane Smith"
                      disabled={!canAct}
                    />
                    <Field
                      label="Approver Title"
                      value={attTitle}
                      onChange={setAttTitle}
                      placeholder="CISO / Security Lead"
                      disabled={!canAct}
                    />
                  </div>
                  <div className="detail-panel-form-grid">
                    <Field
                      label="Waiver Reference"
                      value={attRef}
                      onChange={setAttRef}
                      placeholder="WAV-2024-001"
                      disabled={!canAct}
                    />
                    <Field
                      label="Expiry Date"
                      value={attExpiry}
                      onChange={setAttExpiry}
                      type="date"
                      disabled={!canAct}
                    />
                  </div>
                </div>

                <div className="detail-panel-form-card">
                  <div className="detail-panel-form-card-title">
                    Suppression Type
                  </div>
                  <div className="detail-panel-suppression-options">
                    {[
                      {
                        val: "global" as const,
                        label: "🌐 False Positive",
                        desc: "Scanner is wrong. Suppress everywhere.",
                      },
                      {
                        val: "contextual" as const,
                        label: "📍 Contextual",
                        desc: "Real vuln, not exploitable here.",
                      },
                    ].map((opt) => (
                      <div
                        key={opt.val}
                        role="button"
                        tabIndex={canAct ? 0 : -1}
                        onClick={() => canAct && setSuppScope(opt.val)}
                        onKeyDown={(e) =>
                          canAct &&
                          (e.key === "Enter" || e.key === " ") &&
                          setSuppScope(opt.val)
                        }
                        className={`detail-panel-suppression-option ${
                          suppScope === opt.val ? "selected" : ""
                        }`}
                        style={{
                          cursor: canAct ? "pointer" : "not-allowed",
                          opacity: canAct ? 1 : 0.6,
                        }}
                      >
                        <div className="detail-panel-suppression-option-label">
                          {opt.label}
                        </div>
                        <div className="detail-panel-suppression-option-desc">
                          {opt.desc}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="detail-panel-action-group">
                  <div className="detail-panel-action-group-title">
                    Primary Actions
                  </div>
                  <div className="detail-panel-action-row">
                    <Btn
                      variant="approve"
                      onClick={() => doUpdate("Approved")}
                      disabled={saving || !canAct}
                    >
                      ✓ Approve
                    </Btn>
                    <Btn
                      variant="reject"
                      onClick={() => doUpdate("Rejected")}
                      disabled={saving || !canAct}
                    >
                      ✗ Reject
                    </Btn>
                    <Btn
                      variant="purple"
                      onClick={doRiskAccept}
                      disabled={saving || !canAct || !attApprover.trim()}
                    >
                      ⚠ Accept Risk
                    </Btn>
                  </div>
                </div>
                <div className="detail-panel-action-group">
                  <div className="detail-panel-action-group-title">
                    Resolve & Defer
                  </div>
                  <div className="detail-panel-action-row">
                    <Btn
                      variant="secondary"
                      onClick={doFP}
                      disabled={saving || !canAct}
                    >
                      🌐 False Positive
                    </Btn>
                    <Btn
                      variant="secondary"
                      onClick={doSuppress}
                      disabled={saving || !canAct}
                    >
                      📍 Suppress
                    </Btn>
                    <Btn
                      variant="secondary"
                      onClick={() => doUpdate("Not Applicable")}
                      disabled={saving || !canAct}
                    >
                      ⊘ Not Applicable
                    </Btn>
                    <Btn
                      variant="secondary"
                      onClick={() => doUpdate("Duplicate")}
                      disabled={saving || !canAct}
                    >
                      ⧉ Duplicate
                    </Btn>
                    <Btn
                      variant="secondary"
                      onClick={() => doUpdate("Resolved")}
                      disabled={saving || !canAct}
                    >
                      ✓ Resolved
                    </Btn>
                    <Btn
                      variant="secondary"
                      onClick={() => doUpdate("Mitigated")}
                      disabled={saving || !canAct}
                    >
                      ◐ Mitigated
                    </Btn>
                  </div>
                </div>
              </>
            )}

            {showAdminActions &&
              finding.previousStatus &&
              finding.status !== "Open" && (
                <>
                  <H>Revert</H>
                  {!showRevert ? (
                    <div
                      style={{ display: "flex", alignItems: "center", gap: 10 }}
                    >
                      <Btn
                        size="sm"
                        variant="ghost"
                        onClick={() => setShowRevert(true)}
                      >
                        ↩ Revert to &quot;{finding.previousStatus}&quot;
                      </Btn>
                      <span
                        style={{
                          ...sans,
                          fontSize: 11,
                          color: "var(--app-muted)",
                        }}
                      >
                        Undo the last status change. Reason required.
                      </span>
                    </div>
                  ) : (
                    <div
                      style={{
                        background: "var(--app-card-bg)",
                        border:
                          "1px solid color-mix(in srgb, var(--app-warning) 25%, transparent)",
                        borderRadius: 5,
                        padding: 14,
                      }}
                    >
                      <div
                        style={{
                          ...sans,
                          fontSize: 12,
                          color: "var(--app-warning)",
                          marginBottom: 10,
                        }}
                      >
                        Revert <StTag status={finding.status} /> →{" "}
                        <StTag status={finding.previousStatus} />
                      </div>
                      <Field
                        label="Reason *"
                        value={revertReason}
                        onChange={setRevertReason}
                        rows={2}
                        placeholder="Why is this being reverted?"
                      />
                      <div style={{ display: "flex", gap: 7, marginTop: 10 }}>
                        <Btn
                          variant="warn"
                          disabled={!revertReason.trim() || saving}
                          onClick={async () => {
                            setSaving(true);
                            try {
                              await onRevert(finding.id, revertReason);
                              setShowRevert(false);
                              setRevertReason("");
                              setToast("↩ Reverted");
                            } catch {
                              setToast("Revert failed");
                            } finally {
                              setSaving(false);
                              setTimeout(() => setToast(""), 2500);
                            }
                          }}
                        >
                          ↩ Confirm Revert
                        </Btn>
                        <Btn
                          variant="ghost"
                          onClick={() => {
                            setShowRevert(false);
                            setRevertReason("");
                          }}
                        >
                          Cancel
                        </Btn>
                      </div>
                    </div>
                  )}
                </>
              )}

            {showAdminActions && !finding.archived ? (
              <>
                <H>Archive Finding</H>
                {!showArchiveForm ? (
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 10 }}
                  >
                    <Btn
                      size="sm"
                      variant="secondary"
                      onClick={() => setShowArchiveForm(true)}
                    >
                      🗄 Archive
                    </Btn>
                    <span className="detail-panel-archive-hint">
                      Never deleted — permanently retained, hidden from active
                      list.
                    </span>
                  </div>
                ) : (
                  <div
                    style={{
                      background: "var(--app-card-bg)",
                      border:
                        "1px solid color-mix(in srgb, var(--app-accent) 30%, transparent)",
                      borderRadius: 5,
                      padding: 14,
                    }}
                  >
                    <Field
                      label="Reason *"
                      value={archiveReason}
                      onChange={setArchiveReason}
                      rows={2}
                      placeholder="e.g. Image decommissioned."
                    />
                    <div style={{ display: "flex", gap: 7, marginTop: 10 }}>
                      <Btn
                        variant="warn"
                        disabled={!archiveReason.trim() || saving}
                        onClick={async () => {
                          setSaving(true);
                          try {
                            await onArchive(finding.id, archiveReason);
                            setShowArchiveForm(false);
                            setArchiveReason("");
                            setToast("✓ Archived");
                          } catch {
                            setToast("Archive failed");
                          } finally {
                            setSaving(false);
                            setTimeout(() => setToast(""), 2500);
                          }
                        }}
                      >
                        🗄 Confirm Archive
                      </Btn>
                      <Btn
                        variant="ghost"
                        onClick={() => {
                          setShowArchiveForm(false);
                          setArchiveReason("");
                        }}
                      >
                        Cancel
                      </Btn>
                    </div>
                  </div>
                )}
              </>
            ) : finding.archived ? (
              <>
                <H>Archived</H>
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <span
                    style={{
                      ...sans,
                      fontSize: 12,
                      color: "var(--app-accent)",
                    }}
                  >
                    Archived — permanently retained.
                  </span>
                  {showAdminActions && (
                    <Btn
                      size="sm"
                      variant="ghost"
                      onClick={async () => {
                        try {
                          await onUnarchive(finding.id);
                          setToast("✓ Unarchived");
                        } catch {
                          setToast("Unarchive failed");
                        }
                        setTimeout(() => setToast(""), 2500);
                      }}
                    >
                      ↩ Unarchive
                    </Btn>
                  )}
                </div>
              </>
            ) : null}
          </div>
        )}

        {activeTab === "history" && (
          <div id="panel-history" role="tabpanel" aria-labelledby="tab-history">
            <div className="detail-panel-section">
              <H>Audit Trail</H>
              <p className="detail-panel-prose" style={{ marginBottom: 16 }}>
                Chronological record of all changes to this finding.
              </p>
              <div className="detail-panel-card">
                {[...(finding.audit ?? [])].reverse().map((e, i) => {
                  const isStatusChange = /Status\s*→|status\s*→/i.test(
                    e.action,
                  );
                  return (
                    <div
                      key={i}
                      className={`detail-panel-timeline-item${
                        isStatusChange ? " status-change" : ""
                      }`}
                    >
                      <div className="detail-panel-timeline-marker" />
                      <div className="detail-panel-timeline-content">
                        <div className="timeline-meta">
                          <span
                            style={{
                              color: "var(--app-accent)",
                              fontWeight: 600,
                            }}
                          >
                            {e.user}
                          </span>
                          <span style={{ margin: "0 6px" }}>·</span>
                          {fmtDtUtil(e.ts)}
                        </div>
                        <div
                          className="timeline-action"
                          style={{ ...sans, fontSize: 13 }}
                        >
                          {e.action}
                        </div>
                        {e.note && (
                          <div
                            style={{
                              ...sans,
                              fontSize: 12,
                              color: "var(--app-muted)",
                              fontStyle: "italic",
                              marginTop: 6,
                            }}
                          >
                            &quot;{e.note}&quot;
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {toast && <div className="detail-panel-toast">{toast}</div>}
      </div>
    </div>
  );
}
