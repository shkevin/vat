"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { mono, sans } from "@/lib/styles";
import { FlowCanvas } from "./FlowCanvas";
import { fetchIntegrationSchemas, fetchParsers, type IntegrationSchemas } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { AikidoSettingsPage } from "./AikidoSettingsPage";
import { LinearSettingsPage } from "./LinearSettingsPage";
import { PushSourcesSettings } from "./PushSourcesSettings";
import { VATBackendSettingsPage } from "./VATBackendSettingsPage";
import { DEFAULT_ISSUE_TEMPLATE, PARSER_COLORS, SOURCE_TYPES, TRACKER_TYPES } from "@/lib/constants";
import { displaySourceName } from "@/lib/utils";
import { AVAILABLE_SOURCE_TYPES } from "./nodes";
import type { Source } from "@/types";
import type { Tracker } from "@/types";
import type { WatchedLabel } from "@/types";

type SelectedNode =
  | { type: "source"; source: Source }
  | { type: "add-source"; picker?: string }
  | { type: "vat" }
  | { type: "tracker" }
  | { type: "add-tracker"; picker?: string }
  | null;

interface IntegrationCanvasProps {
  sources: Source[];
  tracker: Tracker;
  labels: WatchedLabel[];
  onSourcesChange?: (sources: Source[]) => void;
  onTrackerChange?: (tracker: Tracker) => void;
  onLabelsChange?: (labels: WatchedLabel[]) => void;
}

/** n8n-style integration canvas: overview is source of truth, settings pane on node click */
export function IntegrationCanvas({ sources, tracker, labels, onSourcesChange, onTrackerChange, onLabelsChange }: IntegrationCanvasProps) {
  const [selected, setSelected] = useState<SelectedNode>(null);
  const { token, user } = useAuth();
  const [integrationSchemas, setIntegrationSchemas] = useState<IntegrationSchemas | null>(null);

  useEffect(() => {
    const auth = { token: token ?? undefined, userEmail: user?.email ?? undefined };
    fetchIntegrationSchemas(auth)
      .then(setIntegrationSchemas)
      .catch(() => setIntegrationSchemas(null));
  }, [token, user?.email]);

  const sourceTypes = Object.entries(SOURCE_TYPES);
  const trackerTypes = Object.entries(TRACKER_TYPES);

  return (
    <div
      style={{
        display: "flex",
        gap: 0,
        height: "100%",
        minHeight: 0,
        position: "relative",
      }}
    >
      {/* Canvas — left side */}
      <div
        style={{
          flex: selected ? "0 1 1" : 1,
          minWidth: selected ? 400 : 0,
          minHeight: 0,
          transition: "flex 0.25s ease, min-width 0.25s ease",
        }}
      >
        <FlowCanvas
          sources={sources}
          tracker={tracker}
          integrationSchemas={integrationSchemas}
          onSourceClick={(source) => source && setSelected({ type: "source", source })}
          onTrackerClick={() => tracker?.name && setSelected({ type: "tracker" })}
          onAddSourceClick={() => setSelected({ type: "add-source" })}
          onAddTrackerClick={() => setSelected({ type: "add-tracker" })}
          onVatClick={() => setSelected({ type: "vat" })}
          onPaneClick={() => setSelected(null)}
          selectedSourceId={selected?.type === "source" ? (selected as { source: Source }).source.id : null}
          selectedTracker={selected?.type === "tracker"}
          selectedAddSource={selected?.type === "add-source"}
          selectedAddTracker={selected?.type === "add-tracker"}
          selectedVat={selected?.type === "vat"}
        />
      </div>

      {/* Settings pane — n8n-style: slides in from right on node click */}
      {selected && (
        <div
          className="vat-settings-pane-wrapper"
          style={{
            flexShrink: 0,
            alignSelf: "stretch",
            marginLeft: 16,
            animation: "vat-pane-slide-in 0.22s cubic-bezier(0.16, 1, 0.3, 1)",
          }}
        >
          <style>{`
            @keyframes vat-pane-slide-in {
              from { opacity: 0; transform: translateX(24px); }
              to { opacity: 1; transform: translateX(0); }
            }
          `}</style>
          <SettingsPane
            selected={selected}
            sources={sources}
            tracker={tracker}
            labels={labels}
            sourceTypes={sourceTypes}
            trackerTypes={trackerTypes}
            onClose={() => setSelected(null)}
            onSelectSourceType={(type) => setSelected({ type: "add-source", picker: type })}
            onSelectTrackerType={(type) => setSelected({ type: "add-tracker", picker: type })}
            onSourceAdded={(source) => setSelected({ type: "source", source })}
            onSourceRemoved={() => setSelected(null)}
            onTrackerAdded={() => setSelected({ type: "tracker" })}
            onTrackerRemoved={() => setSelected(null)}
            onSourcesChange={onSourcesChange}
            onTrackerChange={onTrackerChange}
            onLabelsChange={onLabelsChange}
          />
        </div>
      )}
    </div>
  );
}

function SettingsPane({
  selected,
  sources,
  tracker,
  labels,
  sourceTypes,
  trackerTypes,
  onClose,
  onSelectSourceType,
  onSelectTrackerType,
  onSourceAdded,
  onSourceRemoved,
  onTrackerAdded,
  onTrackerRemoved,
  onSourcesChange,
  onTrackerChange,
  onLabelsChange,
}: {
  selected: SelectedNode;
  sources: Source[];
  tracker: Tracker;
  labels: WatchedLabel[];
  sourceTypes: [string, (typeof SOURCE_TYPES)[string]][];
  trackerTypes: [string, (typeof TRACKER_TYPES)[string]][];
  onClose: () => void;
  onSelectSourceType: (type: string) => void;
  onSelectTrackerType: (type: string) => void;
  onSourceAdded?: (source: Source) => void;
  onSourceRemoved?: () => void;
  onTrackerAdded?: () => void;
  onTrackerRemoved?: () => void;
  onSourcesChange?: (sources: Source[]) => void;
  onTrackerChange?: (tracker: Tracker) => void;
  onLabelsChange?: (labels: WatchedLabel[]) => void;
}) {
  const width = 400;
  const title =
    selected?.type === "source"
      ? (displaySourceName((selected as { source: Source }).source.name) || displaySourceName((selected as { source: Source }).source.id) || "Source")
      : selected?.type === "add-source"
        ? "Add Source"
        : selected?.type === "vat"
          ? "VAT Backend"
          : selected?.type === "tracker"
            ? tracker?.name ?? "Tracker"
            : selected?.type === "add-tracker"
              ? "Add Tracker"
              : "Settings";

  return (
    <div
      style={{
        width,
        height: "100%",
        minHeight: 0,
        background: "var(--app-node-bg)",
        border: "1px solid var(--app-border)",
        borderRadius: 10,
        overflow: "hidden",
        display: "flex",
        flexDirection: "column",
        boxShadow: "0 4px 24px rgba(0,0,0,0.25), 0 0 0 1px var(--app-border-subtle)",
      }}
    >
      {/* n8n-style header: node name + close */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "16px 20px",
          gap: 12,
          borderBottom: "1px solid var(--app-border)",
          background: "var(--app-pane-header-bg)",
        }}
      >
        <span
          style={{
            ...sans,
            fontSize: 14,
            fontWeight: 600,
            color: "var(--app-fg)",
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {title}
        </span>
        <button
          onClick={onClose}
          aria-label="Close settings"
          style={{
            flexShrink: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: 28,
            height: 28,
            background: "transparent",
            border: "1px solid transparent",
            borderRadius: 6,
            color: "var(--app-muted)",
            cursor: "pointer",
            fontSize: 18,
            lineHeight: 1,
            transition: "background 0.15s, color 0.15s, border-color 0.15s",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "var(--app-card-bg)";
            e.currentTarget.style.color = "var(--app-fg)";
            e.currentTarget.style.borderColor = "var(--app-border)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "var(--app-muted)";
            e.currentTarget.style.borderColor = "transparent";
          }}
        >
          ×
        </button>
      </div>

      <div
        style={{
          flex: 1,
          overflowY: "auto",
          overflowX: "hidden",
          padding: 20,
          minHeight: 0,
          overscrollBehavior: "contain",
        }}
      >
        {selected?.type === "source" && (
          <SourceSettingsContent
            source={(selected as { source: Source }).source}
            sources={sources}
            sourceTypes={sourceTypes}
            tracker={tracker}
            onTrackerChange={onTrackerChange}
            onSourcesChange={onSourcesChange}
            onSourceRemoved={onSourceRemoved}
          />
        )}

        {selected?.type === "add-source" && (
          <AddSourceContent
            picker={(selected as { picker?: string }).picker}
            sources={sources}
            sourceTypes={sourceTypes}
            onSelect={onSelectSourceType}
            onSourcesChange={onSourcesChange}
            onSourceAdded={onSourceAdded}
          />
        )}

        {selected?.type === "vat" && <VATBackendSettingsPage />}

        {selected?.type === "tracker" && (
          <LinearSettingsPage
            tracker={tracker}
            labels={labels}
            onTrackerChange={onTrackerChange}
            onLabelsChange={onLabelsChange}
            onRemoveTracker={onTrackerRemoved}
          />
        )}

        {selected?.type === "add-tracker" && (
          <AddTrackerContent
            picker={(selected as { picker?: string }).picker}
            tracker={tracker}
            labels={labels}
            trackerTypes={trackerTypes}
            onSelect={onSelectTrackerType}
            onTrackerChange={onTrackerChange}
            onTrackerAdded={onTrackerAdded}
            onLabelsChange={onLabelsChange}
          />
        )}
      </div>
    </div>
  );
}

const SOURCE_TYPE_OPTS = ["scanner", "compliance", "pentest", "manual"] as const;

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "") || "manual";
}

function AddSourceForm({
  defaultSource,
  sources,
  onSourcesChange,
  onAdded,
}: {
  defaultSource: Source;
  sources: Source[];
  onSourcesChange: (sources: Source[]) => void;
  onAdded: (source: Source) => void;
}) {
  const [edit, setEdit] = useState<Source>({ ...defaultSource });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const handleAdd = useCallback(async () => {
    if (!edit.name?.trim() || !onSourcesChange || !onAdded) return;
    setSaving(true);
    setSaveError(null);
    try {
      const id =
        edit.adapter === "manual" && edit.id
          ? edit.id.trim() || slugify(edit.name)
          : "s-" + Math.random().toString(36).slice(2, 7);
      const newSource: Source = { ...edit, id };
      const next = [...sources, newSource];
      await onSourcesChange(next);
      onAdded(newSource);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to add source");
    } finally {
      setSaving(false);
    }
  }, [edit, sources, onSourcesChange, onAdded]);

  return (
    <div
      style={{
        background: "var(--app-card-bg)",
        border: "1px solid var(--app-border)",
        borderRadius: 8,
        padding: 16,
        marginBottom: 20,
      }}
    >
      <div style={{ ...mono, fontSize: 9, fontWeight: 700, letterSpacing: "0.1em", color: "var(--app-muted)", textTransform: "uppercase", marginBottom: 12 }}>
        Add source
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 80px", gap: 12 }}>
          <Field label="Name" value={edit.name} onChange={(v) => setEdit((p) => ({ ...p, name: v }))} />
          <div>
            <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Color</label>
            <input
              type="color"
              value={edit.color}
              onChange={(e) => setEdit((p) => ({ ...p, color: e.target.value }))}
              style={{ width: "100%", height: 36, background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, cursor: "pointer", padding: 2 }}
            />
          </div>
        </div>
        {edit.adapter === "manual" && (
          <>
            <ParserSelect
              value={edit.parser}
              onChange={(v) =>
                setEdit((p) => ({ ...p, parser: v, color: PARSER_COLORS[v] ?? p.color }))
              }
            />
            <Field
              label="Source ID (for API key)"
              value={edit.id}
              onChange={(v) => setEdit((p) => ({ ...p, id: v || slugify(p.name) }))}
              placeholder={slugify(edit.name) || "e.g. trivy-ci"}
            />
            <div>
              <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Asset type</label>
              <select
                value={edit.assetType ?? "auto"}
                onChange={(e) => setEdit((p) => ({ ...p, assetType: e.target.value as "auto" | "package" | "container" | "repo" }))}
                style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
              >
                <option value="auto">Auto (infer from findings)</option>
                <option value="package">Package (folder, bundle)</option>
                <option value="container">Container</option>
                <option value="repo">Repo</option>
              </select>
            </div>
          </>
        )}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Type</label>
            <select
              value={edit.type}
              onChange={(e) => setEdit((p) => ({ ...p, type: e.target.value }))}
              style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
            >
              {SOURCE_TYPE_OPTS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <ReadOnlyField label="Adapter" value={edit.adapter} />
        </div>
        <Field label="Description" value={edit.description} onChange={(v) => setEdit((p) => ({ ...p, description: v }))} placeholder="Optional" />
        {saveError && <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>{saveError}</div>}
        <button
          onClick={handleAdd}
          disabled={!edit.name?.trim() || saving}
          style={{
            ...mono,
            padding: "8px 16px",
            background: edit.name?.trim() && !saving ? "var(--app-accent)" : "var(--app-border)",
            border: "none",
            borderRadius: 6,
            color: "var(--app-fg)",
            cursor: edit.name?.trim() && !saving ? "pointer" : "not-allowed",
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          {saving ? "Adding…" : "+ Add Source"}
        </button>
      </div>
    </div>
  );
}

function SourceConfigForm({
  source,
  sources,
  onSourcesChange,
  onSourceRemoved,
}: {
  source: Source;
  sources: Source[];
  onSourcesChange?: (sources: Source[]) => void;
  onSourceRemoved?: () => void;
}) {
  const [edit, setEdit] = useState({ ...source });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const prevSourceIdRef = useRef(source.id);
  useEffect(() => {
    if (prevSourceIdRef.current !== source.id) {
      prevSourceIdRef.current = source.id;
      setEdit({ ...source });
    }
  }, [source]);

  const handleSave = useCallback(async () => {
    if (!onSourcesChange) return;
    setSaving(true);
    setSaveError(null);
    try {
      const next = sources.map((s) => (s.id === source.id ? { ...s, ...edit } : s));
      await onSourcesChange(next);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }, [edit, source.id, sources, onSourcesChange]);

  const handleRemove = useCallback(async () => {
    if (!onSourcesChange || !confirm(`Remove "${displaySourceName(source.name) || displaySourceName(source.id) || "source"}" from sources?`)) return;
    setSaving(true);
    setSaveError(null);
    try {
      const next = sources.filter((s) => s.id !== source.id);
      await onSourcesChange(next);
      onSourceRemoved?.();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to remove");
    } finally {
      setSaving(false);
    }
  }, [source.id, source.name, sources, onSourcesChange, onSourceRemoved]);

  if (!onSourcesChange) return null;

  return (
    <div
      style={{
        background: "var(--app-card-bg)",
        border: "1px solid var(--app-border)",
        borderRadius: 8,
        padding: 16,
        marginBottom: 20,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ ...mono, fontSize: 9, fontWeight: 700, letterSpacing: "0.1em", color: "var(--app-muted)", textTransform: "uppercase" }}>
          Source config
        </div>
        <button
          onClick={handleRemove}
          disabled={saving}
          style={{
            ...mono,
            padding: "6px 12px",
            background: "transparent",
            border: "1px solid var(--app-danger)",
            borderRadius: 4,
            color: "var(--app-danger)",
            cursor: saving ? "not-allowed" : "pointer",
            fontSize: 10,
          }}
        >
          Remove
        </button>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 80px", gap: 12 }}>
          <Field label="Name" value={edit.name} onChange={(v) => setEdit((p) => ({ ...p, name: v }))} />
          <div>
            <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Color</label>
            <input
              type="color"
              value={edit.color}
              onChange={(e) => setEdit((p) => ({ ...p, color: e.target.value }))}
              style={{ width: "100%", height: 36, background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, cursor: "pointer", padding: 2 }}
            />
          </div>
        </div>
        {edit.adapter === "manual" && (
          <>
            <ParserSelect
              value={edit.parser}
              onChange={(v) =>
                setEdit((p) => ({ ...p, parser: v, color: PARSER_COLORS[v] ?? p.color }))
              }
            />
            <Field
              label="Source ID (for API key)"
              value={edit.id}
              onChange={(v) => setEdit((p) => ({ ...p, id: v || slugify(p.name) }))}
              placeholder={slugify(edit.name) || "e.g. trivy-ci"}
            />
            <div>
              <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Asset type</label>
              <select
                value={edit.assetType ?? "auto"}
                onChange={(e) => setEdit((p) => ({ ...p, assetType: e.target.value as "auto" | "package" | "container" | "repo" }))}
                style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
              >
                <option value="auto">Auto (infer from findings)</option>
                <option value="package">Package (folder, bundle)</option>
                <option value="container">Container</option>
                <option value="repo">Repo</option>
              </select>
            </div>
          </>
        )}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>Type</label>
            <select
              value={edit.type}
              onChange={(e) => setEdit((p) => ({ ...p, type: e.target.value }))}
              style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
            >
              {SOURCE_TYPE_OPTS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <ReadOnlyField label="Adapter" value={edit.adapter} />
        </div>
        <Field label="Description" value={edit.description} onChange={(v) => setEdit((p) => ({ ...p, description: v }))} placeholder="Optional" />
        {saveError && <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>{saveError}</div>}
        <button
          onClick={handleSave}
          disabled={!edit.name?.trim() || saving}
          style={{
            ...mono,
            padding: "8px 16px",
            background: edit.name?.trim() && !saving ? "var(--app-accent)" : "var(--app-border)",
            border: "none",
            borderRadius: 6,
            color: "var(--app-fg)",
            cursor: edit.name?.trim() && !saving ? "pointer" : "not-allowed",
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div>
      <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{ ...mono, width: "100%", background: "var(--app-bg)", border: "1px solid var(--app-border)", borderRadius: 6, padding: "8px 12px", color: "var(--app-fg)", fontSize: 12 }}
      />
    </div>
  );
}

const PARSER_DESCRIPTIONS: Record<string, string> = {
  trivy: "Container, filesystem, SBOM — vulns, secrets, licenses, misconfig",
  snyk: "Dependency and container vulnerabilities (snyk test --json)",
  semgrep: "SAST — semgrep scan --json",
  gitleaks: "Secrets detection in repos",
  sarif: "SARIF 2.1.0 — any tool that outputs SARIF",
  canonical: "Direct VAT format pass-through { findings: [...] }",
  npm_audit: "npm audit --json (Node.js dependencies)",
  pip_audit: "pip-audit --format json (Python dependencies)",
  grype: "grype -o json (container, filesystem, SBOM)",
  cyclonedx: "CycloneDX SBOM with vulnerabilities (Trivy, Syft, etc.)",
};

const DEFAULT_PARSERS = [
  { id: "trivy", name: "trivy", label: "Trivy", description: PARSER_DESCRIPTIONS.trivy },
  { id: "snyk", name: "snyk", label: "Snyk", description: PARSER_DESCRIPTIONS.snyk },
  { id: "semgrep", name: "semgrep", label: "Semgrep", description: PARSER_DESCRIPTIONS.semgrep },
  { id: "gitleaks", name: "gitleaks", label: "Gitleaks", description: PARSER_DESCRIPTIONS.gitleaks },
  { id: "sarif", name: "sarif", label: "SARIF", description: PARSER_DESCRIPTIONS.sarif },
  { id: "canonical", name: "canonical", label: "Canonical", description: PARSER_DESCRIPTIONS.canonical },
];

function ParserSelect({ value, onChange }: { value?: string; onChange: (v: string) => void }) {
  const { token } = useAuth();
  const containerRef = useRef<HTMLDivElement>(null);
  const [parsers, setParsers] = useState<
    Array<{ id: string; name: string; label: string; description?: string }>
  >([]);
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    fetchParsers({ token: token ?? undefined })
      .then((r) => setParsers(r.parsers || []))
      .catch(() => setParsers([]));
  }, [token]);

  const opts = parsers.length > 0 ? parsers : DEFAULT_PARSERS;
  const optsWithDesc = opts.map((p) => ({
    ...p,
    description: p.description ?? PARSER_DESCRIPTIONS[p.id] ?? "",
  }));
  const selected = optsWithDesc.find((p) => p.id === (value || "sarif"));
  const filtered = query.trim()
    ? optsWithDesc.filter(
        (p) =>
          p.label.toLowerCase().includes(query.toLowerCase()) ||
          p.id.toLowerCase().includes(query.toLowerCase())
      )
    : opts;

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [isOpen]);

  const handleSelect = (id: string) => {
    onChange(id);
    setIsOpen(false);
    setQuery("");
  };

  return (
    <div ref={containerRef}>
      <label style={{ ...mono, fontSize: 9, fontWeight: 700, color: "var(--app-fg)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>
        Parser (output format)
      </label>
      <div style={{ position: "relative" }}>
        <input
          type="text"
          value={isOpen ? query : (selected?.label ?? "SARIF")}
          title={!isOpen && selected?.description ? selected.description : undefined}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => setIsOpen(true)}
          onKeyDown={(e) => {
            if (e.key === "Escape") setIsOpen(false);
            if (e.key === "Enter" && filtered.length > 0 && !isOpen) setIsOpen(true);
          }}
          placeholder="Search parsers…"
          style={{
            ...mono,
            width: "100%",
            background: "var(--app-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: "8px 12px",
            color: "var(--app-fg)",
            fontSize: 12,
            boxSizing: "border-box",
          }}
        />
        {isOpen && (
          <div
            style={{
              position: "absolute",
              top: "100%",
              left: 0,
              right: 0,
              marginTop: 4,
              maxHeight: 200,
              overflowY: "auto",
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
              zIndex: 50,
            }}
          >
            {filtered.length === 0 ? (
              <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", padding: 12 }}>
                No parsers match &quot;{query}&quot;
              </div>
            ) : (
              filtered.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  title={p.description || undefined}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    handleSelect(p.id);
                  }}
                  style={{
                    ...mono,
                    display: "block",
                    width: "100%",
                    padding: "8px 12px",
                    background: p.id === (value || "sarif") ? "var(--app-input-bg)" : "transparent",
                    border: "none",
                    color: "var(--app-fg)",
                    fontSize: 12,
                    textAlign: "left",
                    cursor: "pointer",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "var(--app-input-bg)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background =
                      p.id === (value || "sarif") ? "var(--app-input-bg)" : "transparent";
                  }}
                >
                  {p.label}
                </button>
              ))
            )}
          </div>
        )}
      </div>
      <div style={{ ...sans, fontSize: 10, color: "var(--app-muted)", marginTop: 4 }}>
        Search or select the format your scanner outputs (Trivy, Snyk, SARIF, etc.)
      </div>
    </div>
  );
}

function ReadOnlyField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <label style={{ ...mono, fontSize: 9, fontWeight: 600, color: "var(--app-muted)", textTransform: "uppercase", display: "block", marginBottom: 6 }}>{label}</label>
      <div
        style={{
          ...mono,
          width: "100%",
          background: "#0f172a",
          border: "1px solid #334155",
          borderRadius: 6,
          padding: "8px 12px",
          color: "var(--app-muted)",
          fontSize: 12,
        }}
      >
        {value || "—"}
      </div>
    </div>
  );
}

function SourceSettingsContent({
  source,
  sources,
  sourceTypes,
  tracker,
  onTrackerChange,
  onSourcesChange,
  onSourceRemoved,
}: {
  source: Source;
  sources: Source[];
  sourceTypes: [string, (typeof SOURCE_TYPES)[string]][];
  tracker: Tracker;
  onTrackerChange?: (tracker: Tracker) => void;
  onSourcesChange?: (sources: Source[]) => void;
  onSourceRemoved?: () => void;
}) {
  const typeKey = sourceTypes.find(([, v]) => v.adapter === source.adapter || v.label === source.name)?.[0];

  return (
    <>
      <SourceConfigForm
        source={source}
        sources={sources}
        onSourcesChange={onSourcesChange}
        onSourceRemoved={onSourceRemoved}
      />
      {typeKey === "aikido" && (
        <div style={{ marginTop: 24 }}>
          <AikidoSettingsPage
            sourceId={source.id}
            tracker={tracker}
            onTrackerChange={onTrackerChange}
          />
        </div>
      )}
      {(typeKey === "manual" || source.adapter === "manual") && (
        <div style={{ marginTop: 24 }}>
          <PushSourcesSettings source={source} />
        </div>
      )}
    </>
  );
}

function AddSourceContent({
  picker,
  sources,
  sourceTypes,
  onSelect,
  onSourcesChange,
  onSourceAdded,
}: {
  picker?: string;
  sources: Source[];
  sourceTypes: [string, (typeof SOURCE_TYPES)[string]][];
  onSelect: (type: string) => void;
  onSourcesChange?: (sources: Source[]) => void;
  onSourceAdded?: (source: Source) => void;
}) {
  if (picker && onSourcesChange && onSourceAdded) {
    const info = SOURCE_TYPES[picker];
    const typeDefault: Record<string, string> = {
      aikido: "scanner",
      manual: "manual",
    };
    const descDefault: Record<string, string> = {
      aikido: "Container, SCA, SAST, IaC, secrets scanner. Webhooks + REST.",
      manual: "Push findings from Trivy, Snyk, Semgrep, Gitleaks, SARIF, or canonical format. Select parser below.",
    };
    const label = info?.label ?? picker;
    const defaultId = info?.adapter === "manual" ? slugify(label) : "";
    const defaultSource: Source = {
      id: defaultId,
      name: label,
      color: info?.color ?? "var(--app-muted)",
      type: (typeDefault[picker] ?? "manual") as Source["type"],
      adapter: info?.adapter ?? "manual",
      description: descDefault[picker] ?? "",
      parser: info?.parser ?? (picker === "manual" ? "sarif" : undefined),
    };
    const handleClearAll = () => {
      if (confirm("Clear all sources? The flow canvas will show only sources you add.")) {
        onSourcesChange!([]);
      }
    };
    return (
      <>
        <AddSourceForm
          defaultSource={defaultSource}
          sources={sources}
          onSourcesChange={onSourcesChange}
          onAdded={onSourceAdded}
        />
        {picker === "aikido" && (
          <div style={{ marginTop: 24 }}>
            <p style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginBottom: 8 }}>
              After adding the source, click it on the canvas to configure Aikido credentials.
            </p>
          </div>
        )}
        {picker === "manual" && (
          <div style={{ marginTop: 24 }}>
            <p style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginBottom: 8 }}>
              After adding the source, click it to create an API key or OAuth client for ingest.
            </p>
          </div>
        )}
        {sources.length > 0 && (
          <div
            style={{
              marginTop: 24,
              paddingTop: 16,
              borderTop: "1px solid var(--app-border)",
            }}
          >
            <button
              onClick={handleClearAll}
              style={{
                ...sans,
                fontSize: 11,
                color: "var(--app-muted)",
                background: "transparent",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "8px 12px",
                cursor: "pointer",
              }}
            >
              Clear all sources
            </button>
          </div>
        )}
      </>
    );
  }

  if (picker) {
    const info = SOURCE_TYPES[picker];
    return (
      <PlaceholderSettings
        name={info?.label ?? picker}
        message="Choose a source type to add (handlers not connected)."
      />
    );
  }

  const availableTypes = sourceTypes.filter(([key]) => AVAILABLE_SOURCE_TYPES.includes(key as "aikido"));

  const handleClearAll = useCallback(() => {
    if (!onSourcesChange || !confirm("Clear all sources? The flow canvas will show only sources you add.")) return;
    onSourcesChange([]);
  }, [onSourcesChange]);

  return (
    <div>
      <div style={{ ...sans, fontSize: 12, color: "#94a3b8", marginBottom: 14 }}>
        Choose a source type to add:
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {availableTypes.map(([key, info]) => (
          <button
            key={key}
            onClick={() => onSelect(key)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              background: "#1e293b",
              border: "1px solid var(--app-border)",
              borderRadius: 8,
              padding: 14,
              cursor: "pointer",
              textAlign: "left",
              transition: "background 0.15s, border-color 0.15s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "#334155";
              e.currentTarget.style.borderColor = "#475569";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "var(--app-card-bg)";
              e.currentTarget.style.borderColor = "var(--app-border)";
            }}
          >
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: 5,
                background: info.color,
                flexShrink: 0,
              }}
            />
            <span style={{ ...sans, fontSize: 13, fontWeight: 600, color: "var(--app-fg)" }}>
              {info.label}
            </span>
          </button>
        ))}
      </div>
      {sources.length > 0 && onSourcesChange && (
        <div
          style={{
            marginTop: 24,
            paddingTop: 16,
            borderTop: "1px solid #1e293b",
          }}
        >
          <button
            onClick={handleClearAll}
            style={{
              ...sans,
              fontSize: 11,
              color: "var(--app-muted)",
              background: "transparent",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              padding: "8px 12px",
              cursor: "pointer",
            }}
          >
            Clear all sources
          </button>
        </div>
      )}
    </div>
  );
}

const TRACKER_URL_PRESETS: Record<string, string> = {
  linear: "https://linear.app/yourteam/issue/",
};

function AddTrackerForm({
  defaultTracker,
  onTrackerChange,
  onAdded,
}: {
  defaultTracker: Tracker;
  onTrackerChange: (tracker: Tracker) => void | Promise<void>;
  onAdded: () => void;
}) {
  const [edit, setEdit] = useState<Tracker>({ ...defaultTracker });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const handleAdd = useCallback(async () => {
    if (!edit.name?.trim() || !onTrackerChange || !onAdded) return;
    setSaving(true);
    setSaveError(null);
    try {
      const toSave: Tracker = {
        ...edit,
        issueTemplate: edit.issueTemplate ?? DEFAULT_ISSUE_TEMPLATE,
      };
      await onTrackerChange(toSave);
      onAdded();
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Failed to add tracker");
    } finally {
      setSaving(false);
    }
  }, [edit, onTrackerChange, onAdded]);

  return (
    <div
      style={{
        background: "var(--app-card-bg)",
        border: "1px solid var(--app-border)",
        borderRadius: 8,
        padding: 16,
        marginBottom: 20,
      }}
    >
      <div style={{ ...mono, fontSize: 9, fontWeight: 700, letterSpacing: "0.1em", color: "var(--app-muted)", textTransform: "uppercase", marginBottom: 12 }}>
        Add tracker
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <Field label="Display name" value={edit.name} onChange={(v) => setEdit((p) => ({ ...p, name: v }))} />
          <ReadOnlyField label="Type" value={edit.type} />
        </div>
        <Field
          label="Issue base URL"
          value={edit.baseUrl ?? ""}
          onChange={(v) => setEdit((p) => ({ ...p, baseUrl: v }))}
          placeholder="https://linear.app/yourteam/issue/"
        />
        {edit.type === "linear" && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "10px 12px",
              background: "var(--app-input-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
            }}
          >
            <input
              type="checkbox"
              id="useAikidoTracking"
              checked={!!edit.useAikidoTracking}
              onChange={(e) => setEdit((p) => ({ ...p, useAikidoTracking: e.target.checked }))}
            />
            <label htmlFor="useAikidoTracking" style={{ ...sans, fontSize: 12, color: "var(--app-fg)", cursor: "pointer" }}>
              Use Aikido&apos;s Linear integration for tracking (canvas shows Aikido Tracker node)
            </label>
          </div>
        )}
        {saveError && <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>{saveError}</div>}
        <button
          onClick={handleAdd}
          disabled={!edit.name?.trim() || saving}
          style={{
            ...mono,
            padding: "8px 16px",
            background: edit.name?.trim() && !saving ? "var(--app-accent)" : "var(--app-border)",
            border: "none",
            borderRadius: 6,
            color: "var(--app-fg)",
            cursor: edit.name?.trim() && !saving ? "pointer" : "not-allowed",
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          {saving ? "Adding…" : "Add tracker"}
        </button>
      </div>
    </div>
  );
}

function AddTrackerContent({
  picker,
  tracker,
  labels,
  trackerTypes,
  onSelect,
  onTrackerChange,
  onTrackerAdded,
  onLabelsChange,
}: {
  picker?: string;
  tracker: Tracker;
  labels: WatchedLabel[];
  trackerTypes: [string, (typeof TRACKER_TYPES)[string]][];
  onSelect: (type: string) => void;
  onTrackerChange?: (tracker: Tracker) => void;
  onTrackerAdded?: () => void;
  onLabelsChange?: (labels: WatchedLabel[]) => void;
}) {
  if (picker && onTrackerChange && onTrackerAdded) {
    const info = TRACKER_TYPES[picker];
    const defaultTracker: Tracker = info
      ? {
          name: info.label,
          type: info.type,
          baseUrl: TRACKER_URL_PRESETS[info.type] ?? "",
          icon: info.icon,
          commentPrefix: "[VAT]",
          description: "",
        }
      : tracker;
    return (
      <>
        <AddTrackerForm
          defaultTracker={defaultTracker}
          onTrackerChange={onTrackerChange}
          onAdded={onTrackerAdded}
        />
        <p style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginTop: 24 }}>
          After adding the tracker, click it on the canvas to configure Linear credentials.
        </p>
      </>
    );
  }

  return (
    <div>
      <div style={{ ...sans, fontSize: 12, color: "#94a3b8", marginBottom: 14 }}>
        Choose a task tracker to add:
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {trackerTypes.map(([key, info]) => (
          <button
            key={key}
            onClick={() => onSelect(key)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              background: "#1e293b",
              border: "1px solid var(--app-border)",
              borderRadius: 8,
              padding: 14,
              cursor: "pointer",
              textAlign: "left",
              transition: "background 0.15s, border-color 0.15s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "#334155";
              e.currentTarget.style.borderColor = "#475569";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "var(--app-card-bg)";
              e.currentTarget.style.borderColor = "var(--app-border)";
            }}
          >
            <span style={{ ...mono, fontSize: 16, flexShrink: 0 }}>{info.icon}</span>
            <span style={{ ...sans, fontSize: 13, fontWeight: 600, color: "var(--app-fg)" }}>
              {info.label}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function PlaceholderSettings({ name, message }: { name: string; message: string }) {
  return (
    <div>
      <div style={{ ...mono, fontSize: 12, fontWeight: 700, color: "#94a3b8", marginBottom: 8 }}>
        {name}
      </div>
      <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", lineHeight: 1.5 }}>
        {message}
      </div>
    </div>
  );
}
