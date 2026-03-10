"use client";

import { useState, useEffect, useCallback } from "react";
import { mono, sans } from "@/lib/styles";
import { fetchVatStatus } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";

interface VatStatus {
  databaseConfigured: boolean;
  secretKeyConfigured: boolean;
  publicUrl: string;
}

export function VATBackendSettingsPage() {
  const { token } = useAuth();
  const auth = { token };
  const [status, setStatus] = useState<VatStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const s = await fetchVatStatus(auth);
      setStatus(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load status");
      setStatus(null);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  const copyUrl = (url: string, key: string) => {
    navigator.clipboard.writeText(url);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  if (loading) {
    return (
      <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", padding: 20 }}>
        Loading VAT backend status…
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          background: "var(--app-card-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          padding: 16,
          marginBottom: 20,
        }}
      >
        <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>{error}</div>
        <button
          onClick={load}
          style={{
            ...mono,
            marginTop: 10,
            padding: "6px 12px",
            background: "var(--app-border)",
            border: "1px solid var(--app-muted)",
            borderRadius: 4,
            color: "var(--app-muted)",
            cursor: "pointer",
            fontSize: 10,
          }}
        >
          Retry
        </button>
      </div>
    );
  }

  if (!status) return null;

  const StatusBadge = ({ configured }: { configured: boolean }) => (
    <span
      style={{
        ...mono,
        fontSize: 9,
        fontWeight: 700,
        letterSpacing: "0.08em",
        padding: "3px 8px",
        borderRadius: 4,
        background: configured ? "rgba(80,200,120,0.15)" : "rgba(248,112,96,0.15)",
        color: configured ? "var(--app-success)" : "var(--app-danger)",
      }}
    >
      {configured ? "✓ Configured" : "✗ Not set"}
    </span>
  );

  const CopyBtn = ({ url, label }: { url: string; label: string }) => (
    <button
      onClick={() => copyUrl(url, label)}
      style={{
        ...mono,
        padding: "6px 12px",
        background: copied === label ? "var(--app-success)" : "var(--app-border)",
        border: "1px solid var(--app-muted)",
        borderRadius: 4,
        color: copied === label ? "var(--app-bg)" : "var(--app-muted)",
        cursor: "pointer",
        fontSize: 10,
      }}
    >
      {copied === label ? "Copied" : "Copy"}
    </button>
  );

  return (
    <div>
      <div
        style={{
          ...mono,
          fontSize: 9,
          fontWeight: 700,
          letterSpacing: "0.12em",
          color: "var(--app-muted)",
          textTransform: "uppercase",
          marginBottom: 16,
        }}
      >
        VAT Backend
      </div>

      <div
        style={{
          background: "var(--app-card-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          padding: 20,
        }}
      >
        <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", marginBottom: 16, lineHeight: 1.5 }}>
          VAT ingests findings from sources, deduplicates, and syncs to your task tracker. Configure via environment variables.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)", minWidth: 140 }}>
              Database
            </span>
            <StatusBadge configured={status.databaseConfigured} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)", minWidth: 140 }}>
              Secret key
            </span>
            <StatusBadge configured={status.secretKeyConfigured} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)", minWidth: 140 }}>
              Public URL
            </span>
            <code
              style={{
                ...mono,
                fontSize: 10,
                color: "var(--app-accent)",
                background: "var(--app-bg)",
                padding: "6px 10px",
                borderRadius: 4,
                flex: 1,
                minWidth: 200,
              }}
            >
              {status.publicUrl}
            </code>
            <CopyBtn url={status.publicUrl} label="public" />
          </div>
        </div>

        <div
          style={{
            ...sans,
            fontSize: 10,
            color: "var(--app-muted)",
            marginTop: 20,
            paddingTop: 16,
            borderTop: "1px solid var(--app-border)",
          }}
        >
          Set <code style={{ ...mono, color: "var(--app-muted)" }}>VAT_PUBLIC_URL</code>, <code style={{ ...mono, color: "var(--app-muted)" }}>VAT_DATABASE_URL</code>, and <code style={{ ...mono, color: "var(--app-muted)" }}>VAT_SECRET_KEY</code> in your environment or <code style={{ ...mono, color: "var(--app-muted)" }}>.env</code>.
        </div>
      </div>
    </div>
  );
}
