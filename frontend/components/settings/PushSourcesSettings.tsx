"use client";

import { useState, useEffect, useCallback } from "react";
import { mono, sans } from "@/lib/styles";
import {
  fetchIngestKeys,
  fetchVatStatus,
  createIngestKey,
  regenerateIngestKey,
  revokeIngestKey,
  createOAuthClient,
  rotateOAuthClient,
  revokeOAuthClient,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import type { Source } from "@/types";
import { displaySourceName } from "@/lib/utils";

interface PushSourcesSettingsProps {
  source: Source;
}

export function PushSourcesSettings({ source }: PushSourcesSettingsProps) {
  const { token } = useAuth();
  const auth = { token };
  const [ingestUrl, setIngestUrl] = useState<string>("");
  const [keys, setKeys] = useState<
    Array<{ sourceId: string; keyPrefix: string; configured: boolean; authType?: string; createdAt?: string; rotatedAt?: string }>
  >([]);
  const [oauthClients, setOauthClients] = useState<
    Array<{ sourceId: string; clientId: string; createdAt?: string; rotatedAt?: string }>
  >([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [newKeyFor, setNewKeyFor] = useState<{ sourceId: string; key: string } | null>(null);
  const [newOAuthFor, setNewOAuthFor] = useState<{
    sourceId: string;
    clientId: string;
    clientSecret: string;
  } | null>(null);
  const [actionLoading, setActionLoading] = useState<"key" | "oauth" | "revoke" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const sourceId = source.id;

  /** Source ID must be set and saved before creating credentials. Default ids (s-1, s-2) are placeholders. */
  const canCreateCredentials =
    sourceId.trim().length > 0 && !/^s-\d+$/.test(sourceId.trim());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [vatRes, keysRes] = await Promise.all([
        fetchVatStatus(auth),
        fetchIngestKeys(auth),
      ]);
      const base = vatRes.publicUrl?.replace(/\/$/, "") ?? "";
      setIngestUrl(`${base}/api/ingest`);
      setKeys(keysRes.keys);
      setOauthClients(keysRes.oauthClients ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load status");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const keyForThisSource = keys.find((k) => k.sourceId === sourceId);
  const oauthForThisSource = oauthClients.find((c) => c.sourceId === sourceId);

  const handleGenerate = useCallback(async () => {
    if (!sourceId.trim()) return;
    setActionLoading("key");
    setActionError(null);
    setNewKeyFor(null);
    try {
      const res = await createIngestKey(sourceId, auth);
      setNewKeyFor({ sourceId, key: res.key });
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to generate key");
    } finally {
      setActionLoading(null);
    }
  }, [sourceId, load, token]);

  const handleRegenerate = useCallback(async () => {
    if (!confirm("Regenerating will invalidate the current key. Continue?")) return;
    setActionLoading("key");
    setActionError(null);
    setNewKeyFor(null);
    try {
      const res = await regenerateIngestKey(sourceId, auth);
      setNewKeyFor({ sourceId, key: res.key });
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to regenerate key");
    } finally {
      setActionLoading(null);
    }
  }, [sourceId, load, token]);

  const handleRevoke = useCallback(async () => {
    if (
      !confirm(
        "Revoking will invalidate the key. CI pipelines will fail until a new key is generated. Continue?"
      )
    )
      return;
    setActionLoading("revoke");
    setActionError(null);
    setNewKeyFor(null);
    try {
      await revokeIngestKey(sourceId, auth);
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to revoke key");
    } finally {
      setActionLoading(null);
    }
  }, [sourceId, load, token]);

  const handleCreateOAuth = useCallback(async () => {
    if (!sourceId.trim()) return;
    setActionLoading("oauth");
    setActionError(null);
    setNewOAuthFor(null);
    try {
      const res = await createOAuthClient(sourceId, auth);
      setNewOAuthFor({ sourceId, clientId: res.clientId, clientSecret: res.clientSecret });
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to create OAuth client");
    } finally {
      setActionLoading(null);
    }
  }, [sourceId, load, token]);

  const handleRotateOAuth = useCallback(async () => {
    if (!confirm("Rotating will invalidate the current client secret. Continue?")) return;
    setActionLoading("oauth");
    setActionError(null);
    setNewOAuthFor(null);
    try {
      const res = await rotateOAuthClient(sourceId, auth);
      setNewOAuthFor({ sourceId, clientId: res.clientId, clientSecret: res.clientSecret });
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to rotate OAuth");
    } finally {
      setActionLoading(null);
    }
  }, [sourceId, load, token]);

  const handleRevokeOAuth = useCallback(async () => {
    if (
      !confirm(
        "Revoking will invalidate the OAuth client. CI pipelines will fail until a new client is created. Continue?"
      )
    )
      return;
    setActionLoading("revoke");
    setActionError(null);
    setNewOAuthFor(null);
    try {
      await revokeOAuthClient(sourceId, auth);
      await load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to revoke OAuth client");
    } finally {
      setActionLoading(null);
    }
  }, [sourceId, load, token]);

  const exampleCurl = () => {
    if (!ingestUrl) return "";
    if (oauthForThisSource) {
      return `# 1. Get token
TOKEN=$(curl -s -X POST "${ingestUrl.replace("/api/ingest", "/api/oauth/token")}" \\
  -d "grant_type=client_credentials" \\
  -d "client_id=YOUR_CLIENT_ID" \\
  -d "client_secret=YOUR_CLIENT_SECRET" | jq -r '.access_token')

# 2. Ingest
curl -X POST "${ingestUrl}" \\
  -H "Authorization: Bearer $TOKEN" \\
  -F "file=@result.json"`;
    }
    return `curl -X POST "${ingestUrl}" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -F "file=@result.json"`;
  };

  if (loading) {
    return (
      <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", padding: 20 }}>
        Loading credentials…
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          background: "var(--app-input-bg)",
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
            border: "1px solid var(--app-border)",
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
        Credentials for {displaySourceName(source.name) || displaySourceName(source.id) || "source"}
      </div>

      {!canCreateCredentials && (
        <div
          style={{
            background: "var(--app-input-bg)",
            border: "1px solid var(--app-border)",
            borderRadius: 6,
            padding: 16,
            marginBottom: 20,
          }}
        >
          <div style={{ ...sans, fontSize: 12, color: "var(--app-muted)", lineHeight: 1.5 }}>
            Set a <strong>Source ID</strong> in the form above (e.g. <code style={{ ...mono, fontSize: 11 }}>trivy-ci</code>) and click <strong>Save</strong> before creating credentials.
            The Source ID ties the API key to this integration.
          </div>
        </div>
      )}

      <div
        style={{
          background: "var(--app-card-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 6,
          padding: 20,
        }}
      >
        <div
          style={{
            ...sans,
            fontSize: 12,
            color: "var(--app-muted)",
            marginBottom: 16,
            lineHeight: 1.5,
          }}
        >
          Push findings from CI. Parser: <strong>{source.parser || "sarif"}</strong>. Create an API key
          or OAuth client and store credentials in your pipeline secrets.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {newOAuthFor && newOAuthFor.sourceId === sourceId && (
            <div
              style={{
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-success)",
                borderRadius: 6,
                padding: 12,
              }}
            >
              <div
                style={{
                  ...mono,
                  fontSize: 9,
                  color: "var(--app-success)",
                  marginBottom: 8,
                  textTransform: "uppercase",
                }}
              >
                New OAuth client — copy now, secret won&apos;t be shown again
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span style={{ ...mono, fontSize: 9, color: "var(--app-muted)", minWidth: 70 }}>client_id</span>
                  <code
                    style={{
                      ...mono,
                      fontSize: 10,
                      color: "var(--app-accent)",
                      background: "var(--app-bg)",
                      padding: "6px 10px",
                      borderRadius: 4,
                      flex: 1,
                      minWidth: 120,
                      wordBreak: "break-all",
                    }}
                  >
                    {newOAuthFor.clientId}
                  </code>
                  <button
                    onClick={() => copyToClipboard(newOAuthFor.clientId, `oauth-id-${newOAuthFor.sourceId}`)}
                    style={{
                      ...mono,
                      padding: "6px 12px",
                      background:
                        copied === `oauth-id-${newOAuthFor.sourceId}` ? "var(--app-success)" : "var(--app-border)",
                      border: "1px solid var(--app-border)",
                      borderRadius: 4,
                      color: copied === `oauth-id-${newOAuthFor.sourceId}` ? "var(--app-bg)" : "var(--app-muted)",
                      cursor: "pointer",
                      fontSize: 10,
                    }}
                  >
                    {copied === `oauth-id-${newOAuthFor.sourceId}` ? "Copied" : "Copy"}
                  </button>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span style={{ ...mono, fontSize: 9, color: "var(--app-muted)", minWidth: 70 }}>client_secret</span>
                  <code
                    style={{
                      ...mono,
                      fontSize: 10,
                      color: "var(--app-accent)",
                      background: "var(--app-bg)",
                      padding: "6px 10px",
                      borderRadius: 4,
                      flex: 1,
                      minWidth: 120,
                      wordBreak: "break-all",
                    }}
                  >
                    {newOAuthFor.clientSecret}
                  </code>
                  <button
                    onClick={() => copyToClipboard(newOAuthFor.clientSecret, `oauth-secret-${newOAuthFor.sourceId}`)}
                    style={{
                      ...mono,
                      padding: "6px 12px",
                      background:
                        copied === `oauth-secret-${newOAuthFor.sourceId}` ? "var(--app-success)" : "var(--app-border)",
                      border: "1px solid var(--app-border)",
                      borderRadius: 4,
                      color: copied === `oauth-secret-${newOAuthFor.sourceId}` ? "var(--app-bg)" : "var(--app-muted)",
                      cursor: "pointer",
                      fontSize: 10,
                    }}
                  >
                    {copied === `oauth-secret-${newOAuthFor.sourceId}` ? "Copied" : "Copy"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {newKeyFor && newKeyFor.sourceId === sourceId && (
            <div
              style={{
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-success)",
                borderRadius: 6,
                padding: 12,
              }}
            >
              <div
                style={{
                  ...mono,
                  fontSize: 9,
                  color: "var(--app-success)",
                  marginBottom: 8,
                  textTransform: "uppercase",
                }}
              >
                New key — copy now, it won&apos;t be shown again
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  flexWrap: "wrap",
                }}
              >
                <code
                  style={{
                    ...mono,
                    fontSize: 10,
                    color: "var(--app-accent)",
                    background: "var(--app-bg)",
                    padding: "6px 10px",
                    borderRadius: 4,
                    flex: 1,
                    minWidth: 120,
                    wordBreak: "break-all",
                  }}
                >
                  {newKeyFor.key}
                </code>
                <button
                  onClick={() =>
                    copyToClipboard(newKeyFor.key, `key-${newKeyFor.sourceId}`)
                  }
                  style={{
                    ...mono,
                    padding: "6px 12px",
                    background:
                      copied === `key-${newKeyFor.sourceId}` ? "var(--app-success)" : "var(--app-border)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 4,
                    color:
                      copied === `key-${newKeyFor.sourceId}` ? "var(--app-bg)" : "var(--app-muted)",
                    cursor: "pointer",
                    fontSize: 10,
                  }}
                >
                  {copied === `key-${newKeyFor.sourceId}` ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
          )}

          {actionError && (
            <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>
              {actionError}
            </div>
          )}

          {keyForThisSource ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                flexWrap: "wrap",
                padding: 12,
                background: "var(--app-input-bg)",
                borderRadius: 6,
                border: "1px solid var(--app-border)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <code style={{ ...mono, fontSize: 11, color: "var(--app-accent)" }}>{displaySourceName(sourceId) || sourceId}</code>
                <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)" }}>
                  ({keyForThisSource.keyPrefix}…)
                </span>
                <span
                  style={{
                    ...mono,
                    fontSize: 9,
                    padding: "2px 6px",
                    background: "var(--app-border)",
                    borderRadius: 4,
                    color: "var(--app-muted)",
                  }}
                >
                  API key
                </span>
                {(keyForThisSource.rotatedAt || keyForThisSource.createdAt) && (
                  <span style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
                    {keyForThisSource.rotatedAt ? `Rotated ${keyForThisSource.rotatedAt.slice(0, 10)}` : `Created ${keyForThisSource.createdAt?.slice(0, 10) ?? ""}`}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={handleRegenerate}
                  disabled={actionLoading === "key"}
                  style={{
                    ...mono,
                    padding: "6px 12px",
                    background: "var(--app-border)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 4,
                    color: "var(--app-muted)",
                    cursor: actionLoading === "key" ? "not-allowed" : "pointer",
                    fontSize: 10,
                  }}
                >
                  Regenerate
                </button>
                <button
                  onClick={handleRevoke}
                  disabled={actionLoading === "revoke"}
                  style={{
                    ...mono,
                    padding: "6px 12px",
                    background: "transparent",
                    border: "1px solid var(--app-danger)",
                    borderRadius: 4,
                    color: "var(--app-danger)",
                    cursor: actionLoading === "revoke" ? "not-allowed" : "pointer",
                    fontSize: 10,
                  }}
                >
                  Revoke
                </button>
              </div>
            </div>
          ) : oauthForThisSource ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                flexWrap: "wrap",
                padding: 12,
                background: "var(--app-input-bg)",
                borderRadius: 6,
                border: "1px solid var(--app-border)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <code style={{ ...mono, fontSize: 11, color: "var(--app-accent)" }}>{displaySourceName(sourceId) || sourceId}</code>
                <span style={{ ...mono, fontSize: 10, color: "var(--app-muted)" }}>
                  ({oauthForThisSource.clientId.slice(0, 20)}…)
                </span>
                <span
                  style={{
                    ...mono,
                    fontSize: 9,
                    padding: "2px 6px",
                    background: "var(--app-border)",
                    borderRadius: 4,
                    color: "var(--app-muted)",
                  }}
                >
                  OAuth
                </span>
                {(oauthForThisSource.rotatedAt || oauthForThisSource.createdAt) && (
                  <span style={{ ...mono, fontSize: 9, color: "var(--app-muted)" }}>
                    {oauthForThisSource.rotatedAt ? `Rotated ${oauthForThisSource.rotatedAt.slice(0, 10)}` : `Created ${oauthForThisSource.createdAt?.slice(0, 10) ?? ""}`}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={handleRotateOAuth}
                  disabled={actionLoading === "oauth"}
                  style={{
                    ...mono,
                    padding: "6px 12px",
                    background: "var(--app-border)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 4,
                    color: "var(--app-muted)",
                    cursor: actionLoading === "oauth" ? "not-allowed" : "pointer",
                    fontSize: 10,
                  }}
                >
                  Rotate secret
                </button>
                <button
                  onClick={handleRevokeOAuth}
                  disabled={actionLoading === "revoke"}
                  style={{
                    ...mono,
                    padding: "6px 12px",
                    background: "transparent",
                    border: "1px solid var(--app-danger)",
                    borderRadius: 4,
                    color: "var(--app-danger)",
                    cursor: actionLoading === "revoke" ? "not-allowed" : "pointer",
                    fontSize: 10,
                  }}
                >
                  Revoke
                </button>
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <button
                onClick={handleGenerate}
                disabled={!canCreateCredentials || actionLoading !== null}
                style={{
                  ...mono,
                  padding: "8px 16px",
                  background:
                    canCreateCredentials && !actionLoading ? "var(--app-accent)" : "var(--app-border)",
                  border: "none",
                  borderRadius: 6,
                  color: "var(--app-fg)",
                  cursor: canCreateCredentials && !actionLoading ? "pointer" : "not-allowed",
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                {actionLoading === "key" ? "Creating…" : "Create API key"}
              </button>
              <button
                onClick={handleCreateOAuth}
                disabled={!canCreateCredentials || actionLoading !== null}
                style={{
                  ...mono,
                  padding: "8px 16px",
                  background:
                    canCreateCredentials && !actionLoading ? "var(--app-border)" : "var(--app-border)",
                  border: "1px solid var(--app-border)",
                  borderRadius: 6,
                  color: "var(--app-fg)",
                  cursor: canCreateCredentials && !actionLoading ? "pointer" : "not-allowed",
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                {actionLoading === "oauth" ? "Creating…" : "Create OAuth client"}
              </button>
            </div>
          )}

          {ingestUrl && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
                marginTop: 8,
                paddingTop: 16,
                borderTop: "1px solid var(--app-border)",
              }}
            >
              <span
                style={{
                  ...mono,
                  fontSize: 10,
                  color: "var(--app-muted)",
                  minWidth: 80,
                }}
              >
                Ingest URL
              </span>
              <code
                style={{
                  ...mono,
                  fontSize: 10,
                  color: "var(--app-accent)",
                  background: "var(--app-input-bg)",
                  padding: "6px 10px",
                  borderRadius: 4,
                  flex: 1,
                  minWidth: 200,
                  wordBreak: "break-all",
                }}
              >
                {ingestUrl}
              </code>
              <button
                onClick={() => copyToClipboard(ingestUrl, "url")}
                style={{
                  ...mono,
                  padding: "6px 12px",
                  background: copied === "url" ? "var(--app-success)" : "var(--app-border)",
                  border: "1px solid var(--app-border)",
                  borderRadius: 4,
                  color: copied === "url" ? "var(--app-bg)" : "var(--app-muted)",
                  cursor: "pointer",
                  fontSize: 10,
                }}
              >
                {copied === "url" ? "Copied" : "Copy"}
              </button>
            </div>
          )}

          {(keyForThisSource || oauthForThisSource) && (
            <div style={{ marginTop: 8 }}>
              <span
                style={{
                  ...mono,
                  fontSize: 9,
                  fontWeight: 600,
                  color: "var(--app-muted)",
                  textTransform: "uppercase",
                  display: "block",
                  marginBottom: 8,
                }}
              >
                Example curl
              </span>
              <pre
                style={{
                  ...mono,
                  fontSize: 9,
                  color: "var(--app-muted)",
                  background: "var(--app-input-bg)",
                  padding: 12,
                  borderRadius: 8,
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  margin: 0,
                  border: "1px solid var(--app-border)",
                }}
              >
                {exampleCurl()}
              </pre>
              <button
                onClick={() => copyToClipboard(exampleCurl(), "curl")}
                style={{
                  ...mono,
                  marginTop: 8,
                  padding: "6px 12px",
                  background: copied === "curl" ? "var(--app-success)" : "var(--app-border)",
                  border: "1px solid var(--app-border)",
                  borderRadius: 4,
                  color: copied === "curl" ? "var(--app-bg)" : "var(--app-muted)",
                  cursor: "pointer",
                  fontSize: 10,
                }}
              >
                {copied === "curl" ? "Copied" : "Copy curl"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
