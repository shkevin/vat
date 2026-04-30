"use client";

import { useCallback, useEffect, useState } from "react";
import { useFocusTrap } from "@/hooks/useFocusTrap";
import { mono, sans } from "@/lib/styles";
import {
  createAdminKey,
  createTenant,
  createUser,
  deleteTenant,
  deleteUser,
  fetchAdminKeys,
  fetchTenants,
  fetchUsers,
  revokeAdminKey,
  updateUser,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";

interface Tenant {
  id: string;
  name: string;
}

interface User {
  id: string;
  tenant_id: string | null;
  email: string;
  role: string;
}

const ROLE_OPTIONS = ["admin", "reviewer", "read_only"] as const;

function RoleBadge({ role }: { role: string }) {
  const style =
    role === "admin"
      ? {
          background: "color-mix(in srgb, var(--app-warning) 20%, transparent)",
          color: "var(--app-warning)",
        }
      : role === "reviewer"
        ? {
            background:
              "color-mix(in srgb, var(--app-accent) 20%, transparent)",
            color: "var(--app-accent)",
          }
        : {
            background: "color-mix(in srgb, var(--app-muted) 20%, transparent)",
            color: "var(--app-muted)",
          };
  return (
    <span
      style={{
        ...mono,
        fontSize: 10,
        fontWeight: 600,
        letterSpacing: "0.04em",
        padding: "4px 10px",
        borderRadius: 6,
        ...style,
      }}
    >
      {role.replace("_", " ")}
    </span>
  );
}

export function AccessSettingsPage() {
  const { token, user, setUser, isAdmin, setIsAdmin } = useAuth();
  const auth = {
    token: token ?? undefined,
    userEmail: user?.email ?? undefined,
  };
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [addTenantOpen, setAddTenantOpen] = useState(false);
  const [addUserOpen, setAddUserOpen] = useState(false);
  const [deleteUserConfirm, setDeleteUserConfirm] = useState<User | null>(null);
  const [deleteTenantConfirm, setDeleteTenantConfirm] = useState<Tenant | null>(
    null,
  );
  const [adminKeys, setAdminKeys] = useState<
    Array<{ id: string; keyPrefix: string; createdAt?: string }>
  >([]);
  const [newAdminKey, setNewAdminKey] = useState<{
    id: string;
    key: string;
    keyPrefix: string;
  } | null>(null);
  const [adminKeysLoading, setAdminKeysLoading] = useState(false);
  const [revokeAdminKeyConfirm, setRevokeAdminKeyConfirm] = useState<{
    id: string;
    keyPrefix: string;
  } | null>(null);

  const loadTenants = useCallback(async () => {
    if (!auth.token && !auth.userEmail) return;
    setLoading(true);
    setError(null);
    setForbidden(false);
    try {
      const list = await fetchTenants(auth);
      setTenants(list);
      if (list.length > 0 && !selectedTenantId) setSelectedTenantId(list[0].id);
      setIsAdmin(true);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to load";
      if (msg.includes("403") || msg.includes("Forbidden")) {
        setForbidden(true);
        setTenants([]);
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }, [auth.token, auth.userEmail, selectedTenantId, setIsAdmin]);

  const loadUsers = useCallback(async () => {
    if ((!auth.token && !auth.userEmail) || !selectedTenantId) {
      setUsers([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const list = await fetchUsers(auth, selectedTenantId);
      setUsers(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  }, [auth.token, auth.userEmail, selectedTenantId]);

  useEffect(() => {
    loadTenants();
  }, [loadTenants]);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const loadAdminKeys = useCallback(async () => {
    if (!auth.token && !auth.userEmail) return;
    setAdminKeysLoading(true);
    try {
      const res = await fetchAdminKeys(auth);
      setAdminKeys(res.keys);
    } catch {
      setAdminKeys([]);
    } finally {
      setAdminKeysLoading(false);
    }
  }, [auth.token, auth.userEmail]);

  useEffect(() => {
    if (!forbidden) loadAdminKeys();
  }, [loadAdminKeys, forbidden]);

  const handleCreateAdminKey = useCallback(async () => {
    if (!auth.token && !auth.userEmail) return;
    try {
      const res = await createAdminKey(auth);
      setNewAdminKey({ id: res.id, key: res.key, keyPrefix: res.keyPrefix });
      loadAdminKeys();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create admin key");
    }
  }, [auth.token, auth.userEmail, loadAdminKeys]);

  const handleRevokeAdminKey = useCallback(
    async (keyId: string) => {
      if (!auth.token && !auth.userEmail) return;
      await revokeAdminKey(keyId, auth);
      setRevokeAdminKeyConfirm(null);
      loadAdminKeys();
    },
    [auth.token, auth.userEmail, loadAdminKeys],
  );

  const handleCreateTenant = useCallback(
    async (id: string, name: string) => {
      if (!auth.token && !auth.userEmail) return;
      await createTenant({ id, name }, auth);
      setAddTenantOpen(false);
      loadTenants();
    },
    [auth.token, auth.userEmail, loadTenants],
  );

  const handleCreateUser = useCallback(
    async (
      id: string,
      email: string,
      tenantId: string | null,
      role: string,
    ) => {
      if (!auth.token && !auth.userEmail) return;
      await createUser(
        { id, tenant_id: tenantId ?? undefined, email, role },
        auth,
      );
      setAddUserOpen(false);
      loadUsers();
    },
    [auth.token, auth.userEmail, loadUsers],
  );

  const handleUpdateUserRole = useCallback(
    async (userId: string, role: string) => {
      if (!auth.token && !auth.userEmail) return;
      await updateUser(userId, { role }, auth);
      loadUsers();
    },
    [auth.token, auth.userEmail, loadUsers],
  );

  const handleDeleteUser = useCallback(
    async (u: User) => {
      if (!auth.token && !auth.userEmail) return;
      await deleteUser(u.id, auth);
      setDeleteUserConfirm(null);
      loadUsers();
    },
    [auth.token, auth.userEmail, loadUsers],
  );

  const handleDeleteTenant = useCallback(
    async (t: Tenant) => {
      if (!auth.token && !auth.userEmail) return;
      await deleteTenant(t.id, auth);
      setDeleteTenantConfirm(null);
      setSelectedTenantId((prev) => (prev === t.id ? null : prev));
      loadTenants();
    },
    [auth.token, auth.userEmail, loadTenants],
  );

  const selectedTenant = tenants.find((t) => t.id === selectedTenantId);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          flexShrink: 0,
          padding: "24px 28px",
          borderBottom: "1px solid var(--app-card-bg)",
          background:
            "linear-gradient(180deg, rgba(15,23,42,0.98) 0%, rgba(15,23,42,0.95) 100%)",
        }}
      >
        <h1
          style={{
            ...sans,
            fontSize: 18,
            fontWeight: 600,
            color: "var(--app-fg)",
            margin: 0,
            marginBottom: 4,
          }}
        >
          Access
        </h1>
        <p
          style={{
            ...sans,
            fontSize: 13,
            color: "var(--app-muted)",
            margin: 0,
            lineHeight: 1.5,
          }}
        >
          Manage tenants and user access. Admin only.
        </p>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            marginTop: 16,
          }}
        >
          <span style={{ ...sans, fontSize: 12, color: "var(--app-muted)" }}>
            Signed in as
          </span>
          <code
            style={{
              ...mono,
              fontSize: 12,
              color: "var(--app-accent)",
              background: "var(--app-bg)",
              padding: "4px 10px",
              borderRadius: 6,
              border: "1px solid var(--app-card-bg)",
            }}
          >
            {user?.email}
          </code>
          <button
            onClick={() => setUser(null)}
            style={{
              ...mono,
              fontSize: 11,
              padding: "6px 12px",
              background: "transparent",
              border: "1px solid var(--app-border)",
              borderRadius: 6,
              color: "var(--app-muted)",
              cursor: "pointer",
              transition: "all 0.15s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "var(--app-card-bg)";
              e.currentTarget.style.borderColor = "var(--app-muted)";
              e.currentTarget.style.color = "var(--app-fg)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.borderColor = "var(--app-border)";
              e.currentTarget.style.color = "var(--app-muted)";
            }}
          >
            Log out
          </button>
        </div>
      </div>

      {/* Content */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          padding: 28,
        }}
      >
        {forbidden && (
          <div
            style={{
              background: "rgba(248,112,96,0.08)",
              border: "1px solid rgba(248,112,96,0.25)",
              borderRadius: 10,
              padding: 24,
              marginBottom: 24,
              ...sans,
              fontSize: 14,
              color: "var(--app-danger)",
              lineHeight: 1.5,
            }}
          >
            Admin access required. Log in with an admin user to manage tenants
            and users.
          </div>
        )}

        {error && !forbidden && (
          <div
            style={{
              background: "var(--app-card-bg)",
              border: "1px solid var(--app-border)",
              borderRadius: 10,
              padding: 20,
              marginBottom: 24,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 16,
            }}
          >
            <span style={{ ...sans, fontSize: 13, color: "var(--app-danger)" }}>
              {error}
            </span>
            <button
              onClick={() => loadTenants()}
              style={{
                ...mono,
                padding: "8px 16px",
                background: "var(--app-border)",
                border: "1px solid var(--app-muted)",
                borderRadius: 6,
                color: "var(--app-fg)",
                cursor: "pointer",
                fontSize: 11,
                flexShrink: 0,
              }}
            >
              Retry
            </button>
          </div>
        )}

        {!forbidden && (
          <>
            {/* Tenants section */}
            <section style={{ marginBottom: 32 }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: 16,
                }}
              >
                <h2
                  style={{
                    ...mono,
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: "0.1em",
                    color: "var(--app-muted)",
                    textTransform: "uppercase",
                    margin: 0,
                  }}
                >
                  Tenants
                </h2>
                <button
                  onClick={() => setAddTenantOpen(true)}
                  style={{
                    ...mono,
                    padding: "8px 16px",
                    background: "var(--app-accent)",
                    border: "none",
                    borderRadius: 8,
                    color: "var(--app-fg)",
                    cursor: "pointer",
                    fontSize: 12,
                    fontWeight: 600,
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "var(--app-accent)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "var(--app-accent)";
                  }}
                >
                  + Add tenant
                </button>
              </div>

              {loading && tenants.length === 0 ? (
                <div
                  style={{
                    background: "var(--app-card-bg)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 10,
                    padding: 32,
                    textAlign: "center",
                    ...sans,
                    fontSize: 13,
                    color: "var(--app-muted)",
                  }}
                >
                  Loading tenants…
                </div>
              ) : tenants.length === 0 ? (
                <div
                  style={{
                    background: "var(--app-card-bg)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 10,
                    padding: 40,
                    textAlign: "center",
                    ...sans,
                    fontSize: 13,
                    color: "var(--app-muted)",
                  }}
                >
                  No tenants yet. Add one to get started.
                </div>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 12,
                  }}
                >
                  {tenants.map((t) => (
                    <div
                      key={t.id}
                      style={{
                        display: "flex",
                        alignItems: "stretch",
                        background:
                          selectedTenantId === t.id
                            ? "var(--app-input-bg)"
                            : "var(--app-card-bg)",
                        border:
                          selectedTenantId === t.id
                            ? "1px solid var(--app-accent)"
                            : "1px solid var(--app-border)",
                        borderRadius: 10,
                        minWidth: 180,
                        overflow: "hidden",
                      }}
                    >
                      <button
                        onClick={() => setSelectedTenantId(t.id)}
                        style={{
                          ...sans,
                          flex: 1,
                          padding: "14px 20px",
                          background: "none",
                          border: "none",
                          color: "var(--app-fg)",
                          fontSize: 13,
                          fontWeight: 500,
                          cursor: "pointer",
                          textAlign: "left",
                          transition: "background 0.15s",
                        }}
                        onMouseEnter={(e) => {
                          if (selectedTenantId !== t.id) {
                            e.currentTarget.style.background =
                              "var(--app-border)";
                          }
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = "transparent";
                        }}
                      >
                        <div style={{ fontWeight: 600, marginBottom: 2 }}>
                          {t.name}
                        </div>
                        <div
                          style={{
                            ...mono,
                            fontSize: 11,
                            color: "var(--app-muted)",
                          }}
                        >
                          {t.id}
                        </div>
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteTenantConfirm(t);
                        }}
                        aria-label={`Remove tenant ${t.name}`}
                        style={{
                          ...mono,
                          padding: "0 10px",
                          background: "none",
                          border: "none",
                          borderLeft: "1px solid var(--app-border)",
                          color: "var(--app-muted)",
                          fontSize: 12,
                          cursor: "pointer",
                          transition: "color 0.15s, background 0.15s",
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.color = "var(--app-danger)";
                          e.currentTarget.style.background =
                            "rgba(248,112,96,0.1)";
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.color = "var(--app-muted)";
                          e.currentTarget.style.background = "none";
                        }}
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Users table */}
            {selectedTenantId && (
              <section>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 16,
                  }}
                >
                  <h2
                    style={{
                      ...mono,
                      fontSize: 11,
                      fontWeight: 700,
                      letterSpacing: "0.1em",
                      color: "var(--app-muted)",
                      textTransform: "uppercase",
                      margin: 0,
                    }}
                  >
                    Users in {selectedTenant?.name ?? selectedTenantId}
                  </h2>
                  <button
                    onClick={() => setAddUserOpen(true)}
                    style={{
                      ...mono,
                      padding: "8px 16px",
                      background: "var(--app-accent)",
                      border: "none",
                      borderRadius: 8,
                      color: "var(--app-fg)",
                      cursor: "pointer",
                      fontSize: 12,
                      fontWeight: 600,
                      transition: "background 0.15s",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = "var(--app-accent)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = "var(--app-accent)";
                    }}
                  >
                    + Add user
                  </button>
                </div>

                <div
                  style={{
                    background: "var(--app-card-bg)",
                    border: "1px solid var(--app-border)",
                    borderRadius: 10,
                    overflow: "hidden",
                  }}
                >
                  {loading ? (
                    <div
                      style={{
                        padding: 32,
                        textAlign: "center",
                        ...sans,
                        fontSize: 13,
                        color: "var(--app-muted)",
                      }}
                    >
                      Loading users…
                    </div>
                  ) : users.length === 0 ? (
                    <div
                      style={{
                        padding: 48,
                        textAlign: "center",
                        ...sans,
                        fontSize: 13,
                        color: "var(--app-muted)",
                      }}
                    >
                      No users in this tenant. Add one to grant access.
                    </div>
                  ) : (
                    <table
                      style={{
                        width: "100%",
                        borderCollapse: "collapse",
                      }}
                    >
                      <thead>
                        <tr
                          style={{
                            background: "var(--app-bg)",
                            borderBottom: "1px solid var(--app-border)",
                          }}
                        >
                          <th
                            style={{
                              ...mono,
                              fontSize: 10,
                              fontWeight: 600,
                              letterSpacing: "0.06em",
                              color: "var(--app-muted)",
                              textTransform: "uppercase",
                              padding: "14px 20px",
                              textAlign: "left",
                            }}
                          >
                            Email
                          </th>
                          <th
                            style={{
                              ...mono,
                              fontSize: 10,
                              fontWeight: 600,
                              letterSpacing: "0.06em",
                              color: "var(--app-muted)",
                              textTransform: "uppercase",
                              padding: "14px 20px",
                              textAlign: "left",
                            }}
                          >
                            Role
                          </th>
                          <th
                            style={{
                              ...mono,
                              fontSize: 10,
                              fontWeight: 600,
                              letterSpacing: "0.06em",
                              color: "var(--app-muted)",
                              textTransform: "uppercase",
                              padding: "14px 20px",
                              textAlign: "right",
                              width: 80,
                            }}
                          >
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.map((u, i) => (
                          <tr
                            key={u.id}
                            style={{
                              borderBottom:
                                i < users.length - 1
                                  ? "1px solid var(--app-border)"
                                  : "none",
                              transition: "background 0.1s",
                            }}
                            onMouseEnter={(e) => {
                              e.currentTarget.style.background =
                                "var(--app-bg)";
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.background = "transparent";
                            }}
                          >
                            <td
                              style={{
                                ...sans,
                                fontSize: 13,
                                color: "var(--app-fg)",
                                padding: "14px 20px",
                              }}
                            >
                              {u.email}
                            </td>
                            <td style={{ padding: "14px 20px" }}>
                              <div
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 12,
                                }}
                              >
                                <span style={{ minWidth: 88, flexShrink: 0 }}>
                                  <RoleBadge role={u.role} />
                                </span>
                                <select
                                  value={u.role}
                                  onChange={(e) =>
                                    handleUpdateUserRole(u.id, e.target.value)
                                  }
                                  style={{
                                    ...mono,
                                    fontSize: 11,
                                    background: "var(--app-bg)",
                                    border: "1px solid var(--app-border)",
                                    borderRadius: 6,
                                    padding: "6px 10px",
                                    color: "var(--app-fg)",
                                    cursor: "pointer",
                                    width: 120,
                                  }}
                                >
                                  {ROLE_OPTIONS.map((r) => (
                                    <option key={r} value={r}>
                                      {r.replace("_", " ")}
                                    </option>
                                  ))}
                                </select>
                              </div>
                            </td>
                            <td
                              style={{
                                padding: "14px 20px",
                                textAlign: "right",
                              }}
                            >
                              {(() => {
                                const adminCount = users.filter(
                                  (x) => x.role === "admin",
                                ).length;
                                const isLastAdmin =
                                  u.role === "admin" && adminCount <= 1;
                                return (
                                  <button
                                    onClick={() =>
                                      !isLastAdmin && setDeleteUserConfirm(u)
                                    }
                                    disabled={isLastAdmin}
                                    title={
                                      isLastAdmin
                                        ? "Cannot remove the last admin"
                                        : undefined
                                    }
                                    style={{
                                      ...mono,
                                      padding: "4px 10px",
                                      background: "transparent",
                                      border: "1px solid var(--app-border)",
                                      borderRadius: 6,
                                      color: isLastAdmin
                                        ? "var(--app-muted)"
                                        : "var(--app-muted)",
                                      fontSize: 11,
                                      cursor: isLastAdmin
                                        ? "not-allowed"
                                        : "pointer",
                                      transition: "all 0.15s",
                                      opacity: isLastAdmin ? 0.6 : 1,
                                    }}
                                    onMouseEnter={(e) => {
                                      if (!isLastAdmin) {
                                        e.currentTarget.style.color =
                                          "var(--app-danger)";
                                        e.currentTarget.style.borderColor =
                                          "var(--app-danger)";
                                      }
                                    }}
                                    onMouseLeave={(e) => {
                                      if (!isLastAdmin) {
                                        e.currentTarget.style.color =
                                          "var(--app-muted)";
                                        e.currentTarget.style.borderColor =
                                          "var(--app-border)";
                                      }
                                    }}
                                  >
                                    Remove
                                  </button>
                                );
                              })()}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </section>
            )}

            {/* Admin API keys */}
            <section style={{ marginTop: 32 }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: 16,
                }}
              >
                <h2
                  style={{
                    ...mono,
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: "0.1em",
                    color: "var(--app-muted)",
                    textTransform: "uppercase",
                    margin: 0,
                  }}
                >
                  Admin API keys
                </h2>
                <button
                  onClick={handleCreateAdminKey}
                  style={{
                    ...mono,
                    padding: "8px 16px",
                    background: "var(--app-accent)",
                    border: "none",
                    borderRadius: 8,
                    color: "var(--app-fg)",
                    cursor: "pointer",
                    fontSize: 12,
                    fontWeight: 600,
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = "var(--app-accent)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = "var(--app-accent)";
                  }}
                >
                  + Create admin key
                </button>
              </div>
              <p
                style={{
                  ...sans,
                  fontSize: 12,
                  color: "var(--app-muted)",
                  margin: 0,
                  marginBottom: 16,
                  lineHeight: 1.5,
                }}
              >
                Long-lived keys for automation (scripts, CI). Use as
                VAT_ADMIN_TOKEN. Key shown once.
              </p>
              {newAdminKey && (
                <div
                  style={{
                    background: "var(--app-card-bg)",
                    border: "1px solid var(--app-accent)",
                    borderRadius: 10,
                    padding: 20,
                    marginBottom: 16,
                  }}
                >
                  <p
                    style={{
                      ...sans,
                      fontSize: 12,
                      color: "var(--app-warning)",
                      margin: 0,
                      marginBottom: 12,
                    }}
                  >
                    Copy this key now. It will not be shown again.
                  </p>
                  <code
                    style={{
                      ...mono,
                      fontSize: 11,
                      fontWeight: 500,
                      color: "var(--app-fg)",
                      background: "var(--app-bg)",
                      padding: "12px 16px",
                      borderRadius: 8,
                      display: "block",
                      wordBreak: "break-all",
                      border: "1px solid var(--app-border)",
                    }}
                  >
                    {newAdminKey.key}
                  </code>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(newAdminKey.key);
                      setNewAdminKey(null);
                    }}
                    style={{
                      ...mono,
                      marginTop: 12,
                      padding: "8px 16px",
                      background: "var(--app-accent)",
                      border: "none",
                      borderRadius: 8,
                      color: "var(--app-fg)",
                      cursor: "pointer",
                      fontSize: 11,
                      fontWeight: 600,
                    }}
                  >
                    Copy and close
                  </button>
                </div>
              )}
              <div
                style={{
                  background: "var(--app-card-bg)",
                  border: "1px solid var(--app-border)",
                  borderRadius: 10,
                  overflow: "hidden",
                }}
              >
                {adminKeysLoading ? (
                  <div
                    style={{
                      padding: 32,
                      textAlign: "center",
                      ...sans,
                      fontSize: 13,
                      color: "var(--app-muted)",
                    }}
                  >
                    Loading…
                  </div>
                ) : adminKeys.length === 0 ? (
                  <div
                    style={{
                      padding: 32,
                      textAlign: "center",
                      ...sans,
                      fontSize: 13,
                      color: "var(--app-muted)",
                    }}
                  >
                    No admin keys. Create one for scripts or CI.
                  </div>
                ) : (
                  <table
                    style={{
                      width: "100%",
                      borderCollapse: "collapse",
                    }}
                  >
                    <thead>
                      <tr
                        style={{
                          background: "var(--app-bg)",
                          borderBottom: "1px solid var(--app-border)",
                        }}
                      >
                        <th
                          style={{
                            ...mono,
                            fontSize: 10,
                            fontWeight: 600,
                            letterSpacing: "0.06em",
                            color: "var(--app-muted)",
                            textTransform: "uppercase",
                            padding: "14px 20px",
                            textAlign: "left",
                          }}
                        >
                          Key
                        </th>
                        <th
                          style={{
                            ...mono,
                            fontSize: 10,
                            fontWeight: 600,
                            letterSpacing: "0.06em",
                            color: "var(--app-muted)",
                            textTransform: "uppercase",
                            padding: "14px 20px",
                            textAlign: "left",
                          }}
                        >
                          Created
                        </th>
                        <th
                          style={{
                            ...mono,
                            fontSize: 10,
                            fontWeight: 600,
                            letterSpacing: "0.06em",
                            color: "var(--app-muted)",
                            textTransform: "uppercase",
                            padding: "14px 20px",
                            textAlign: "right",
                            width: 80,
                          }}
                        >
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {adminKeys.map((k, i) => (
                        <tr
                          key={k.id}
                          style={{
                            borderBottom:
                              i < adminKeys.length - 1
                                ? "1px solid var(--app-border)"
                                : "none",
                          }}
                        >
                          <td
                            style={{
                              ...mono,
                              fontSize: 12,
                              color: "var(--app-fg)",
                              padding: "14px 20px",
                            }}
                          >
                            {k.keyPrefix}…
                          </td>
                          <td
                            style={{
                              ...sans,
                              fontSize: 12,
                              color: "var(--app-muted)",
                              padding: "14px 20px",
                            }}
                          >
                            {k.createdAt
                              ? new Date(k.createdAt).toLocaleString()
                              : "—"}
                          </td>
                          <td
                            style={{
                              padding: "14px 20px",
                              textAlign: "right",
                            }}
                          >
                            <button
                              onClick={() =>
                                setRevokeAdminKeyConfirm({
                                  id: k.id,
                                  keyPrefix: k.keyPrefix,
                                })
                              }
                              style={{
                                ...mono,
                                padding: "4px 10px",
                                background: "transparent",
                                border: "1px solid var(--app-border)",
                                borderRadius: 6,
                                color: "var(--app-muted)",
                                fontSize: 11,
                                cursor: "pointer",
                                transition: "all 0.15s",
                              }}
                              onMouseEnter={(e) => {
                                e.currentTarget.style.color =
                                  "var(--app-danger)";
                                e.currentTarget.style.borderColor =
                                  "var(--app-danger)";
                              }}
                              onMouseLeave={(e) => {
                                e.currentTarget.style.color =
                                  "var(--app-muted)";
                                e.currentTarget.style.borderColor =
                                  "var(--app-border)";
                              }}
                            >
                              Revoke
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>
          </>
        )}

        {addTenantOpen && (
          <AddTenantModal
            onClose={() => setAddTenantOpen(false)}
            onCreate={handleCreateTenant}
          />
        )}
        {addUserOpen && (
          <AddUserModal
            tenants={tenants}
            selectedTenantId={selectedTenantId}
            onClose={() => setAddUserOpen(false)}
            onCreate={handleCreateUser}
          />
        )}
        {deleteUserConfirm && (
          <ConfirmModal
            title="Remove user"
            message={`Remove ${deleteUserConfirm.email}? They will lose access to VAT.`}
            confirmLabel="Remove"
            confirmDanger
            onConfirm={() => handleDeleteUser(deleteUserConfirm)}
            onCancel={() => setDeleteUserConfirm(null)}
          />
        )}
        {deleteTenantConfirm && (
          <ConfirmModal
            title="Remove tenant"
            message={`Remove tenant "${deleteTenantConfirm.name}"? Users in this tenant will be unassigned.`}
            confirmLabel="Remove"
            confirmDanger
            onConfirm={() => handleDeleteTenant(deleteTenantConfirm)}
            onCancel={() => setDeleteTenantConfirm(null)}
          />
        )}
        {revokeAdminKeyConfirm && (
          <ConfirmModal
            title="Revoke admin key"
            message={`Revoke key ${revokeAdminKeyConfirm.keyPrefix}…? Scripts using this key will no longer work.`}
            confirmLabel="Revoke"
            confirmDanger
            onConfirm={() => handleRevokeAdminKey(revokeAdminKeyConfirm.id)}
            onCancel={() => setRevokeAdminKeyConfirm(null)}
          />
        )}
      </div>
    </div>
  );
}

function ConfirmModal({
  title,
  message,
  confirmLabel,
  confirmDanger,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  confirmDanger?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const handleConfirm = async () => {
    setLoading(true);
    setError(null);
    try {
      await onConfirm();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    } finally {
      setLoading(false);
    }
  };
  const dialogRef = useFocusTrap<HTMLDivElement>(true);
  return (
    <div
      ref={dialogRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-title"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
      onClick={onCancel}
    >
      <div
        style={{
          background: "var(--app-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 12,
          padding: 24,
          width: "100%",
          maxWidth: 400,
          boxShadow: "0 24px 48px rgba(0,0,0,0.5)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3
          id="confirm-title"
          style={{
            ...sans,
            fontSize: 16,
            fontWeight: 600,
            color: "var(--app-fg)",
            margin: 0,
            marginBottom: 12,
          }}
        >
          {title}
        </h3>
        <p
          style={{
            ...sans,
            fontSize: 13,
            color: "var(--app-muted)",
            margin: 0,
            marginBottom: error ? 12 : 20,
            lineHeight: 1.5,
          }}
        >
          {message}
        </p>
        {error && (
          <div
            style={{
              ...sans,
              fontSize: 12,
              color: "var(--app-danger)",
              marginBottom: 16,
              padding: "8px 12px",
              background: "rgba(248,112,96,0.1)",
              borderRadius: 6,
            }}
          >
            {error}
          </div>
        )}
        <div style={{ display: "flex", gap: 12, justifyContent: "flex-end" }}>
          <button
            onClick={onCancel}
            disabled={loading}
            style={{
              ...mono,
              padding: "8px 16px",
              background: "transparent",
              border: "1px solid var(--app-border)",
              borderRadius: 8,
              color: "var(--app-muted)",
              cursor: loading ? "not-allowed" : "pointer",
              fontSize: 12,
            }}
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={loading}
            style={{
              ...mono,
              padding: "8px 16px",
              background: confirmDanger
                ? "var(--app-danger)"
                : "var(--app-accent)",
              border: "none",
              borderRadius: 8,
              color: "var(--app-fg)",
              cursor: loading ? "not-allowed" : "pointer",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {loading ? "…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

function AddTenantModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: (id: string, name: string) => Promise<void>;
}) {
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!id.trim() || !name.trim()) return;
    setSaving(true);
    setErr(null);
    try {
      await onCreate(id.trim().replace(/\s+/g, "-"), name.trim());
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed");
    } finally {
      setSaving(false);
    }
  };

  const dialogRef = useFocusTrap<HTMLDivElement>(true);
  return (
    <div
      ref={dialogRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-tenant-title"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--app-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 12,
          padding: 28,
          width: "100%",
          maxWidth: 400,
          boxShadow: "0 24px 48px rgba(0,0,0,0.5)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3
          id="add-tenant-title"
          style={{
            ...sans,
            fontSize: 16,
            fontWeight: 600,
            color: "var(--app-fg)",
            margin: 0,
            marginBottom: 20,
          }}
        >
          Add tenant
        </h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-muted)",
                display: "block",
                marginBottom: 6,
              }}
            >
              ID (slug)
            </label>
            <input
              value={id}
              onChange={(e) => setId(e.target.value)}
              placeholder="t-engineering"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 13,
              }}
            />
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-muted)",
                display: "block",
                marginBottom: 6,
              }}
            >
              Name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Engineering Team"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 13,
              }}
            />
          </div>
          {err && (
            <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>
              {err}
            </div>
          )}
          <div
            style={{
              display: "flex",
              gap: 12,
              justifyContent: "flex-end",
              marginTop: 8,
            }}
          >
            <button
              onClick={onClose}
              style={{
                ...mono,
                padding: "10px 18px",
                background: "transparent",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                color: "var(--app-muted)",
                cursor: "pointer",
                fontSize: 12,
              }}
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={!id.trim() || !name.trim() || saving}
              style={{
                ...mono,
                padding: "10px 18px",
                background:
                  id.trim() && name.trim() && !saving
                    ? "var(--app-accent)"
                    : "var(--app-border)",
                border: "none",
                borderRadius: 8,
                color: "var(--app-fg)",
                cursor:
                  id.trim() && name.trim() && !saving
                    ? "pointer"
                    : "not-allowed",
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {saving ? "Adding…" : "Add tenant"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AddUserModal({
  tenants,
  selectedTenantId,
  onClose,
  onCreate,
}: {
  tenants: Tenant[];
  selectedTenantId: string | null;
  onClose: () => void;
  onCreate: (
    id: string,
    email: string,
    tenantId: string | null,
    role: string,
  ) => Promise<void>;
}) {
  const [id, setId] = useState("");
  const [email, setEmail] = useState("");
  const [tenantId, setTenantId] = useState(selectedTenantId ?? "");
  const [role, setRole] = useState("reviewer");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!id.trim() || !email.trim()) return;
    setSaving(true);
    setErr(null);
    try {
      await onCreate(id.trim(), email.trim(), tenantId || null, role);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed");
    } finally {
      setSaving(false);
    }
  };

  const dialogRef = useFocusTrap<HTMLDivElement>(true);
  return (
    <div
      ref={dialogRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby="add-user-title"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--app-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 12,
          padding: 28,
          width: "100%",
          maxWidth: 400,
          boxShadow: "0 24px 48px rgba(0,0,0,0.5)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3
          id="add-user-title"
          style={{
            ...sans,
            fontSize: 16,
            fontWeight: 600,
            color: "var(--app-fg)",
            margin: 0,
            marginBottom: 20,
          }}
        >
          Add user
        </h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-muted)",
                display: "block",
                marginBottom: 6,
              }}
            >
              ID
            </label>
            <input
              value={id}
              onChange={(e) => setId(e.target.value)}
              placeholder="u-eng-lead"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 13,
              }}
            />
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-muted)",
                display: "block",
                marginBottom: 6,
              }}
            >
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="eng-lead@co.com"
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 13,
              }}
            />
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-muted)",
                display: "block",
                marginBottom: 6,
              }}
            >
              Tenant
            </label>
            <select
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 13,
              }}
            >
              <option value="">— None —</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label
              style={{
                ...mono,
                fontSize: 10,
                fontWeight: 600,
                color: "var(--app-muted)",
                display: "block",
                marginBottom: 6,
              }}
            >
              Role
            </label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-card-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 13,
              }}
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r} value={r}>
                  {r.replace("_", " ")}
                </option>
              ))}
            </select>
          </div>
          {err && (
            <div style={{ ...sans, fontSize: 12, color: "var(--app-danger)" }}>
              {err}
            </div>
          )}
          <div
            style={{
              display: "flex",
              gap: 12,
              justifyContent: "flex-end",
              marginTop: 8,
            }}
          >
            <button
              onClick={onClose}
              style={{
                ...mono,
                padding: "10px 18px",
                background: "transparent",
                border: "1px solid var(--app-border)",
                borderRadius: 8,
                color: "var(--app-muted)",
                cursor: "pointer",
                fontSize: 12,
              }}
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={!id.trim() || !email.trim() || saving}
              style={{
                ...mono,
                padding: "10px 18px",
                background:
                  id.trim() && email.trim() && !saving
                    ? "var(--app-accent)"
                    : "var(--app-border)",
                border: "none",
                borderRadius: 8,
                color: "var(--app-fg)",
                cursor:
                  id.trim() && email.trim() && !saving
                    ? "pointer"
                    : "not-allowed",
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {saving ? "Adding…" : "Add user"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
