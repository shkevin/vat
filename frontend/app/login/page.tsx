"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { exchangeCode, fetchAuthConfig, login } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";
import { mono, sans } from "@/lib/styles";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "/api";

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginPageInner />
    </Suspense>
  );
}

function LoginPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, initialized, setUser } = useAuth();
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [googleEnabled, setGoogleEnabled] = useState(false);

  useEffect(() => {
    fetchAuthConfig()
      .then((c) => setGoogleEnabled(c.google_enabled))
      .catch(() => setGoogleEnabled(false));
  }, []);

  // Redirect to home if already logged in (session restored from localStorage)
  useEffect(() => {
    if (initialized && user) router.replace("/", { scroll: false });
  }, [initialized, user, router]);

  // Handle OAuth callback: ?code= (server-exchanged) or ?error=
  // The legacy ?token= path was removed (CVE-equivalent: anyone with a
  // crafted login URL could log a victim in as the attacker's account
  // since the token was decoded client-side without server verification).
  useEffect(() => {
    const code = searchParams.get("code");
    const err = searchParams.get("error");
    if (err) {
      const messages: Record<string, string> = {
        oauth_denied: "Sign-in was cancelled",
        oauth_failed: "Google sign-in failed",
        oauth_state: "Sign-in expired or was tampered with — please try again",
        no_email: "Google did not provide an email",
        user_not_found: "Account not found. Contact your admin.",
      };
      setError(messages[err] ?? "Sign-in failed");
      router.replace("/login", { scroll: false });
      return;
    }
    if (code) {
      exchangeCode(code)
        .then((res) => {
          setUser(res.user, res.token);
          router.replace("/", { scroll: false });
        })
        .catch((e) => {
          setError(e instanceof Error ? e.message : "Invalid session");
          router.replace("/login", { scroll: false });
        });
    }
  }, [searchParams, setUser, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const u = usernameRef.current?.value?.trim() ?? "";
    const p = passwordRef.current?.value ?? "";
    if (!u || !p) {
      setError("Username and password required");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const res = await login(u, p);
      setUser(res.user, res.token);
      router.replace("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = () => {
    window.location.href = `${API_BASE}/auth/google/authorize`;
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "var(--app-bg)",
        padding: 20,
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 360,
          background: "var(--app-card-bg)",
          border: "1px solid var(--app-border)",
          borderRadius: 12,
          padding: 32,
          boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
        }}
      >
        <div
          style={{
            ...mono,
            fontSize: 14,
            fontWeight: 700,
            color: "var(--app-fg)",
            marginBottom: 8,
          }}
        >
          VAT — Vulnerability Assessment Tracker
        </div>
        <div
          style={{
            ...sans,
            fontSize: 12,
            color: "var(--app-muted)",
            marginBottom: 24,
          }}
        >
          Sign in to continue
        </div>

        {googleEnabled && (
          <>
            <button
              type="button"
              onClick={handleGoogleSignIn}
              style={{
                ...mono,
                width: "100%",
                padding: "12px 16px",
                background: "#4285f4",
                border: "none",
                borderRadius: 6,
                color: "#fff",
                fontSize: 13,
                fontWeight: 600,
                cursor: "pointer",
                marginBottom: 16,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 8,
              }}
            >
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                <path
                  fill="#fff"
                  d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z"
                />
                <path
                  fill="#fff"
                  d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.909-2.258c-.806.54-1.837.86-3.047.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332C2.438 15.983 5.482 18 9 18z"
                />
                <path
                  fill="#fff"
                  d="M3.964 10.71c-.18-.54-.282-1.117-.282-1.71 0-.593.102-1.17.282-1.71V4.958H.957C.347 6.173 0 7.548 0 9s.348 2.827.957 4.042l3.007-2.332z"
                />
                <path
                  fill="#fff"
                  d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0 5.482 0 2.438 2.017.957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z"
                />
              </svg>
              Sign in with Google
            </button>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                marginBottom: 16,
              }}
            >
              <div
                style={{ flex: 1, height: 1, background: "var(--app-border)" }}
              />
              <span
                style={{ ...sans, fontSize: 11, color: "var(--app-muted)" }}
              >
                or
              </span>
              <div
                style={{ flex: 1, height: 1, background: "var(--app-border)" }}
              />
            </div>
          </>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label
              htmlFor="username"
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 600,
                color: "var(--app-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                display: "block",
                marginBottom: 6,
              }}
            >
              Username
            </label>
            <input
              ref={usernameRef}
              id="username"
              type="text"
              autoComplete="username"
              defaultValue=""
              autoFocus
              required
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 14,
              }}
            />
          </div>
          <div style={{ marginBottom: 24 }}>
            <label
              htmlFor="password"
              style={{
                ...mono,
                fontSize: 9,
                fontWeight: 600,
                color: "var(--app-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
                display: "block",
                marginBottom: 6,
              }}
            >
              Password
            </label>
            <input
              ref={passwordRef}
              id="password"
              type="password"
              autoComplete="current-password"
              defaultValue=""
              required
              style={{
                ...mono,
                width: "100%",
                background: "var(--app-input-bg)",
                border: "1px solid var(--app-border)",
                borderRadius: 6,
                padding: "10px 14px",
                color: "var(--app-fg)",
                fontSize: 14,
              }}
            />
          </div>
          {error && (
            <div
              style={{
                ...sans,
                fontSize: 12,
                color: "var(--app-danger)",
                marginBottom: 16,
              }}
            >
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            style={{
              ...mono,
              width: "100%",
              padding: "12px 16px",
              background: loading ? "var(--app-muted)" : "var(--app-accent)",
              border: "none",
              borderRadius: 6,
              color: "var(--app-fg)",
              fontSize: 13,
              fontWeight: 600,
              cursor: loading ? "wait" : "pointer",
            }}
          >
            {loading ? "Signing in…" : "Sign in with email"}
          </button>
        </form>

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
          Contact your administrator for credentials
        </div>
      </div>
    </div>
  );
}
