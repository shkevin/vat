/** @type {import('next').NextConfig} */
const apiUpstream = process.env.API_UPSTREAM_URL || "http://localhost:8000";
const isProd = process.env.NODE_ENV === "production";

// CSP intentionally allows 'unsafe-inline' for script and style — Next.js
// hydration emits inline <script> for the route loader, and the report
// engine pervasively uses inline styles. We deliberately omit
// 'unsafe-eval' so eval() / new Function() are blocked browser-side, which
// neutralizes the legacy /test-report eval and any future XSS-via-eval
// path. A nonce-based hardening pass can replace 'unsafe-inline' later.
const cspDirectives = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self' https:",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
];

const securityHeaders = [
  { key: "Content-Security-Policy", value: cspDirectives.join("; ") },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "geolocation=(), microphone=(), camera=()" },
];
if (isProd) {
  // Only enable HSTS in production — setting it on localhost pins the
  // browser to HTTPS for that hostname even after dev cert expiry.
  securityHeaders.push({
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains",
  });
}

const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  transpilePackages: ["@xyflow/react"],
  experimental: {
    optimizePackageImports: ["lucide-react"],
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${apiUpstream}/api/:path*` },
      {
        source: "/webhook/:path*",
        destination: `${apiUpstream}/webhook/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
