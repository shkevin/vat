/** @type {import('next').NextConfig} */
const apiUpstream = process.env.API_UPSTREAM_URL || "http://localhost:8000";

const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  transpilePackages: ["@xyflow/react"],
  experimental: {
    optimizePackageImports: ["lucide-react"],
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
