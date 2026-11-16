/** @type {import('next').NextConfig} */
const nextConfig = {
  // POSITIVE (WEB-DEBUG-007) line 4: public browser source maps in production.
  productionBrowserSourceMaps: true,
  // NEGATIVE: unrelated option that merely mentions maps.
  experimental: { serverSourceMaps: true },
  async headers() {
    return [
      {
        source: "/api/:path*",
        headers: [
          // POSITIVE (WEB-CORS-006, low) line 14: wildcard with credentials via key/value pairs.
          { key: "Access-Control-Allow-Origin", value: "*" },
          { key: "Access-Control-Allow-Credentials", value: "true" },
        ],
      },
    ];
  },
};

export default nextConfig;
