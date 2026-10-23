import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  cacheComponents: true,
  partialPrefetching: true,
  allowedDevOrigins: ["localhost", "127.0.0.1", "0.0.0.0"],
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://127.0.0.1:8000/api/:path*",
      },
      {
        source: "/health/:path*",
        destination: "http://127.0.0.1:8000/health/:path*",
      },
      {
        source: "/actions",
        destination: "http://127.0.0.1:8000/actions",
      },
    ];
  },
};

export default nextConfig;
