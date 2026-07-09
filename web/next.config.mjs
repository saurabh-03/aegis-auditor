/** @type {import('next').NextConfig} */
const API = process.env.API_ORIGIN ?? 'http://localhost:4000';

const nextConfig = {
  reactStrictMode: true,
  // ESLint isn't configured in this workspace; type-checking still gates the build.
  eslint: { ignoreDuringBuilds: true },
  async rewrites() {
    // Proxy API + WebSocket to the Aegis backend so the browser talks same-origin.
    return [{ source: '/api/:path*', destination: `${API}/api/:path*` }];
  },
};

export default nextConfig;
