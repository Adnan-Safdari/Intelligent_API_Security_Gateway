/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Traces the runtime dependencies into .next/standalone, so the image can be
  // assembled by copying build output instead of installing packages on the
  // target architecture. See gateway-dashboard/Dockerfile.
  output: "standalone",
};

export default nextConfig;
