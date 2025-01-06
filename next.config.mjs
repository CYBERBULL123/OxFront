/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    // Ignore ESLint errors during builds
    ignoreDuringBuilds: true,
  },
  typescript: {
    // Ignore TypeScript errors during builds
    ignoreBuildErrors: true,
  },
  experimental: {
    // Enable experimental features like output tracing excludes
    outputFileTracingExcludes: {
      '*': ['**/*'],
    },
  },
  webpack: (config, { isServer }) => {
    // Fix for window is not defined
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false, // Prevent server-side modules like fs from breaking the client build
      };
    }
    return config;
  },
};

export default nextConfig;
