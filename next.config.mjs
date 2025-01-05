/** @type {import('next').NextConfig} */
const nextConfig = {
    images: {
      domains: ['i.ibb.co'],
    },
  
    eslint: {
      ignoreDuringBuilds: true,
    },
    
    typescript: {
      ignoreBuildErrors: true,
    },
  };
  
  export default nextConfig;
  