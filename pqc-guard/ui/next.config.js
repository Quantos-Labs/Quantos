/** @type {import('next').NextConfig} */
const path = require('path');

const nextConfig = {
  transpilePackages: ['@noble/post-quantum', '@noble/hashes'],
  webpack: (config) => {
    config.resolve.fallback = { ...config.resolve.fallback, fs: false, crypto: false };
    config.resolve.alias = {
      ...config.resolve.alias,
      '@sdk': path.resolve(__dirname, '../sdk/dist'),
    };
    return config;
  },
};

module.exports = nextConfig;
