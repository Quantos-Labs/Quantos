import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#0a0b0f',
          card: '#121319',
          hover: '#1a1b23',
          input: '#1e1f28',
        },
        border: {
          DEFAULT: '#2a2b35',
          hover: '#3a3b48',
        },
        accent: {
          DEFAULT: '#7c3aed',
          hover: '#8b5cf6',
          muted: '#6d28d9',
        },
        ok: '#22c55e',
        warn: '#f59e0b',
        err: '#ef4444',
        muted: '#6b7280',
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
