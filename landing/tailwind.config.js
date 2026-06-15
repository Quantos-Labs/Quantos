/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        galaxy: {
          50: '#eef2ff',
          100: '#c7d2fe',
          200: '#818cf8',
          300: '#6366f1',
          400: '#4f46e5',
          500: '#3730a3',
          600: '#1e1b4b',
          700: '#13103a',
          800: '#0c0a2a',
          900: '#06051a',
          950: '#03020d',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'marquee': 'marquee 30s linear infinite',
        'float-orb': 'float-orb 14s ease-in-out infinite',
        'float-orb-slow': 'float-orb 20s ease-in-out infinite reverse',
        'shimmer': 'shimmer 4s linear infinite',
        'float-card': 'float-card 6s ease-in-out infinite',
        'float-card-2': 'float-card-2 8s ease-in-out infinite',
        'float-card-3': 'float-card-3 7s ease-in-out infinite',
      },
      keyframes: {
        'marquee': {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        'float-orb': {
          '0%, 100%': { transform: 'translate(0px, 0px)' },
          '33%': { transform: 'translate(40px, -55px)' },
          '66%': { transform: 'translate(-30px, 35px)' },
        },
        'shimmer': {
          'from': { backgroundPosition: '0% center' },
          'to': { backgroundPosition: '-200% center' },
        },
        'float-card': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-12px)' },
        },
        'float-card-2': {
          '0%, 100%': { transform: 'translateY(-8px)' },
          '50%': { transform: 'translateY(8px)' },
        },
        'float-card-3': {
          '0%, 100%': { transform: 'translateY(-4px)' },
          '50%': { transform: 'translateY(12px)' },
        },
      },
    },
  },
  plugins: [],
}
