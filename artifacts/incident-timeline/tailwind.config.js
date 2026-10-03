/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0f1d',
          card: '#111827',
          cardBorder: '#1f293d',
          accent: '#06b6d4',
          accentHover: '#0891b2',
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#10b981',
          info: '#3b82f6',
        }
      }
    },
  },
  plugins: [],
}
