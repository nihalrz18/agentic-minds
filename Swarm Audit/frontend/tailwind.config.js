/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:       '#0d1117',
          surface:  '#161b22',
          border:   '#30363d',
          text:     '#c9d1d9',
          muted:    '#8b949e',
          blue:     '#58a6ff',
          green:    '#3fb950',
          orange:   '#ffa657',
          red:      '#ff7b72',
          purple:   '#bc8cff',
          yellow:   '#ffd700',
          cyan:     '#a5d6ff',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'monospace'],
      },
      animation: {
        'pulse-slow':  'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow':   'spin 2s linear infinite',
        'bounce-once': 'bounce 0.5s ease-in-out 1',
      },
    },
  },
  plugins: [],
};
