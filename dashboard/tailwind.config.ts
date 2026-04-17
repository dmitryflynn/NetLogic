import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base:     '#080b10',
        panel:    '#0d1117',
        surface:  '#131820',
        elevated: '#1a2030',
        hover:    '#1e2635',
        border: {
          DEFAULT: '#1e2840',
          dim:     '#151e2e',
        },
        text: {
          DEFAULT: '#cdd9e5',
          dim:     '#6a7a8f',
          bright:  '#e8f0f8',
        },
        accent: {
          DEFAULT: '#00d4ff',
          dim:     '#003a4d',
        },
        critical: '#ff4444',
        high:     '#ff8c42',
        medium:   '#ffcc44',
        low:      '#44dd88',
        info:     '#66aaff',
      },
      fontFamily: {
        mono:    ['"JetBrains Mono"', 'monospace'],
        display: ['Syne', 'sans-serif'],
      },
      borderRadius: {
        sm: '6px',
        DEFAULT: '8px',
        lg: '12px',
      },
    },
  },
  plugins: [],
} satisfies Config
