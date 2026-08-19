import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base:     '#080b12',
        panel:    'rgba(14, 18, 28, 0.62)',
        surface:  'rgba(18, 24, 36, 0.72)',
        elevated: 'rgba(28, 36, 52, 0.55)',
        hover:    'rgba(255, 255, 255, 0.045)',
        border: {
          DEFAULT: 'rgba(255, 255, 255, 0.09)',
          dim:     'rgba(255, 255, 255, 0.05)',
        },
        text: {
          DEFAULT: '#c5cdd8',
          dim:     '#7a8494',
          bright:  '#f4f6f8',
        },
        accent: {
          DEFAULT: '#7ee0d0',
          dim:     'rgba(126, 224, 208, 0.12)',
          glow:    '#3d9e90',
        },
        critical: '#e07a7a',
        high:     '#e09a62',
        medium:   '#d4b45a',
        low:      '#6ec89a',
        info:     '#7aa8d4',
      },
      fontFamily: {
        sans:    ['"Source Sans 3"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        serif:   ['"Source Serif 4"', 'Georgia', 'serif'],
        display: ['"Source Serif 4"', 'Georgia', 'serif'],
        mono:    ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        glass: '0 1px 0 0 rgba(255,255,255,0.06) inset, 0 12px 40px rgba(0,0,0,0.28)',
        glow:  '0 0 40px rgba(126, 224, 208, 0.10)',
      },
      borderRadius: {
        sm: '8px',
        DEFAULT: '12px',
        lg: '16px',
        xl: '22px',
      },
      backdropBlur: {
        glass: '28px',
      },
    },
  },
  plugins: [],
} satisfies Config
