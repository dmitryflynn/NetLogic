import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base:     '#06080d',
        panel:    '#0a0e16',
        surface:  '#0f141f',
        elevated: '#151b28',
        hover:    '#1a2233',
        border: {
          DEFAULT: '#1e2a3d',
          dim:     '#141c2a',
        },
        text: {
          DEFAULT: '#c8d4e3',
          dim:     '#6b7c94',
          bright:  '#eef4fb',
        },
        accent: {
          DEFAULT: '#22d3ee',
          dim:     '#083344',
          glow:    '#0891b2',
        },
        critical: '#f87171',
        high:     '#fb923c',
        medium:   '#fbbf24',
        low:      '#4ade80',
        info:     '#60a5fa',
      },
      fontFamily: {
        sans:    ['Inter', 'system-ui', 'sans-serif'],
        mono:    ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        display: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        panel: '0 1px 0 0 rgba(255,255,255,0.04) inset, 0 8px 32px rgba(0,0,0,0.35)',
        glow:  '0 0 24px rgba(34, 211, 238, 0.12)',
      },
      borderRadius: {
        sm: '6px',
        DEFAULT: '8px',
        lg: '12px',
        xl: '16px',
      },
      backgroundImage: {
        'grid-fade': 'radial-gradient(circle at 50% 0%, rgba(34,211,238,0.08) 0%, transparent 55%)',
        'sidebar': 'linear-gradient(180deg, #0a0e16 0%, #06080d 100%)',
      },
    },
  },
  plugins: [],
} satisfies Config
