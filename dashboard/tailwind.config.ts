import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base:     '#071014',
        panel:    '#0d191e',
        surface:  '#101d23',
        elevated: '#16262e',
        hover:    'rgba(255, 255, 255, 0.045)',
        border: {
          DEFAULT: '#20343b',
          dim:     '#16262e',
        },
        text: {
          DEFAULT: '#c4d3d8',
          dim:     '#81939b',
          bright:  '#eaf3f5',
        },
        accent: {
          DEFAULT: '#62e5dc',
          dim:     'rgba(98, 229, 220, 0.12)',
          glow:    '#84c8bd',
        },
        critical: '#ff5f5f',
        high:     '#ff8c42',
        medium:   '#f0c77b',
        low:      '#8fe2a5',
        info:     '#66aaff',
      },
      fontFamily: {
        sans:    ['"Space Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Space Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        serif:   ['"Space Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono:    ['"DM Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        glass: 'inset 0 1px 0 rgba(255,255,255,.08), inset 0 -1px 0 rgba(98,229,220,.12), 0 12px 32px rgba(0,0,0,.45)',
        glow:  '0 0 40px rgba(98, 229, 220, 0.12)',
      },
      borderRadius: {
        sm: '8px',
        DEFAULT: '12px',
        lg: '16px',
        xl: '22px',
      },
      backdropBlur: {
        glass: '16px',
      },
    },
  },
  plugins: [],
} satisfies Config
