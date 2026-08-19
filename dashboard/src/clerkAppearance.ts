/** Align Clerk widgets with netlogic.studio tokens. */
export const clerkAppearance = {
  variables: {
    colorPrimary: '#62e5dc',
    colorBackground: '#0d191e',
    colorInputBackground: '#071014',
    colorInputText: '#eaf3f5',
    colorText: '#eaf3f5',
    colorTextSecondary: '#81939b',
    colorDanger: '#ff5f5f',
    colorNeutral: '#c4d3d8',
    colorSuccess: '#8fe2a5',
    borderRadius: '0.75rem',
    fontFamily: '"Space Grotesk", ui-sans-serif, system-ui, sans-serif',
    fontFamilyButtons: '"Space Grotesk", ui-sans-serif, system-ui, sans-serif',
  },
  elements: {
    card: {
      background: 'transparent',
      boxShadow: 'none',
    },
    headerTitle: {
      fontFamily: '"Space Grotesk", ui-sans-serif, sans-serif',
      fontWeight: '700',
    },
    formButtonPrimary: {
      background: 'linear-gradient(180deg, rgba(255,255,255,.07), rgba(255,255,255,0) 42%), rgba(98,229,220,.18)',
      color: '#62e5dc',
      border: '1px solid rgba(98,229,220,.45)',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,.10)',
    },
    socialButtonsBlockButton: {
      background: 'rgba(7,16,20,.55)',
      border: '1px solid #20343b',
      color: '#eaf3f5',
    },
    formFieldInput: {
      background: '#071014',
      borderColor: '#20343b',
      color: '#eaf3f5',
    },
    footerActionLink: {
      color: '#62e5dc',
    },
  },
} as const
