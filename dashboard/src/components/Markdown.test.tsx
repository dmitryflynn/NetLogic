import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import Markdown from './Markdown'

describe('Markdown — analyst per-finding output', () => {
  it('renders a level-3 finding as a collapsible section, open by default', () => {
    const md = [
      '## Findings',
      '### 1. OpenSSH 6.6.1p1 on :22 `[HIGH]` `[Potential]`',
      '- **What:** outdated OpenSSH on port 22',
      '- **Remediation:** upgrade OpenSSH to >= 9.6',
    ].join('\n')
    const { container } = render(<Markdown text={md} />)
    const details = container.querySelector('details')
    expect(details).toBeTruthy()
    expect(details).toHaveAttribute('open')                         // open by default
    expect(screen.getByText(/upgrade OpenSSH to >= 9.6/)).toBeInTheDocument()
  })

  it('renders fenced code blocks (PoC commands)', () => {
    const md = [
      '### 1. Exposed env file `[CRITICAL]` `[Confirmed]`',
      '- **Proof of concept:**',
      '```',
      'curl -sI http://host:80/.env',
      '```',
    ].join('\n')
    const { container } = render(<Markdown text={md} />)
    expect(container.querySelector('pre code')).toBeTruthy()
    expect(screen.getByText(/curl -sI http:\/\/host:80\/\.env/)).toBeInTheDocument()
  })
})
