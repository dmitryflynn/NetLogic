import React from 'react'

/**
 * Tiny dependency-free Markdown renderer for AI analyst output.
 *
 * Supports the subset the analyst prompt emits: #/##/### headings, **bold**,
 * `inline code`, bullet + numbered lists, GFM tables, --- rules, > blockquotes,
 * [text](url) links, and paragraphs. XSS-safe by construction — every value is
 * passed to React as a string child (React escapes it); no dangerouslySetInnerHTML.
 */

// ── Inline: **bold**, `code`, [text](url) ──────────────────────────────────────
function renderInline(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  const re = /(\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\))/g
  let last = 0
  let key = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index))
    if (m[2] !== undefined) {
      out.push(<strong key={key++} className="text-text-bright font-semibold">{m[2]}</strong>)
    } else if (m[3] !== undefined) {
      out.push(<code key={key++} className="font-mono text-[11px] bg-elevated px-1 py-0.5 rounded text-accent">{m[3]}</code>)
    } else if (m[4] !== undefined) {
      const href = m[5]
      const safe = /^https?:\/\//i.test(href)
      out.push(safe
        ? <a key={key++} href={href} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline break-all">{m[4]}</a>
        : <span key={key++}>{m[4]}</span>)
    }
    last = re.lastIndex
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

const SEV_CLASS = (s: string): string => {
  const u = s.toUpperCase()
  if (u.includes('CRITICAL')) return 'text-critical'
  if (u.includes('HIGH'))     return 'text-high'
  if (u.includes('MEDIUM'))   return 'text-medium'
  if (u.includes('LOW'))      return 'text-low'
  return ''
}

function splitRow(line: string): string[] {
  return line.replace(/^\||\|$/g, '').split('|').map((c) => c.trim())
}

export default function Markdown({ text, onExplore, exploring }: { text: string; onExplore?: (finding: string) => void; exploring?: string | null }) {
  const lines = (text || '').replace(/\r\n/g, '\n').split('\n')
  const blocks: React.ReactNode[] = []
  let i = 0
  let key = 0
  let currentSection = ''

  function isBeyond() { return currentSection === 'Beyond Known CVEs' }

  while (i < lines.length) {
    const line = lines[i]

    // blank
    if (!line.trim()) { i++; continue }

    // heading
    const h = /^(#{1,6})\s+(.*)$/.exec(line)
    if (h) {
      currentSection = h[2]
      const level = h[1].length
      const content = h[2]
      const sev = SEV_CLASS(content)
      const cls = level <= 1
        ? 'text-text-bright font-display font-bold text-[15px] mt-4 mb-2'
        : level === 2
          ? 'text-text-bright font-semibold text-[13px] mt-4 mb-1.5 border-b border-border pb-1'
          : `font-semibold text-[12px] mt-3 mb-1 ${sev || 'text-accent'}`
      blocks.push(React.createElement(`h${Math.min(level, 4)}`, { key: key++, className: cls }, renderInline(content)))
      i++; continue
    }

    // horizontal rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(line.trim())) {
      blocks.push(<hr key={key++} className="border-border my-3" />)
      i++; continue
    }

    // table: header row containing '|' followed by a separator row of dashes
    if (line.includes('|') && i + 1 < lines.length && /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/.test(lines[i + 1])) {
      const header = splitRow(line)
      i += 2
      const rows: string[][] = []
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) {
        rows.push(splitRow(lines[i])); i++
      }
      blocks.push(
        <div key={key++} className="my-2 overflow-x-auto">
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr>{header.map((c, j) => (
                <th key={j} className="text-left text-text-dim font-medium border-b border-border px-2 py-1">{renderInline(c)}</th>
              ))}</tr>
            </thead>
            <tbody>{rows.map((r, ri) => (
              <tr key={ri} className="border-b border-border/40">
                {r.map((c, ci) => (
                  <td key={ci} className={`px-2 py-1 align-top ${SEV_CLASS(c)}`}>{renderInline(c)}</td>
                ))}
              </tr>
            ))}</tbody>
          </table>
        </div>,
      )
      continue
    }

    // blockquote
    if (/^>\s?/.test(line)) {
      const quote: string[] = []
      while (i < lines.length && /^>\s?/.test(lines[i])) { quote.push(lines[i].replace(/^>\s?/, '')); i++ }
      blocks.push(
        <blockquote key={key++} className="border-l-2 border-accent/40 pl-3 my-2 text-text-dim text-[12px]">
          {quote.map((q, qi) => <p key={qi} className="mb-1 last:mb-0">{renderInline(q)}</p>)}
        </blockquote>,
      )
      continue
    }

    // unordered list
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, '')); i++
      }
      blocks.push(
        <ul key={key++} className="list-disc pl-5 my-1.5 space-y-1 text-[12px] text-text leading-relaxed">
          {items.map((it, j) => (
            <li key={j}>
              {renderInline(it)}
              {isBeyond() && onExplore && (
                <button
                  onClick={() => onExplore(it)}
                  disabled={exploring === it}
                  className={`ml-2 text-[10px] underline underline-offset-2 cursor-pointer ${
                    exploring === it
                      ? 'text-text-dim cursor-wait'
                      : 'text-accent hover:text-accent/80'
                  }`}
                >
                  {exploring === it ? 'Loading…' : 'Learn more ↷'}
                </button>
              )}
            </li>
          ))}
        </ul>,
      )
      continue
    }

    // ordered list
    if (/^\s*(\d+)\.\s+/.test(line)) {
      const start = parseInt(line.match(/^\s*(\d+)\.\s+/)?.[1] ?? '1', 10)
      const items: string[] = []
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i++ }
      blocks.push(
        <ol key={key++} start={start} className="list-decimal pl-5 my-1.5 space-y-1 text-[12px] text-text leading-relaxed">
          {items.map((it, j) => <li key={j}>{renderInline(it)}</li>)}
        </ol>,
      )
      continue
    }

    // paragraph (accumulate consecutive plain lines)
    const para: string[] = []
    while (i < lines.length && lines[i].trim()
           && !/^(#{1,6})\s/.test(lines[i])
           && !/^\s*[-*]\s+/.test(lines[i])
           && !/^\s*\d+\.\s+/.test(lines[i])
           && !/^>\s?/.test(lines[i])
           && !(lines[i].includes('|') && i + 1 < lines.length && /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/.test(lines[i + 1])))
    {
      para.push(lines[i]); i++
    }
    blocks.push(
      <p key={key++} className="text-[12px] text-text leading-relaxed my-1.5">{renderInline(para.join(' '))}</p>,
    )
  }

  return <div>{blocks}</div>
}
