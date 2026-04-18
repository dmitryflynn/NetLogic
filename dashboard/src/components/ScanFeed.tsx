import { useEffect, useRef } from 'react'
import type { ScanEvent } from '../api/scan'

const TYPE_COLOR: Record<string, string> = {
  port:     'text-low',
  vuln:     'text-critical',
  progress: 'text-accent',
  info:     'text-text-dim',
  error:    'text-critical',
  done:     'text-low',
}

function fmtEvent(e: ScanEvent): string {
  const d = e.data ?? {}
  switch (e.type) {
    case 'port': {
      const p = d as { port?: number; proto?: string; service?: unknown; state?: string; version?: unknown; product?: string }
      const svc = typeof p.service === 'string' ? p.service : ''
      const ver = typeof p.version === 'string' ? p.version : typeof p.product === 'string' ? p.product : ''
      return `PORT  ${p.port}/${p.proto ?? 'tcp'}  ${p.state ?? 'open'}  ${svc}${ver ? ' ' + ver : ''}`
    }
    case 'vuln': {
      const v = d as { cve_id?: string; title?: string; cvss?: number }
      return `VULN  ${v.cve_id ?? ''}  ${v.title ?? ''}  (CVSS ${v.cvss ?? '?'})`
    }
    case 'progress': {
      const p = d as { percent?: number; message?: string }
      return `....  ${p.message ?? ''}  ${p.percent != null ? `(${Math.round(p.percent)}%)` : ''}`
    }
    case 'error': {
      const err = d as { message?: string }
      return `ERR   ${err.message ?? ''}`
    }
    case 'done':
      return `DONE`
    default:
      try { return `${e.type.toUpperCase().padEnd(5)} ${JSON.stringify(d)}` }
      catch { return `${e.type.toUpperCase().padEnd(5)} [unparseable]` }
  }
}

export default function ScanFeed({ events }: { events: ScanEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events.length])

  return (
    <div className="bg-base border border-border rounded-lg overflow-hidden">
      <div className="h-64 overflow-y-auto p-3 font-mono text-[11px] space-y-0.5">
        {events.map((e, i) => (
          <div key={i} className={TYPE_COLOR[e.type] ?? 'text-text'}>
            {e.ts != null && (
              <span className="text-text-dim mr-2 select-none">
                {new Date(e.ts * 1000).toLocaleTimeString()}
              </span>
            )}
            {(() => { try { return fmtEvent(e) } catch { return `${e.type} [render error]` } })()}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
