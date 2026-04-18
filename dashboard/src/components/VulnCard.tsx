import { useState } from 'react'

// Only allow http/https URLs in reference links — blocks javascript: injection.
function isSafeUrl(url: string): boolean {
  try {
    const { protocol } = new URL(url)
    return protocol === 'https:' || protocol === 'http:'
  } catch {
    return false
  }
}

interface Vuln {
  cve_id?:      string
  title?:       string
  description?: string
  cvss?:        number
  severity?:    string
  remediation?: string
  references?:  string[]
  port?:        number
  service?:     string
  exploitable?: boolean
  exploit_ref?: string
  kev?:         boolean
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-critical border-critical/40 bg-critical/10',
  HIGH:     'text-high    border-high/40    bg-high/10',
  MEDIUM:   'text-medium  border-medium/40  bg-medium/10',
  LOW:      'text-low     border-low/40     bg-low/10',
  INFO:     'text-text-dim border-border    bg-elevated',
}

function sevColor(v: Vuln): string {
  if (v.severity) return SEV_COLORS[v.severity.toUpperCase()] ?? SEV_COLORS.INFO
  if (!v.cvss) return SEV_COLORS.INFO
  if (v.cvss >= 9)   return SEV_COLORS.CRITICAL
  if (v.cvss >= 7)   return SEV_COLORS.HIGH
  if (v.cvss >= 4)   return SEV_COLORS.MEDIUM
  return SEV_COLORS.LOW
}

export default function VulnCard({ vuln }: { vuln: Vuln }) {
  const [open, setOpen] = useState(false)
  const color = sevColor(vuln)

  return (
    <div className="panel border rounded-lg overflow-hidden">
      <button
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-elevated/50 transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide shrink-0 ${color}`}>
          {vuln.severity ?? (vuln.cvss != null ? `${vuln.cvss.toFixed(1)}` : 'INFO')}
        </span>
        {vuln.cvss != null && (
          <span className="text-[11px] font-mono text-text-dim shrink-0">{vuln.cvss.toFixed(1)}</span>
        )}
        <span className="font-medium text-[12px] text-text-bright flex-1 text-left">{vuln.title ?? vuln.cve_id ?? 'Unknown'}</span>
        {vuln.kev && (
          <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-critical/20 text-critical border border-critical/40 uppercase tracking-wide shrink-0">KEV</span>
        )}
        {vuln.exploitable && !vuln.kev && (
          <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-high/20 text-high border border-high/40 uppercase tracking-wide shrink-0">Exploit</span>
        )}
        {vuln.cve_id && (
          <span className="text-[10px] font-mono text-text-dim shrink-0">{vuln.cve_id}</span>
        )}
        {(vuln.port || vuln.service) && (
          <span className="text-[10px] text-text-dim shrink-0">
            {vuln.service}{vuln.port ? `:${vuln.port}` : ''}
          </span>
        )}
        <span className="text-text-dim text-[10px] shrink-0">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-border/50 pt-3">
          {vuln.description && (
            <p className="text-[12px] text-text leading-relaxed">{vuln.description}</p>
          )}
          {vuln.description && !vuln.remediation && vuln.kev && (
            <p className="text-[11px] text-critical font-medium">⚠ Listed in CISA Known Exploited Vulnerabilities catalog</p>
          )}
          {vuln.remediation && (
            <div>
              <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Remediation</p>
              <p className="text-[12px] text-text">{vuln.remediation}</p>
            </div>
          )}
          {vuln.exploit_ref && isSafeUrl(vuln.exploit_ref) && (
            <div>
              <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Exploit Reference</p>
              <a href={vuln.exploit_ref} target="_blank" rel="noopener noreferrer"
                 className="text-[11px] font-mono text-high hover:underline break-all">
                {vuln.exploit_ref}
              </a>
            </div>
          )}
          {vuln.references && vuln.references.length > 0 && (
            <div>
              <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">References</p>
              <ul className="space-y-0.5">
                {vuln.references.map((r, i) =>
                  isSafeUrl(r) ? (
                    <li key={i}>
                      <a
                        href={r}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[11px] font-mono text-accent truncate hover:underline block"
                      >
                        {r}
                      </a>
                    </li>
                  ) : (
                    <li key={i} className="text-[11px] font-mono text-text-dim truncate">{r}</li>
                  )
                )}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
