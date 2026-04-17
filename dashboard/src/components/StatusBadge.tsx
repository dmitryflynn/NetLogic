const COLORS: Record<string, string> = {
  queued:    'text-text-dim border-border bg-elevated',
  running:   'text-accent border-accent/30 bg-accent/10',
  completed: 'text-low border-low/30 bg-low/10',
  failed:    'text-critical border-critical/30 bg-critical/10',
  cancelled: 'text-text-dim border-border bg-elevated',
}

export default function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-block text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${COLORS[status] ?? COLORS.queued}`}
    >
      {status}
    </span>
  )
}
