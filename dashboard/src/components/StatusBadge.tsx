const COLORS: Record<string, string> = {
  queued:    'text-text-dim border-white/10 bg-white/[0.04]',
  running:   'text-accent border-accent/25 bg-accent/10',
  completed: 'text-low border-low/25 bg-low/10',
  failed:    'text-critical border-critical/30 bg-critical/10',
  cancelled: 'text-text-dim border-white/10 bg-white/[0.04]',
}

export default function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-block text-[10px] font-semibold px-2 py-0.5 rounded-md border uppercase tracking-[0.08em] ${COLORS[status] ?? COLORS.queued}`}
    >
      {status}
    </span>
  )
}
