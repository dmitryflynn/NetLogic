export function Brand({ size = 'md', subtitle }: { size?: 'sm' | 'md' | 'lg'; subtitle?: boolean }) {
  const title =
    size === 'lg' ? 'text-[2rem]' :
    size === 'sm' ? 'text-[1.15rem]' : 'text-[1.35rem]'
  return (
    <div>
      <p className={`font-serif font-semibold text-text-bright tracking-[-0.03em] leading-none ${title}`}>
        NetLogic
      </p>
      {subtitle && (
        <p className="font-sans text-[11px] text-text-dim mt-1.5 tracking-[0.08em] uppercase">
          Attack surface intelligence
        </p>
      )}
    </div>
  )
}

export function IconScan({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M16 16.5 20.5 21" strokeLinecap="round" />
    </svg>
  )
}

export function IconTarget({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="3.5" />
    </svg>
  )
}

export function IconAgents({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <rect x="3.5" y="4.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="4.5" width="7" height="7" rx="1.5" />
      <rect x="8.5" y="13.5" width="7" height="7" rx="1.5" />
    </svg>
  )
}

export function IconSettings({ className = 'w-4 h-4' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 3.5v2.2M12 18.3v2.2M4.9 6.4l1.6 1.6M17.5 16l1.6 1.6M3.5 12h2.2M18.3 12h2.2M4.9 17.6l1.6-1.6M17.5 8l1.6-1.6" strokeLinecap="round" />
    </svg>
  )
}
