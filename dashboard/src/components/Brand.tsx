export function BrandMark({ className = '' }: { className?: string }) {
  return (
    <span className={`brand-lock ${className}`} aria-hidden>
      <svg viewBox="0 0 66 48">
        <rect x="7" y="18" width="4" height="20" rx="2" fill="#f2f1ee" />
        <rect x="21" y="15" width="4" height="26" rx="2" fill="#f2f1ee" />
        <rect x="34" y="8" width="4" height="40" rx="2" fill="#98e8db" />
        <rect x="48" y="16" width="4" height="25" rx="2" fill="#f2f1ee" />
        <rect x="62" y="18" width="4" height="20" rx="2" fill="#f2f1ee" />
      </svg>
    </span>
  )
}

export function Brand({ size = 'md', subtitle }: { size?: 'sm' | 'md' | 'lg'; subtitle?: boolean }) {
  const title =
    size === 'lg' ? 'text-[1.35rem]' :
    size === 'sm' ? 'text-[15px]' : 'text-[16px]'
  return (
    <div className="flex items-center gap-2.5">
      <BrandMark />
      <div>
        <p className={`brand-name leading-none ${title}`}>
          netlogic<sup className="text-[0.55em] font-medium ml-0.5">®</sup>
        </p>
        {subtitle && (
          <p className="font-mono text-[10px] text-text-dim mt-1.5 tracking-[0.16em] uppercase">
            proves, not guesses
          </p>
        )}
      </div>
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
