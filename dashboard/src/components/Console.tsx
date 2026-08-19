import type { ReactNode } from 'react'

export function ChapterLabel({ chapter, title }: { chapter: string; title: string }) {
  return (
    <div className="chapter-label">
      ch. {chapter} · {title}
    </div>
  )
}

export function ConsoleFrame({
  title,
  meta,
  children,
  className = '',
}: {
  title: string
  meta?: string
  children: ReactNode
  className?: string
}) {
  return (
    <div className={`product-frame ${className}`}>
      <div className="console-bar">
        <span>
          <span className="dot">■</span>
          {' '}
          {title}
        </span>
        {meta ? <span>{meta}</span> : null}
      </div>
      {children}
    </div>
  )
}
