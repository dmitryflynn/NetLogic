import { Brand } from './Brand'

/** Shown when the dashboard was built without a Clerk publishable key. */
export default function MissingConfig({ message }: { message: string }) {
  return (
    <div className="min-h-full overflow-hidden site-bg relative flex items-center justify-center px-6">
      <div className="site-grid pointer-events-none absolute inset-0" />
      <div className="site-noise pointer-events-none absolute inset-0" />
      <div className="radar" aria-hidden>
        <div className="r-ring" />
        <div className="r-ring r2" />
        <div className="r-ring r3" />
        <div className="r-cross" />
        <div className="r-cross h" />
        <div className="r-sweep" />
      </div>
      <div className="relative z-10 glass-strong rounded-[28px] max-w-md w-full p-8 space-y-5">
        <Brand size="md" subtitle />
        <h1 className="font-display text-xl font-bold text-text-bright">Dashboard not configured</h1>
        <p className="text-[14px] text-text-dim leading-relaxed">{message}</p>
        <p className="font-mono text-[11px] text-text tracking-tight leading-relaxed">
          Set <span className="text-accent">VITE_CLERK_PUBLISHABLE_KEY</span> in{' '}
          <span className="text-text-bright">dashboard/.env.local</span>, then rebuild
          (<span className="text-accent">npm run build</span> or restart{' '}
          <span className="text-accent">netlogic --gui</span>).
        </p>
      </div>
    </div>
  )
}
