import { SignIn } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'
import { Brand } from '../components/Brand'

export default function Login() {
  return (
    <div className="min-h-full overflow-x-hidden site-bg relative flex">
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

      <div className="relative z-10 hidden lg:flex lg:w-[48%] flex-col justify-between p-14">
        <Brand size="md" subtitle />
        <div className="max-w-lg space-y-8">
          <h1 className="font-display text-[2.35rem] xl:text-[2.65rem] font-bold text-text-bright leading-[1.12] tracking-[-0.03em]">
            Attack-surface scanner
            <br />
            that <span className="text-accent">proves,</span> not
            <br />
            <span className="text-text-dim font-medium">guesses.</span>
          </h1>
          <p className="text-[14.5px] text-text-dim leading-[1.75]">
            NetLogic scans your external footprint and comes back with what is
            actually exploitable, evidence attached to each finding.
          </p>
          <ul className="space-y-3 text-[14px] text-text font-mono tracking-tight">
            <li className="flex gap-3"><span className="text-accent">01</span> collect → classify → adjudicate → report</li>
            <li className="flex gap-3"><span className="text-accent">02</span> fusion pipeline, not signature noise</li>
            <li className="flex gap-3"><span className="text-accent">03</span> graded findings with evidence attached</li>
          </ul>
        </div>
        <p className="text-text-dim text-[11px] font-mono tracking-[0.12em] uppercase">Authorized assessments only</p>
      </div>

      <div className="relative z-10 flex-1 flex flex-col items-center justify-center gap-8 py-12 px-6">
        <div className="lg:hidden">
          <Brand size="md" subtitle />
        </div>
        <div className="glass-strong rounded-[28px] p-2 w-full max-w-[420px]">
          <SignIn
            routing="path"
            path="/login"
            signUpUrl="/sign-up"
            forceRedirectUrl="/"
          />
        </div>
        <p className="text-center text-[13px] font-mono tracking-[0.08em]">
          <Link to="/terms" className="text-accent hover:underline">terms</Link>
          <span className="text-text-dim"> · </span>
          <Link to="/privacy" className="text-accent hover:underline">privacy</Link>
        </p>
      </div>
    </div>
  )
}
