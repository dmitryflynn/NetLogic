import { SignIn } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'
import { Brand } from '../components/Brand'

export default function Login() {
  return (
    <div className="min-h-full site-bg relative flex">
      <div className="site-grid pointer-events-none absolute inset-0" />
      <div className="site-noise pointer-events-none absolute inset-0" />

      <div className="relative z-10 hidden lg:flex lg:w-[48%] flex-col justify-between p-14">
        <Brand size="md" subtitle />
        <div className="max-w-lg space-y-8">
          <h1 className="font-serif text-[2.65rem] font-semibold text-text-bright leading-[1.15] tracking-[-0.03em]">
            See the attack surface as it actually is.
          </h1>
          <p className="text-[16px] text-text-dim leading-relaxed">
            Fusion-adjudicated findings, live CVE correlation, and executive reporting —
            the same visual language as the product site, built for operators.
          </p>
          <ul className="space-y-3 text-[14.5px] text-text">
            <li className="flex gap-3"><span className="text-accent mt-0.5">—</span> Multi-sensor fusion with AI adjudication</li>
            <li className="flex gap-3"><span className="text-accent mt-0.5">—</span> NVD + EPSS correlation, not signature noise</li>
            <li className="flex gap-3"><span className="text-accent mt-0.5">—</span> Executive and technical reports from one scan</li>
          </ul>
        </div>
        <p className="text-text-dim text-[12px]">Authorized assessments only.</p>
      </div>

      <div className="relative z-10 flex-1 flex flex-col items-center justify-center gap-8 py-12 px-6">
        <div className="lg:hidden">
          <Brand size="md" subtitle />
        </div>
        <div className="glass-strong rounded-2xl p-2 w-full max-w-[420px]">
          <SignIn
            routing="path"
            path="/login"
            signUpUrl="/sign-up"
            forceRedirectUrl="/"
          />
        </div>
        <p className="text-center text-text-dim text-[12px]">
          <Link to="/terms" className="hover:text-text">Terms</Link>
          {' · '}
          <Link to="/privacy" className="hover:text-text">Privacy</Link>
        </p>
      </div>
    </div>
  )
}
