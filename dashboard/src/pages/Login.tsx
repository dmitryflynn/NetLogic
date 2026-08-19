import { SignIn } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'

export default function Login() {
  return (
    <div className="min-h-full flex bg-base">
      {/* Brand panel */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 border-r border-border bg-sidebar relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-fade pointer-events-none" />
        <div className="relative">
          <p className="font-display font-bold text-2xl text-text-bright tracking-tight">
            Net<span className="text-accent">Logic</span>
          </p>
          <p className="text-text-dim text-[12px] mt-1 uppercase tracking-[0.2em]">
            Attack Surface Intelligence
          </p>
        </div>
        <div className="relative space-y-6 max-w-md">
          <h1 className="text-3xl font-semibold text-text-bright leading-tight">
            Map, correlate, and prioritize vulnerabilities across your external attack surface.
          </h1>
          <ul className="space-y-3 text-[13px] text-text-dim">
            <li className="flex gap-2"><span className="text-accent">◈</span> Multi-sensor fusion with AI adjudication</li>
            <li className="flex gap-2"><span className="text-accent">◈</span> Live CVE correlation via NVD + EPSS</li>
            <li className="flex gap-2"><span className="text-accent">◈</span> Executive and technical reporting</li>
          </ul>
        </div>
        <p className="relative text-text-dim text-[11px]">For authorized security assessments only.</p>
      </div>

      {/* Sign-in panel */}
      <div className="flex-1 flex flex-col items-center justify-center gap-6 py-10 px-6">
        <div className="lg:hidden text-center space-y-1 mb-2">
          <p className="font-display font-bold text-xl text-text-bright tracking-tight">
            Net<span className="text-accent">Logic</span>
          </p>
        </div>
        <SignIn
          routing="path"
          path="/login"
          signUpUrl="/sign-up"
          forceRedirectUrl="/"
        />
        <p className="text-center text-text-dim text-[10px]">
          <Link to="/terms" className="hover:text-text">Terms</Link>
          {' · '}
          <Link to="/privacy" className="hover:text-text">Privacy</Link>
        </p>
      </div>
    </div>
  )
}
