import { SignIn } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'

/**
 * Sign-in screen — Clerk owns authentication (password, MFA, passkeys, recovery).
 * Path-based routing under /login so Clerk can handle its own sub-steps; on
 * success the user lands on the dashboard root.
 */
export default function Login() {
  return (
    <div className="min-h-full flex flex-col items-center justify-center bg-base gap-6 py-10">
      <div className="text-center space-y-1">
        <p className="font-display font-bold text-xl text-text-bright tracking-widest">
          NET<span className="text-accent">LOGIC</span>
        </p>
        <p className="text-text-dim text-[11px]">Attack Surface Intelligence</p>
      </div>
      <SignIn
        routing="path"
        path="/login"
        signUpUrl="/sign-up"
        forceRedirectUrl="/"
      />
      <p className="text-center text-text-dim text-[10px]">For authorized use only</p>
      <p className="text-center text-text-dim text-[10px]">
        <Link to="/terms" className="hover:text-text">Terms</Link>
        {' · '}
        <Link to="/privacy" className="hover:text-text">Privacy</Link>
      </p>
    </div>
  )
}
