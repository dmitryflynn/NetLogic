import { useState } from 'react'
import { SignUp } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'
import { Brand } from '../components/Brand'

/**
 * Sign-up screen — Clerk owns account creation (verification, MFA, passkeys).
 *
 * FTC-aligned consent gate: the account-creation widget is not shown until the
 * user gives affirmative, express consent to the Terms of Service and Privacy
 * Policy. The checkbox is unchecked by default (no pre-checked / implied
 * consent), the disclosure is clear and conspicuous, and both documents are
 * linked and reachable before agreeing.
 */
export default function SignUpPage() {
  const [agreed, setAgreed] = useState(false)

  return (
    <div className="min-h-full overflow-x-hidden site-bg relative flex flex-col items-center justify-center gap-8 py-12 px-6">
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
      <div className="relative z-10">
        <Brand size="md" subtitle />
      </div>

      {!agreed ? (
        <div className="relative z-10 glass-strong p-7 max-w-md w-full space-y-5 rounded-2xl">
          <p className="font-display text-xl font-bold text-text-bright">Before you create an account</p>
          <label className="flex items-start gap-3 text-[14px] text-text-dim cursor-pointer select-none leading-relaxed">
            <input
              type="checkbox"
              checked={agreed}
              onChange={(e) => setAgreed(e.target.checked)}
              className="accent-accent mt-1"
            />
            <span>
              I have read and agree to the{' '}
              <Link to="/terms" className="text-accent hover:underline">Terms of Service</Link>{' '}
              and{' '}
              <Link to="/privacy" className="text-accent hover:underline">Privacy Policy</Link>,
              and I confirm I will only scan systems I own or am authorized to test.
            </span>
          </label>
          <button
            type="button"
            className="btn btn-primary w-full"
            disabled={!agreed}
            aria-disabled={!agreed}
            title={!agreed ? 'Agree to the terms to continue' : undefined}
            onClick={() => setAgreed(true)}
          >
            Continue to sign up
          </button>
          {!agreed && (
            <p className="text-center text-[12px] text-text-dim font-mono">
              Check the box above to enable continue
            </p>
          )}
        </div>
      ) : (
        <div className="relative z-10 glass-strong rounded-2xl p-2 w-full max-w-[420px]">
          <SignUp
            routing="path"
            path="/sign-up"
            signInUrl="/login"
            forceRedirectUrl="/"
          />
          <p className="text-center text-text-dim text-[12px] max-w-sm mx-auto pb-4 px-4">
            By creating an account you agree to the{' '}
            <Link to="/terms" className="text-accent hover:underline">Terms of Service</Link>{' '}
            and{' '}
            <Link to="/privacy" className="text-accent hover:underline">Privacy Policy</Link>.
          </p>
        </div>
      )}

      <p className="relative z-10 text-center text-[13px] font-mono tracking-[0.08em]">
        <Link to="/terms" className="text-accent hover:underline">terms</Link>
        <span className="text-text-dim"> · </span>
        <Link to="/privacy" className="text-accent hover:underline">privacy</Link>
      </p>
    </div>
  )
}
