import { useState } from 'react'
import { SignUp } from '@clerk/clerk-react'
import { Link } from 'react-router-dom'

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
    <div className="min-h-full flex flex-col items-center justify-center bg-base gap-6 py-10">
      <div className="text-center space-y-1">
        <p className="font-display font-bold text-xl text-text-bright tracking-widest">
          NET<span className="text-accent">LOGIC</span>
        </p>
        <p className="text-text-dim text-[11px]">Attack Surface Intelligence</p>
      </div>

      {!agreed ? (
        <div className="panel p-5 max-w-sm w-full space-y-4">
          <p className="section-title">Before you create an account</p>
          <label className="flex items-start gap-2.5 text-[12px] text-text-dim cursor-pointer select-none">
            <input
              type="checkbox"
              checked={agreed}
              onChange={(e) => setAgreed(e.target.checked)}
              className="accent-accent mt-0.5"
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
            onClick={() => setAgreed(true)}
          >
            Continue to sign up
          </button>
        </div>
      ) : (
        <>
          <SignUp
            routing="path"
            path="/sign-up"
            signInUrl="/login"
            forceRedirectUrl="/"
          />
          <p className="text-center text-text-dim text-[10px] max-w-sm">
            By creating an account you agree to the{' '}
            <Link to="/terms" className="text-accent hover:underline">Terms of Service</Link>{' '}
            and{' '}
            <Link to="/privacy" className="text-accent hover:underline">Privacy Policy</Link>.
          </p>
        </>
      )}

      <p className="text-center text-text-dim text-[10px]">For authorized use only</p>
    </div>
  )
}
