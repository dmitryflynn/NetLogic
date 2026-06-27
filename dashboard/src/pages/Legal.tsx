import { Link } from 'react-router-dom'
import Markdown from '../components/Markdown'
import { TERMS_MD, PRIVACY_MD } from '../legal'

/**
 * Public legal pages (Terms of Service, Privacy Policy). Rendered outside the
 * license/auth gates so they are always reachable — including the links shown on
 * the sign-up consent step.
 */
function LegalDoc({ md }: { md: string }) {
  return (
    <div className="min-h-full bg-base">
      <div className="max-w-3xl mx-auto px-6 py-10">
        <Link to="/sign-up" className="text-accent text-[12px] hover:underline">← Back to sign-up</Link>
        <div className="mt-6 text-text-dim text-[13px] leading-relaxed legal-doc">
          <Markdown text={md} />
        </div>
      </div>
    </div>
  )
}

export function TermsPage() {
  return <LegalDoc md={TERMS_MD} />
}

export function PrivacyPage() {
  return <LegalDoc md={PRIVACY_MD} />
}
