# NetLogic — Legal Compliance & Liability-Reduction Notes

> **Not legal advice.** This is a researched, good-faith summary to help you reduce
> risk and brief a lawyer efficiently. No document and no engineer can guarantee
> you "can't get sued" — anyone can sue over anything. The goal is to (a) reduce
> the *likelihood*, (b) cap the *damage*, and (c) shield you *personally*. Have a
> licensed attorney review before launch.

## 0. The single most important thing
You currently operate as an **individual with no registered company**. That means
**your personal assets are exposed** — the liability caps in your Terms are far
weaker against an individual, and a judgment can reach your savings, not just "the
business." Two structural steps dwarf everything else below:

1. **Form an LLC** (or equivalent) and operate the Service *through it* — separate
   bank account, contracts in the entity's name, no commingling. This is the
   primary personal-asset shield. Until then, the Terms still help, but you are the
   liable party.
2. **Buy insurance**: Technology **Errors & Omissions (E&O)** + **Cyber liability**.
   For a security-scanning product handling sensitive data, this is the realistic
   backstop if a claim gets through.

Everything else reduces risk *at the margin*; these two change the magnitude.

## 1. FTC exposure (Section 5 — "unfair or deceptive acts or practices")
The FTC's core rule: **if you promise it, you must do it**, and **don't overstate
what the product does**. Applied here:

- **Privacy promises must match practice.** The FTC sues companies that break
  privacy/security promises. Your Privacy Policy claims (encryption of secrets at
  rest, no selling of personal data, sending scan data to the AI provider *only*
  when you enable it, strictly-necessary cookies) **must remain true** as the code
  evolves. They currently match the implementation — keep them in sync.
- **No deceptive claims.** Audited the UI/marketing: **no** "guarantees security,"
  "finds all vulnerabilities," "100% accurate," or "zero false positives" language
  — good. Keep it that way. Avoid absolute security/accuracy claims anywhere
  (site, ads, sales decks). The product is "informational," not a guarantee.
- **AI claims (FTC "Keep Your AI Claims in Check" + Operation AI Comply, 2024–25).**
  Don't exaggerate the AI. Don't claim accuracy you can't substantiate, and you
  can't blame the third-party model if it's wrong. The Terms now include an
  explicit AI-accuracy disclaimer. If you publish benchmark numbers (e.g.
  false-positive reduction), keep the testing evidence and state the conditions.
- **Affirmative consent for unexpected uses.** Don't use customer data (scan
  results, etc.) for anything they wouldn't expect (e.g. training models, marketing)
  without clear, opt-in consent.

## 2. FTC data-security expectations ("Start with Security")
Even with no broken promise, the FTC brings **unfairness** cases for *unreasonable*
security. Their published lessons, mapped to NetLogic (which holds especially
sensitive data — vulnerability maps of customers' networks **and** their provider
API keys):

- **Minimize what you collect/keep** — don't store scan data or keys longer than
  needed; document retention.
- **Protect what you keep** — secrets encrypted at rest (✓), TLS in transit (ensure
  your deploy terminates TLS), tenant isolation (✓), access controls + audit log (✓).
- **Segment access / least privilege** — limit who/what can read the database.
- **Oversee service providers** — your subprocessors (identity provider, hosting/DB,
  the AI/LLM provider) must also be reasonably secure; the FTC says "the buck stops
  with you." Keep a subprocessor list and their security commitments.
- **Have a written incident-response/breach plan** — most US states require
  notification on a breach of personal data within set timeframes. A vuln-data or
  key breach here is high-severity; plan for it before it happens.

## 3. The scanner-specific risk (bigger than FTC for you): misuse & the CFAA
This is the **#1 litigation/criminal-exposure** area for a scanning product:

- A customer could point NetLogic at systems they don't own → potential **Computer
  Fraud and Abuse Act (CFAA)** and equivalent violations, and **you** could face
  secondary/contributory claims for "providing the tool."
- Your Terms already require **authorized use only** and shift responsibility to the
  user (good). To strengthen the defense, **strongly consider**:
  - Re-introducing an **authorization gate or per-scan attestation** (you removed
    the DNS-verification gate; an attestation checkbox + audit log is the lighter
    middle ground and a strong "we required users to certify authorization" record).
  - **Abuse monitoring + prompt termination** of users who scan non-consenting
    third parties; preserve audit logs.
  - Blocking scans of your *own* cloud-metadata/link-local ranges so a tenant can't
    pivot through a shared agent to your credentials (noted in `ENTERPRISE_READINESS.md` §5).
- Keep the **"For authorized use only"** notice prominent (it is, on login/sign-up).

## 4. Contractual protections (now in your Terms)
- "AS IS"/no-warranty, **no-reliance / not professional advice**, AI-accuracy
  disclaimer, **limitation of liability** (capped), **indemnification** (user covers
  claims from their use, incl. unauthorized scanning), and **binding arbitration +
  class-action waiver** with a 30-day opt-out and an informal-resolution step.
  - *Note:* arbitration/class-waiver enforceability varies by state and by how it's
    presented; it's a strong tool but have counsel confirm it for your jurisdiction.
- **Consent at sign-up** is affirmative and unchecked-by-default (no dark pattern —
  the FTC penalizes pre-checked/forced consent). For a tamper-proof, server-recorded
  consent trail, also enable your identity provider's built-in legal-consent feature
  pointing at `/terms` and `/privacy`.

## 5. If/when you charge money (Negative Option / "Click-to-Cancel" Rule, Oct 2024)
Applies to **auto-renewing subscriptions and free trials — including B2B**:
- Disclose all material terms (price, renewal cadence) **before** taking payment info.
- Get **informed consent** to the recurring charge separately.
- Make cancellation **as easy as sign-up** (same channel, similar steps).
- Don't trap users in retention offers — take "no" and cancel immediately.
- Use a reputable payment processor; don't store full card numbers.

## 6. Other
- **COPPA / minors** — Service is 18+, not directed to children (stated). Don't
  knowingly collect data from minors.
- **International (GDPR/UK/CCPA)** — if you take EU/UK or California users, you owe
  additional rights (access/delete/portability) and possibly a DPA with
  subprocessors. The Privacy Policy gestures at these; formalize if you go there.
- **Keep `LAST_UPDATED` current** and notify users of material changes (the docs
  promise this).

## 7. Prioritized checklist
- [ ] **Form an LLC; run everything through it.** (biggest personal-asset shield)
- [ ] **Get Tech E&O + Cyber liability insurance.**
- [ ] Have a lawyer review the Terms, Privacy Policy, and the arbitration clause.
- [ ] Set `GOVERNING_LAW` (and `COMPANY` once incorporated) in `dashboard/src/legal.ts`.
- [ ] Write an incident-response / breach-notification plan.
- [ ] Re-add a scan-authorization attestation + abuse monitoring (CFAA defense).
- [ ] Keep the Privacy Policy in sync with actual data practices as code changes.
- [ ] Maintain a subprocessor list (identity provider, hosting/DB, AI providers).
- [ ] Before charging: implement Click-to-Cancel-compliant billing.
- [ ] Don't make absolute security/accuracy/AI claims anywhere in marketing.

## Sources (FTC, current)
- Privacy & Security business guidance — https://www.ftc.gov/business-guidance/privacy-security
- Start with Security: A Guide for Business — https://www.ftc.gov/business-guidance/resources/start-security-guide-business
- Keep your AI claims in check — https://www.ftc.gov/business-guidance/blog/2023/02/keep-your-ai-claims-check
- Operation AI Comply (2024) — https://www.ftc.gov/business-guidance/blog/2024/09/operation-ai-comply-continuing-crackdown-overpromises-ai-related-lies
- Click-to-Cancel / amended Negative Option Rule (2024) — https://www.ftc.gov/business-guidance/blog/2024/10/click-cancel-ftcs-amended-negative-option-rule-what-it-means-your-business
