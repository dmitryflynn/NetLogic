/**
 * Terms of Service + Privacy Policy content.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * OPERATOR ACTION REQUIRED BEFORE LAUNCH:
 *   • Set the constants below to your real legal entity, contact address, and
 *     governing jurisdiction.
 *   • Have these documents reviewed by qualified legal counsel. They are a
 *     good-faith, FTC-aligned starting template (truthful/clear/conspicuous
 *     disclosure, affirmative consent, authorized-use terms for a scanner) —
 *     they are NOT legal advice and do not substitute for counsel.
 *   • Keep LAST_UPDATED current whenever you change either document, and notify
 *     users of material changes (see the "Changes" sections).
 * ─────────────────────────────────────────────────────────────────────────────
 */

// "NetLogic" is operated by an individual (no registered company yet), so the
// docs intentionally avoid implying an incorporated entity. When you register a
// company, update COMPANY to the legal entity name. Set GOVERNING_LAW to your
// actual state/country of residence before launch — it is a placeholder now
// rather than a fabricated jurisdiction.
export const COMPANY = 'NetLogic'
export const CONTACT_EMAIL = 'dmitryflynn665@gmail.com'
export const GOVERNING_LAW = '[your state/country — set before launch]'
export const LAST_UPDATED = 'June 22, 2026'

export const TERMS_MD = `# Terms of Service

**Last updated: ${LAST_UPDATED}**

These Terms of Service ("Terms") are a binding agreement between you and ${COMPANY}
("we", "us") governing your access to and use of the ${COMPANY} attack-surface
scanning service, dashboard, APIs, and related software (the "Service"). By
creating an account or using the Service, you agree to these Terms. If you do not
agree, do not use the Service.

## 1. Eligibility
You must be at least 18 years old and able to form a binding contract. If you use
the Service on behalf of an organization, you represent that you are authorized to
bind that organization, and "you" includes that organization.

## 2. The Service
The Service performs network and application security scanning, vulnerability
correlation, and AI-assisted analysis of targets that you specify. Results are
informational only and are provided to help you assess security posture.

## 3. Authorized use only — your core responsibility
**You may scan only systems, networks, domains, and assets that you own or for
which you have explicit, current authorization to test.** You represent and
warrant that, for every target you submit, you have such authorization. You are
solely responsible for obtaining it and for your use of the Service.

Unauthorized scanning may violate law — including the U.S. Computer Fraud and
Abuse Act (CFAA), comparable state and foreign laws, and third-party terms. You
agree not to use the Service to access, probe, or attack any system without
authorization. We may suspend or terminate access if we reasonably suspect
unauthorized or abusive use, and we may preserve and disclose records as required
by law (see the Privacy Policy).

## 4. Acceptable use
You will not: (a) use the Service for any unlawful purpose; (b) scan or attack
third-party systems without authorization; (c) use scan results to facilitate an
attack, intrusion, or other harm; (d) interfere with or disrupt the Service or
circumvent its security, rate limits, or tenancy boundaries; (e) resell or
provide the Service to third parties except as expressly permitted; or (f)
misrepresent your identity or authorization.

## 5. Accounts and credentials
You are responsible for safeguarding your account credentials and for all activity
under your account. Authentication is provided through our identity provider.
Notify us promptly of any unauthorized use.

## 6. API keys and third-party AI providers
If you configure a third-party AI/LLM provider key for analysis, you authorize us
to use it to transmit relevant scan data to that provider on your behalf, and you
agree to that provider's terms. You are responsible for your provider keys and any
charges they incur. We encrypt stored provider keys at rest and never display them
again after entry.

## 7. Intellectual property
We retain all rights in the Service and its software. You retain rights in the
data you submit and the reports generated for you. You grant us a limited license
to process your data solely to provide and improve the Service, consistent with
the Privacy Policy.

## 8. Disclaimers
THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTIES OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
AND NON-INFRINGEMENT. Security scanning is inherently imperfect: findings may
include false positives or miss real issues, and a clean result is **not** a
guarantee that a system is secure. You remain responsible for your own security
decisions.

**Not professional advice; no reliance.** The Service and its output are provided
for informational purposes only and do not constitute professional, security,
legal, or compliance advice. You should not rely on any result as a definitive
statement of your security posture, and you are responsible for independently
verifying findings and exercising your own professional judgment.

**AI-assisted analysis.** Some features use third-party large-language-model (AI)
systems to help summarize and prioritize findings. AI output can be incomplete,
inaccurate, or "hallucinated," may not reflect the most current information, and
is not a substitute for professional judgment. We do not warrant the accuracy or
completeness of AI-generated content, and you use it at your own risk.

## 9. Limitation of liability
TO THE MAXIMUM EXTENT PERMITTED BY LAW, ${COMPANY} WILL NOT BE LIABLE FOR ANY
INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR FOR LOST
PROFITS, DATA, OR GOODWILL. OUR TOTAL LIABILITY ARISING FROM OR RELATING TO THE
SERVICE WILL NOT EXCEED THE GREATER OF THE AMOUNT YOU PAID US IN THE 12 MONTHS
BEFORE THE CLAIM OR USD $100. Some jurisdictions do not allow these limits, so
they may not fully apply to you.

## 10. Indemnification
You will indemnify and hold ${COMPANY} harmless from any claims, losses, and
expenses (including reasonable legal fees) arising out of your use of the Service,
your data, or your breach of these Terms — including any claim that your scanning
was unauthorized.

## 11. Suspension and termination
You may stop using the Service at any time. We may suspend or terminate your
access for breach of these Terms, suspected abuse, or as required by law. Sections
that by their nature should survive termination (e.g., 3, 8–10) survive.

## 12. Changes to these Terms
We may update these Terms. For material changes we will provide reasonable notice
(e.g., in-app or by email) before they take effect. Continued use after the
effective date constitutes acceptance.

## 13. Dispute resolution; binding arbitration; class-action waiver
**Please read this section carefully — it affects your legal rights.**

We will try to resolve any dispute informally first: before filing a claim, you
agree to contact us at ${CONTACT_EMAIL} and give us 30 days to resolve it.

If we cannot resolve it, you and ${COMPANY} agree that any dispute arising out of
or relating to these Terms or the Service will be resolved by **final and binding
individual arbitration**, rather than in court, except that either party may bring
an individual claim in small-claims court. **You and ${COMPANY} waive any right to
a jury trial and to participate in a class, collective, or representative action.**
Arbitration will be conducted by a recognized arbitration provider under its
consumer/commercial rules. If this class-action waiver is found unenforceable, the
rest of this section will not apply to that claim.

You may opt out of this arbitration agreement by emailing ${CONTACT_EMAIL} within
30 days of first accepting these Terms.

## 14. Governing law
These Terms are governed by the laws of ${GOVERNING_LAW}, without regard to
conflict-of-laws rules. To the extent any dispute proceeds in court rather than
arbitration, venue lies in the courts located there, unless applicable law
requires otherwise.

## 15. Contact
Questions about these Terms: **${CONTACT_EMAIL}**.
`

export const PRIVACY_MD = `# Privacy Policy

**Last updated: ${LAST_UPDATED}**

This Privacy Policy explains what personal information ${COMPANY} ("we", "us")
collects, how we use and share it, and the choices you have. We aim to describe
our practices clearly and accurately, consistent with FTC guidance. By using the
Service you acknowledge this Policy.

## 1. Information we collect
- **Account information** — when you sign up, our identity provider collects your
  email address, name (if provided), and authentication identifiers (including
  OAuth/SSO identifiers if you use GitHub/Google/Microsoft sign-in).
- **Scan data you submit** — the targets you enter (hostnames, IP addresses, CIDR
  ranges), scan configuration, and the results we generate (open ports, detected
  services/versions, findings, and analysis).
- **Provider API keys** — if you configure a third-party AI/LLM key, we store it
  encrypted at rest and use it only to perform the analysis you request.
- **Usage and log data** — IP address, timestamps, request metadata, and audit
  events, used for security, abuse prevention, and operating the Service.
- **Payment information** — if you purchase a paid plan, payment is handled by a
  third-party payment processor; we do not store full card numbers.

## 2. How we use information
We use information to: provide, secure, and operate the Service; authenticate you;
run the scans and analysis you request; prevent fraud, abuse, and unauthorized
scanning; comply with legal obligations; and improve the Service. We do not use
the content of your scan results to train third-party models without your
configuration/consent.

## 3. How we share information
- **Service providers (subprocessors)** — our identity provider (authentication),
  hosting/database providers, and, **only when you enable AI analysis**, the
  third-party AI/LLM provider you configure (relevant scan data is sent to it to
  produce the analysis).
- **Legal and safety** — when required by law, legal process, or to investigate or
  prevent abuse, fraud, or threats to safety or the Service.
- **Business transfers** — in connection with a merger, acquisition, or asset sale,
  subject to this Policy.
- **We do not sell your personal information**, and we do not share it for
  cross-context behavioral advertising.

## 4. Data retention
We keep personal information for as long as your account is active and as needed
to provide the Service, then for a reasonable period to meet legal, security, and
operational requirements, after which we delete or anonymize it.

## 5. Security
We protect information with measures including encryption of secrets at rest,
encrypted transport (TLS), tenant isolation, access controls, and audit logging.
No method of transmission or storage is perfectly secure, so we cannot guarantee
absolute security.

## 6. Your choices and rights
You can access and update your account information, request a copy of your data,
or request deletion by contacting us. Depending on where you live (e.g., the EU/UK
or California), you may have additional rights to access, correct, delete, port,
or restrict processing of your personal information, and to appeal or lodge a
complaint with a regulator. We will not discriminate against you for exercising
these rights.

## 7. Cookies
We use strictly necessary cookies/local storage for authentication and session
management. We do not use advertising or cross-site tracking cookies.

## 8. Children's privacy
The Service is not directed to children and is intended for users 18 and older. We
do not knowingly collect personal information from anyone under 13 (or the
applicable minimum age in your jurisdiction). If you believe a child has provided
us information, contact us and we will delete it.

## 9. International transfers
We may process information in countries other than yours. Where required, we use
appropriate safeguards for cross-border transfers.

## 10. Changes to this Policy
We may update this Policy. For material changes we will provide reasonable notice
(e.g., in-app or by email) and update the "Last updated" date above.

## 11. Contact
Questions or privacy requests: **${CONTACT_EMAIL}**.
`
