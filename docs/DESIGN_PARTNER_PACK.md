# NetLogic — Design Partner Pack

> **Not legal advice.** These are good-faith templates to reduce risk and to brief a
> lawyer efficiently, not a substitute for one. Before you send any of this to a real
> business, do the two things in `LEGAL_COMPLIANCE.md` §0: **form an LLC** and **buy
> E&O + cyber liability insurance**. Until you incorporate, you are signing these as an
> individual and your personal assets are the backstop. Have a licensed attorney review
> the agreement before a counterparty signs it.

This pack has four pieces:
1. Design Partner Agreement (the contract)
2. Scan Authorization & Scope form (the CFAA-critical piece)
3. The pitch email
4. How to actually find partners + the honest take on cold outreach

---

## 1. Design Partner Agreement (template)

**NETLOGIC DESIGN PARTNER / BETA AGREEMENT**

This Design Partner Agreement (the "Agreement") is between [LEGAL ENTITY NAME, e.g.
NetLogic LLC] ("NetLogic", "we") and [PARTNER COMPANY] ("Partner", "you"), effective on
the date last signed below ("Effective Date").

**1. Purpose.** NetLogic provides an AI-assisted attack-surface scanner (the "Service").
Partner agrees to evaluate the Service during a beta period and provide feedback.

**2. Beta status; AS-IS.** The Service is pre-release. It is provided **"AS IS" and "AS
AVAILABLE," without warranties of any kind**, express or implied, including
merchantability, fitness for a particular purpose, accuracy, or non-infringement.
NetLogic does not warrant that the Service will detect all vulnerabilities, that its
findings are accurate or complete, or that it will be uninterrupted or error-free.
Findings are **informational** and are not a guarantee of security.

**3. Authorization to scan (critical).** Partner may use the Service **only** against
systems, domains, and IP ranges that Partner owns or is contractually authorized to
test, as listed in the Scan Authorization form (§2 of this pack). Partner represents
and warrants it has all rights and authorizations necessary to permit scanning of those
targets, and Partner is solely responsible for the consequences of scanning any target
it lists. Partner will not direct the Service at third-party systems without written
authorization from that third party.

**4. Term and termination.** This Agreement runs for [90] days and may be ended by
either party on [7] days' written notice. Sections 2, 5, 6, 7, 8, and 9 survive
termination.

**5. Fees.** The beta is provided at no charge. No commitment to purchase is created.

**6. Confidentiality (mutual).** Each party may receive the other's non-public
information ("Confidential Information"), including, for Partner, its scan results and
network data, and for NetLogic, the Service's non-public features and roadmap. The
receiving party will use Confidential Information only to perform under this Agreement,
protect it with reasonable care, and not disclose it to third parties except to its
personnel and subprocessors with a need to know. This survives [2] years after
termination.

**7. Data handling.** NetLogic will process Partner scan data only to provide the
Service, will not sell it, and will not use it to train models or for marketing without
Partner's separate opt-in consent. NetLogic encrypts stored secrets at rest and isolates
Partner data per organization. NetLogic's subprocessors are listed at [LINK / on
request]. On termination, NetLogic will delete Partner scan data within [30] days on
written request.

**8. Limitation of liability.** **To the maximum extent permitted by law, neither party
is liable for indirect, incidental, special, consequential, or punitive damages, or lost
profits or data. NetLogic's total aggregate liability arising out of or relating to this
Agreement will not exceed US $100.** Because the beta is provided free, this cap reflects
the parties' allocation of risk.

**9. Indemnity.** Partner will defend and indemnify NetLogic against claims arising from
Partner scanning targets it was not authorized to scan, or from Partner's breach of §3.

**10. Feedback.** Partner grants NetLogic a perpetual, royalty-free license to use
feedback Partner provides to improve the Service. Partner is not obligated to give
feedback.

**11. Publicity.** Neither party will use the other's name or logo publicly without prior
written consent. (If you later want to cite them as a design partner, get this in
writing separately.)

**12. Governing law.** This Agreement is governed by the laws of [STATE], without regard
to conflict-of-law rules. Venue lies in the state and federal courts located in [COUNTY,
STATE].

**13. Entire agreement.** This Agreement and its Scan Authorization form are the entire
agreement and supersede prior discussions.

NETLOGIC: __________________________  Date: __________
PARTNER:  __________________________  Date: __________

---

## 2. Scan Authorization & Scope (template)

> This is the piece that keeps a security scan on the right side of the **Computer Fraud
> and Abuse Act**. Never scan a target a partner has not listed and signed off on here.

**SCAN AUTHORIZATION** — attached to and part of the Design Partner Agreement dated
__________ between NetLogic and [PARTNER COMPANY].

Partner authorizes NetLogic's Service to scan the following targets, which Partner
represents it owns or is contractually authorized to test:

| # | Target (domain / IP / CIDR) | Owned or authorized? | Notes / window |
|---|------------------------------|----------------------|----------------|
| 1 |                              |                      |                |
| 2 |                              |                      |                |

- Authorized scan window: [dates / "anytime during beta"]
- Off-limits assets (do not scan): ______________________________
- Partner technical contact (for scan alerts): __________________
- Partner confirms the listed IP ranges are not hosted on third-party infrastructure
  whose provider's terms prohibit scanning (e.g. some cloud providers require notice).

Signed (Partner, authorized signer): __________________  Title: ______  Date: ______

---

## 3. Pitch email (your voice, personal-project framing)

This is the version to use right now: a personal project, free, looking for feedback. No
company, no signed contract, just a short disclaimer in the email itself.

**Subject:** built a security scanner as a side project, want to try it?

> Hi [Name],
>
> I'm Dmitry. I've been building a side project called NetLogic, an attack-surface
> scanner that finds what's exposed on a network and tries to tell you what's actually
> exploitable instead of burying you in false positives.
>
> Most scanners flag a vuln any time a version might be affected, so you end up
> triaging hundreds of maybes. Mine confirms the certain stuff first and only uses AI on
> the genuinely ambiguous findings, so the report is shorter and more honest.
>
> It's not a company and it's free, I'm just looking for a few people to run it against
> their own stuff and tell me what's useful and what's missing. You'd only point it at
> assets you own or control, and it's provided as-is, the findings are informational and
> not a guarantee that anything is or isn't secure.
>
> Want to give it a shot? I can send you a sample report first if that's easier, or hop
> on a quick call.
>
> Thanks,
> Dmitry
> dmitryflynn665@gmail.com

Keep it honest: no "finds all vulnerabilities," no "guarantees security." That language is
both untrue and a legal problem if you ever do turn this into a company.

---

## 3b. Lightweight consent (personal-project version)

You don't need the full agreement in §1 for a free personal project. The disclaimer in
the email above plus this one-liner before someone scans is enough to set expectations.
Keep the full §1 agreement for when this becomes a paid company.

> By using this tool you confirm you'll only scan systems you own or are authorized to
> test. It's a personal project provided as-is, with no warranty; findings are
> informational and not a guarantee of security. I won't sell your scan data or use it
> for anything besides improving the tool.

Put that on the sign-in screen / first-run, or paste it in the email. That's the whole
"legal stuff" you need at the personal-project stage. The heavy machinery (LLC,
insurance, signed agreement) only becomes necessary when money changes hands.

---

## 4. Finding partners + the honest take on cold outreach

**Who to target first (warm beats cold every time):**
- People you already know who run IT/security at a small or mid-size company.
- Local Seattle/Kirkland businesses with an internal IT person (MSPs, dev shops,
  fintech/health startups who care about their external surface).
- Founders in your network whose companies have a public footprint to scan.
- Security communities you're already in (bug-bounty contacts, local OWASP chapter,
  infosec Discords/Slacks) where "I built a scanner, want to try it" is welcome.

**On sending the emails:** as a personal project the bar is low and the framing is honest,
so this is mostly fine. Two practical guardrails:
- **Warm beats cold.** A personal "I built a thing, want to try it?" lands best with
  people who already know you. Cold-emailing total strangers from your Gmail is still
  low-yield and can ding your email reputation, so keep volume small and personal.
- **You pick the recipients and hit send.** Sending real email to real people is
  irreversible, so I'll draft and prep individual messages, but you review and send each
  one. That way a wrong name or wrong company never goes out under your name.

**The path I'd recommend:** build a list of 5-10 people you have some connection to, I'll
prep an individual Gmail draft for each (personalized, not a blast), you skim and send.
