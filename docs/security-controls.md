# Individual security control register

Assessment date: 2026-10-13 (Asia/Seoul). This is an evidence register and a
preparation procedure, **not a compliance attestation**. Account configuration
has not been inspected. A written policy or a passing local test does not prove
that an account control is enabled.

## Evidence in this repository

| Control or property | Evidence | Scope and limit |
| --- | --- | --- |
| Synthetic local initial scope | `labs/`, [authorization policy](authorization-policy.md) | Does not prove authorization for another project. |
| Bounded subprocess execution | `src/patchproof/sandbox.py`, tests, [threat model](threat-model.md) | No hostile-code, filesystem, or network isolation. |
| Explicit verification expectations | Lab manifests and [verification report](../reports/application/verification.json) | Covers the included corpus; not a security guarantee. |
| Checks against selected bad repairs | [Benchmark report](../reports/application/benchmark.json) | Curated development evidence; not independent or population-level validation. |
| Manual model workflow | [Claude workflow](claude-workflow.md) | Offline preparation; no live model call or account-control verification. |
| Disclosure and incident guidance | [SECURITY.md](../SECURITY.md), procedure below | Documented process; no completed incident exercise claimed. |

## Individual Defense Access requirements

The following requirements come from section 3, “Defense Access for Individuals,”
of the [official security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements),
accessed 2026-10-13 (Asia/Seoul). That section imports Incident Reporting,
Cooperation, and Ongoing Review from “All Access Levels.” Organization-only Red
Team and Specialized Access controls are not presented here as individual
requirements.

| Requirement | Timing | Current evidence | Private evidence to obtain |
| --- | --- | --- | --- |
| Sign in through Google or an equivalent identity provider | From grant | Unverified | Confirm the sign-in route and grant-holding account. |
| MFA enabled on that account | From grant | Unverified | Check active factors and recovery settings. |
| Phishing-resistant MFA; no email magic-link sign-in | By 2026-12-15 | Unverified | Confirm security key, passkey, or smartcard/PIV and the actual sign-in route. SMS, voice, emailed codes, authenticator-app codes, and push approvals do not qualify. |
| No static or long-lived model credentials, including API keys | By 2026-12-15 | Account state unverified; this workflow needs no key | Confirm OAuth for Claude Code, Claude Console, and claude.ai; WIF for programmatic workloads where offered. Check removal of any old keys. |
| Interim API key restrictions, if using one | Until cutoff | No use asserted | At most one key, stored in a password manager or local secrets store, never shared or put in source, replaced at least every 7 days. |
| Sole personal use; no shared account, session, or session-exposing proxy/extension | Throughout grant | Intended use only; not verified | Review account sessions and any integrations. |
| All grant traffic retained and monitored; no zero data retention | Throughout grant | Source requirement understood; no grant observed | Accept applicable terms and keep sensitive material out of requests. |
| Report suspected breach/misuse within 72 hours, or security incident within 24 hours | On incident | Procedure drafted below | Keep a private contact route and incident record; rehearse response. |
| Investigate identified abuse within 48 hours, cooperate on remediation, answer misuse inquiries within 7 days | On notification | Procedure drafted below | Be able to receive notices and record response times. |
| Supply evidence for ongoing review when requested | Throughout grant | Account evidence pending | Maintain current private records without committing secrets or identity documents. |

Paid-plan status and identity verification are separate eligibility checks under
the [CVP help article](https://support.claude.com/en/articles/14604842-cyber-verification-program)
(accessed 2026-10-13, Asia/Seoul); neither is established by this repository.
The source specifies retention and monitoring for individuals but this document
does not invent a retention duration or extend organizational ZDR exceptions to
individuals.

## Proposed individual incident procedure

1. Stop the affected model workflow and record the time of discovery privately.
   Revoke or suspend affected sessions or credentials using the provider's
   available controls. Preserve relevant evidence without copying secrets into
   an issue or public repository.
2. Report suspected breach or misuse involving the grant to
   **security@anthropic.com** or the account-team contact within **72 hours**;
   for a security incident, report within **24 hours**. These are the official
   deadlines. If classification is unclear, use the shorter deadline as the
   operator's conservative procedure. Include scope, times, containment actions,
   and a safe way to follow up; do not delay an initial report for a complete
   investigation.
3. Investigate abuse identified by Anthropic within **48 hours**, work with
   Anthropic on remediation, and respond to misuse inquiries within **7 days**.
   Record notices and responses privately.
4. Review the cause and affected authorization boundary before resuming the
   workflow. Update relevant controls and provide evidence when requested.

This procedure has not been exercised as part of the current project. Listing
Anthropic's official reporting address does not create a contact channel for
vulnerabilities in Patchproof; those follow [SECURITY.md](../SECURITY.md).

## Evidence handling

Keep identity documents, unnecessary legal identity details, account screenshots
containing identifiers, recovery codes, credentials, and incident transcripts
outside the repository. Supply required identity evidence only through the
official portal or a verified secure channel. A sanitized public record may
state the control, verification date, and reviewer without revealing secrets.

Recheck the current requirements before submission and before the December 15
cutoff. An unchecked control remains unverified even when its implementation is
planned. Do not mark the applicant “CVP compliant” based on repository controls.
