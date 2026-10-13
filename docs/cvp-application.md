# CVP application draft — individual Defense Access

Prepared on 2026-10-13 (Asia/Seoul). **Not submitted.** Adapt this narrative to the
current portal fields. It intentionally contains no assumed legal name, employer,
client history, vulnerability disclosure, or account-security attestation.
Complete identity verification only through the official portal; do not commit
identity documents or authentication evidence to this repository.

## Short project description

Patchproof is my local Python research project for checking whether a repair
blocks a reproduced vulnerability while preserving legitimate behavior. It uses
four synthetic labs and explicit baseline, patched, and regression expectations.
The current local evaluation passed 109 tests, verified 44 cases, accepted four
reference patches, and rejected 13 curated incorrect candidates. One case study
shows why returning a denial after unsafe deserialization is insufficient; an
independent audit observation detects that behavior. These are findings about
this development corpus, not third-party vulnerability disclosures. I propose
using Claude for authorized reproduction analysis and candidate repairs, with
human review before execution. No live Claude experiment or blocking event has
been recorded. I am an individual beginning a research portfolio, without an
existing public security research track record, seeking consideration for Defense
Access.

## Applicant background

I am an individual developer starting a security research portfolio with
Patchproof, a local Python tool for testing whether a patch addresses a reproduced
vulnerability while preserving expected behavior. My public GitHub account is
[lejw9910-svg](https://github.com/lejw9910-svg). I do not currently have a public
track record of security disclosures or open-source security research to present.

I am presenting a reproducible starter project and a proposed research plan. I
am not claiming prior CVEs, bug bounty findings, client engagements, maintained
security projects, or CVP membership. My public profile is a portfolio reference,
not proof of legal identity or program verification.

## Work I propose to perform

My initial work uses four synthetic local labs covering path traversal, unsafe
deserialization, authorization bypass, and SQL injection. For each candidate
patch, I check that the baseline reproduces the expected bad behavior, the patch
produces the specified safe behavior, and ordinary cases continue to work. I also
evaluate deliberately incomplete fixes to find weaknesses in the verifier itself.

The research question is whether observable behavioral evidence catches repairs
that only hide a symptom or break normal functionality. Results will be reported
with case-level evidence, source identities, failures, and limitations. I intend
to publish reproducible methods using synthetic data and, if I later work on
another project, only within its documented authorization and disclosure rules.
The current repository is not evidence of production vulnerability discoveries.

## Proposed Claude use and reason for applying

I propose to use Claude manually to reason about authorized local reproductions,
suggest candidate repairs, and identify useful defensive regression cases. I
will review any proposed code before running it locally and keep the verification
expectations fixed during candidate evaluation. Patchproof prepares an offline
prompt package; it does not call Claude or carry model credentials.

I understand that general Claude already supports secure code review, threat
modeling, known-issue patching, and vulnerability finding in owned source code.
The CVP use case I would like considered is authorized exploit validation: working
through a reproduction to determine whether a defensive patch addresses it.
I have not yet documented a Claude blocking event or completed a live Claude
evaluation for this project. I therefore present this as a proposed workflow,
not proof that general access is insufficient.

I am applying as an individual for Defense Access only. I understand that a paid
plan is required for an individual application and that my lack of an established
research record may limit qualification. I do not request organizational Red Team
or Specialized Access.

## Scope and safeguards

I will keep the initial work limited to the repository's synthetic local labs,
using no production credentials, personal data, or external targets. The runner
has execution bounds but does not isolate arbitrary code from the host; every
candidate requires human review before execution. I will not use access to test
systems outside my authorization or to provide a client-facing product or
service without separate approval.

The grant would be personal to me. I understand that individual CVP traffic is
retained and monitored and that zero data retention is unavailable. I will verify
the required account controls before making an attestation, including identity-
provider sign-in and MFA, the December 15, 2026 transition to phishing-resistant
MFA and away from static model credentials, and the incident/cooperation duties.
This draft does not assert that those controls are already enabled.

## Evidence accompanying the draft

The current local run on Python 3.12.14 passed **109 tests** and verified **44
cases across four labs: 9 attack cases and 35 regression cases**. The curated
benchmark accepted **4/4 reference patches** and rejected **13/13 incorrect
candidates**, with zero false acceptances, false rejections, execution errors,
or inconclusive results in those 17 evaluations. The evidence bundle passed an
internal checksum check for **26 files**. These counts describe this fixed
synthetic corpus; they are not population-level security metrics or a hosted CI
run. See the [machine-readable summary](../reports/application/summary.json) and
[test log](../reports/application/tests.txt).

The [deserialization case study](case-studies/false-safe-deserialization.md)
documents a weakness found in Patchproof's own test oracle: a candidate could
deserialize first and return the expected denial afterward. The current worker
observes the relevant Python audit event separately and rejects that candidate.
The before/after policy comparison uses the same recorded executions, not an
invented historical experiment. This is local verifier research, not a
third-party vulnerability finding or a Claude result.

- [Local verification](../reports/application/verification.json): observed
  behavior on the synthetic corpus, not real-world discovery history.
- [Curated mutation benchmark](../reports/application/benchmark.json): checks of
  the verifier against selected reference and incorrect candidates, not Claude
  capability or CVP eligibility measurements.
- [Research plan](research-plan.md): evaluation questions, limitations,
  and a 30-day plan.
- [Evidence integrity](../reports/application/integrity.json): unsigned internal
  checksum verification; not proof of origin or an independent reproduction.
- [Authorization policy](authorization-policy.md),
  [control register](security-controls.md), and
  [manual Claude workflow](claude-workflow.md).

Repository URL: **pending publication or confirmation**. Replace this text with
the actual URL only when the reviewed revision is available there. Before
submission, open every evidence link and verify that its contents match that
revision. A connected GitHub identity is not a substitute for a published project
or verified research record.

## Private completion steps

Confirm the paid plan, identity-provider sign-in, MFA settings, sole-user access,
and required credential posture. Review the current portal and security terms;
attest only to controls actually in place. Enter the real applicant identity and
contact details in the portal. If a field requests work history or findings,
state that none are available rather than substituting these synthetic labs.

Official sources, accessed 2026-10-13 (Asia/Seoul):
[CVP eligibility and permitted uses](https://support.claude.com/en/articles/14604842-cyber-verification-program),
[October 6 program announcement](https://www.anthropic.com/news/cyber-verification-program),
and [security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements).
Apply only through the [Verification Portal](https://portal.anthropic.com/programs).
These sources do not guarantee approval.
