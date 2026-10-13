# Cyber Verification Program use case

Prepared on 2026-10-13 (Asia/Seoul). This describes proposed use of Anthropic's
Cyber Verification Program (CVP), not membership, endorsement, or an application
that has been submitted.

## Applicant and intended access

The applicant is an individual developer beginning a public security research
portfolio with Patchproof. Their connected public GitHub account is
[lejw9910-svg](https://github.com/lejw9910-svg). They report no existing public
security or open-source research track record. A connected account is not proof
of vulnerability disclosures, maintainership, legal identity, or CVP verification.

The current [CVP help article](https://support.claude.com/en/articles/14604842-cyber-verification-program)
says individuals may apply for **Defense Access on a paid plan**; Red Team and
Specialized Access are for organizations. The
[October 6 announcement](https://www.anthropic.com/news/cyber-verification-program)
includes individual researchers with a track record of reported vulnerabilities
among examples of qualifying defenders. The applicant's missing track record is
a material evidence gap. The sources do not establish that a starter repository
alone will qualify, and this project cannot estimate an approval probability.
Both sources were accessed on 2026-10-13 (Asia/Seoul).

## Research question and defensive scope

Can explicit baseline reproduction, independent observations of relevant side
effects, and normal-behavior controls distinguish a useful patch from a change
that merely suppresses the visible symptom?

Patchproof starts with four synthetic, local vulnerability classes: path
traversal, unsafe deserialization, caller-controlled authorization, and SQL
injection. It compares a known vulnerable baseline with a candidate patch against
a fixed corpus. It records failures and execution errors separately from a safe
result. The [research plan](research-plan.md) defines the evaluation and its
limits; the [authorization policy](authorization-policy.md) restricts execution
to reviewed local fixtures and explicitly authorized work.

The intended Claude workflow is to discuss an authorized reproduction, propose
a candidate repair, and reason about missed defensive cases. A person reviews
the candidate before local execution. An offline prompt package supports that
manual process; it does not contact Claude or demonstrate model performance.
See the [workflow](claude-workflow.md) for steps and provenance records.

## Why request CVP rather than assume it is necessary?

The official help article explicitly permits ordinary secure code review,
patching known issues, threat modeling, and vulnerability finding in owned source
code on generally available Claude. Much of this starter fits those uses today.
The possible CVP need is the narrower step of authorized exploit validation:
reasoning about a reproduction well enough to show that a repair blocks the
demonstrated bad behavior while keeping legitimate behavior intact. The same
article identifies exploit validation as work that may encounter safety blocks.

No live Claude experiment or blocking event is evidenced in this repository.
The application therefore proposes a use case and does not claim an observed
need for reduced blocking. If a future permitted experiment is blocked, record
its exact scope and response truthfully and use the official support or appeal
route. Do not manufacture a refusal or attempt to evade a safeguard.

## Evidence and boundaries

The [verification report](../reports/application/verification.json) and
[benchmark report](../reports/application/benchmark.json) are local development
evidence. The benchmark contrasts reference patches with curated incorrect
mutations; it is not a live Claude evaluation, a representative sample of real
vulnerabilities, or independent validation. Evidence bundles retain source and
manifest snapshots and checksums; integrity checks are unsigned and do not prove
authorship. The [application draft](cvp-application.md) separates these artifacts
from unverified account controls and future plans.

An individual grant would be used only by the applicant. Patchproof will not use
CVP access to provide a customer-facing service, process a customer's systems,
share an account, or expose a model session through an application without the
separate approval described in the official help article. Publishing this local
tool does not itself grant other users CVP access.

The [individual security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements)
include identity-provider sign-in, MFA, retained and monitored traffic, and
incident obligations. The [control register](security-controls.md) records what
is evidenced and what needs private verification. Requirements were accessed on
2026-10-13 (Asia/Seoul) and must be rechecked before attestation.
