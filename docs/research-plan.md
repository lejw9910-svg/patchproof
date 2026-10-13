# Patch verification research plan

Prepared on 2026-10-13 (Asia/Seoul). This is a 30-day plan for an individual
beginning a research portfolio. It is not a claim of completed discoveries,
published findings, independent review, or live model evaluation.

## Questions and hypotheses

**H1:** The verifier accepts the four included reference patches and rejects the
curated incorrect candidates while keeping execution errors separate from
behavioral rejections.

**H2:** Regression controls expose repairs that disable legitimate functionality,
and independent observation of a security-relevant side effect exposes a repair
that performs the unsafe operation before returning a safe-looking response.

**H3, future model experiment:** A candidate proposed through a manual Claude
workflow can be evaluated against a frozen corpus without giving the prompt the
reference patch or the manifest's expected answers. No result for H3 is claimed.

These questions organize an existing development evaluation; H1 and H2 were
not preregistered before building this corpus. Future reserved evaluation cases
should be defined before generating new candidates.

## Current observations

The [recorded local run](../reports/application/summary.json) on Python 3.12.14
passed 109 tests and verified 44 cases (9 attack, 35 regression) across four labs.
The benchmark accepted all four reference patches and behaviorally rejected all
13 curated incorrect candidates. It recorded no false acceptances, false
rejections, execution errors, or inconclusive evaluations. These observations
support H1 only for the chosen corpus; they cannot establish a general error rate.

For H2, the [deserialization case study](case-studies/false-safe-deserialization.md)
records a candidate that reconstructs the unsafe object and then returns a denial.
Returned values alone would accept it; the separately observed class-resolution
event causes rejection. This is a counterfactual policy comparison of the same
executions, not a historical before/after run or a model experiment. The observation
does not cover every deserialization operation, subprocess, or hostile tampering.

## Design and measurement

The initial unit is a **candidate for one lab**. Four synthetic vulnerability
classes provide the corpus: path traversal, insecure deserialization,
authorization bypass, and SQL injection. Reference patches are positive controls.
Curated incorrect candidates include unchanged vulnerable behavior, repairs that
break normal behavior, and selected incomplete fixes.

Before an evaluation, freeze and record the source, manifest, candidate identities,
and execution settings. Keep the corpus unchanged while evaluating a candidate.
If a failure reveals a gap in the verifier, record the initial result and the
reason for a subsequent version; do not silently rewrite the original outcome.

Report these counts separately, with denominators:

- Reference patches accepted and unexpectedly rejected.
- Incorrect candidates behaviorally rejected and incorrectly accepted.
- Candidates producing errors or inconclusive results; these do not count as
  successful detection of a bad repair.
- Attack and regression cases executed, including their actual observations.

Any rate is descriptive of this fixed corpus. An observed false acceptance rate
uses incorrect candidates accepted divided by incorrect candidates attempted,
alongside separate error and inconclusive counts. Do not omit an error from a
chart without stating its treatment. A zero observed count is not proof that
the underlying risk is zero.

## Reproduce the local evidence

From the installed repository root:

```sh
python -m patchproof verify --format json --output reports/application/verification.json --bundle reports/application/evidence.zip
python -m patchproof check-bundle reports/application/evidence.zip
python -m patchproof benchmark --format json --output reports/application/benchmark.json
python -m patchproof benchmark --output reports/application/benchmark.md
```

The [verification artifact](../reports/application/verification.json) and
[benchmark artifact](../reports/application/benchmark.json) record local runs.
The bundle retains source, manifest, engine, and report material with checksums.
`check-bundle` checks internal integrity; it does not validate an external
signature, prove origin, or independently establish that every reported
execution occurred. Preserve a reviewed revision alongside the artifacts.

## Evidence gaps and limitations

During development, review identified a reproduction gap in the earlier report
format: hashes and diffs alone could not reconstruct all executed source and
manifest material. The evidence bundle addresses that packaging gap. It remains
unsigned, and a separately completed independent reproduction is not claimed.

The fixtures, reference patches, and mutations are authored together. This makes
the benchmark useful for development and vulnerable to selection bias and
overfitting. It has no independent held-out corpus, no representative sampling of
real applications, and no basis for statistical claims about all vulnerabilities.
Deterministic repeat runs check reproducibility; they do not increase the number
of independent research examples. A candidate can also be written specifically
to recognize public cases, so passing is not a security proof.

The runner does not contain malicious code or block host filesystem/network
access. Independent fixture observations improve the test oracle within the
trusted-fixture model; they do not turn it into a tamper-proof execution boundary.
See the [threat model](threat-model.md) and [methodology](research-methodology.md).

The offline prompt workflow is not a blinded model study: the repository and its
reference implementations may be public, and training-data exposure is unknown.
Omitting the reference patch and expected answers from the prepared prompt only
reduces direct answer leakage in that prompt. No live Claude runs, refusal rates,
model comparisons, or CVP approval probabilities are established by these data.

## Thirty-day schedule

Day 1 is the day the researcher starts this plan; dates are not claimed as
completed milestones.

| Days | Work | Reviewable deliverable |
| --- | --- | --- |
| 1–7 | Reproduce current local results; review authorization and account-control gaps; document verifier failures found during development. | A versioned baseline, complete local reports, and an honest evidence register. |
| 8–14 | Add cases motivated by identified blind spots; reserve new evaluation cases before testing new candidates; seek review from an available maintainer or researcher. | Rationale for each added case and, only if obtained, attributed review feedback. |
| 15–21 | If access and account requirements are satisfied, conduct a small manual Claude experiment on authorized synthetic inputs. Record every attempt and failure; if none is performed, retain the offline protocol and say so. | Candidate provenance, unchanged evaluation corpus, exact outcomes, and any genuine blocking evidence. |
| 22–30 | Reproduce final results from the recorded revision; write a short report separating measurements from open questions; prepare an application only with verified facts. | A reproducible research note and updated application/control register. |

A paid general Claude plan may be sufficient for the proposed code-review and
known-patch work. The narrower potential CVP need is authorized exploit validation,
which the [official help article](https://support.claude.com/en/articles/14604842-cyber-verification-program)
identifies as work that may be blocked (accessed 2026-10-13, Asia/Seoul). A future
blocked attempt should be reported accurately through official channels, not
worked around. Progress under this plan does not guarantee CVP acceptance.

External project work begins only with recorded scope and authorization; no
external scanning, customer-facing model service, or unannounced disclosure is
part of this plan. Use synthetic examples until those conditions are satisfied.
