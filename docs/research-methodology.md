# Research and verification methodology

## Start with a reproducible claim

Describe the affected behavior, preconditions, and expected safe behavior.
Confirm authorization, then reduce the issue to a local fixture using synthetic
data. Keep the vulnerable baseline and candidate patch separately reviewable.
The included labs make this distinction with `vulnerable.py` and `patched.py`.

For each attack case, record the input, explicit `expected_vulnerable` result,
and explicit `expected_patched` result in the lab manifest. Where a security
property requires an independent observation, include it instead of relying
only on the candidate's self-reported return value. A safe expectation
should describe a meaningful response, such as denial or treating input as
literal data. A crash or absent result is not evidence of a fix. Add regression
cases with expected ordinary behavior for both source versions.

## Execute and classify

Run each case against both implementations under the subprocess runner. It
uses fresh temporary state and bounds execution time and output. It does not
isolate hostile code from the host; only run reviewed, trusted fixtures.

Interpret the evidence as follows:

| Observation | Interpretation |
| --- | --- |
| Attack baseline, patched safe response, and both regression expectations match | Verification passes for this corpus. |
| A vulnerable baseline does not reproduce its expected behavior | Inconclusive: the case has not demonstrated that the patch addresses the stated issue. |
| A patched or regression expectation does not match | Verification fails. |
| A child crashes, times out, exceeds limits, or returns invalid protocol data | Execution error; do not count it as a blocked attack. |

When a run has multiple problems, inspect the per-case evidence rather than
relying on the aggregate label alone.

## Review the patch and evidence

Use the advisory AST analyzer to identify selected risky constructs and the
diff tool to inspect the change. Neither substitutes for verification or human
review. Compare report source hashes to the version under review, inspect every
unexpected result, and rerun after changing the implementation or corpus.

Reports contain the source differences and case evidence available to the
runner. They are reproducible development records, not signed attestations.
Reports record Python/platform details, execution limits, a UTC timestamp, and
the engine source hashes. Use `verify --bundle reports/evidence.zip` to retain
the corresponding source/manifest snapshots, and `check-bundle` to check unsigned
integrity. Preserve failures as well as successful runs when making a research
claim.

## Extend the corpus

Create a directory such as `labs/my-lab/` containing `manifest.json`,
`vulnerable.py`, and `patched.py`. Both Python files must be self-contained and
expose `run(payload, workspace: pathlib.Path)`, returning a JSON-compatible
value. Put temporary fixtures inside `workspace`. The verifier snapshots each
source file, then executes it in a new process and working directory for every
case; sibling imports and third-party packages are not available. Imports must
not depend on the current repository directory.

A minimal manifest has this shape:

```json
{
  "schema_version": 1,
  "id": "my-lab",
  "title": "Example access check",
  "cwe": "CWE-863",
  "cases": [
    {
      "id": "forged-role",
      "kind": "attack",
      "input": {"token": "user-token", "role": "admin"},
      "expected_vulnerable": {"allowed": true},
      "expected_patched": {"allowed": false}
    },
    {
      "id": "valid-admin",
      "kind": "regression",
      "input": {"token": "admin-token", "role": "admin"},
      "expected_vulnerable": {"allowed": true},
      "expected_patched": {"allowed": true}
    }
  ]
}
```

The lab identifier must match its directory name. Lab and case identifiers use
lowercase letters, digits, underscores, or hyphens, start with a letter or digit,
and are at most 80 characters. Case identifiers must be unique. Both attack and
regression cases are required; attack expectations must differ in returned
values or declared observations, and regression expectations must match. JSON
comparison preserves types, so
`true`, `1`, and `1.0` are different. Unknown manifest fields, duplicate JSON
keys, and non-finite numbers are rejected. The manifest is limited to 1 MiB,
256 cases, and 64 KiB per serialized case. The runner separately limits serialized
input to 64 KiB. JSON output must fit the per-execution output budget.

Optional `expected_vulnerable_observations` and `expected_patched_observations`
must be supplied together with the same nonempty set of known keys. Currently
the only supported key is `pickle_class_resolutions`, a nonnegative integer
count from the worker's `pickle.find_class` audit events. For example, an attack
can declare `{"pickle_class_resolutions": 1}` on the baseline and
`{"pickle_class_resolutions": 0}` on the patch. This observes the worker process
only and is not a security boundary against a hostile candidate. See the
[deserialization case study](case-studies/false-safe-deserialization.md).

Select the new lab with `python -m patchproof verify --lab my-lab`. Python
prints are captured as diagnostics; uncaught exceptions become execution errors.
Return an explicit JSON denial for an expected rejection. The verifier trusts
the author's expected values to represent the stated security property.

Include realistic negative and positive controls, boundaries, alternate input
encodings, and known regressions that are relevant to the application. Avoid
assertions that only mirror the implementation: define expectations from the
desired behavior. Keep every fixture local, deterministic, and free of real
credentials or personal data. Run both the fixture verification and the
project's standard-library test suite:

```sh
python -m patchproof verify
python -m unittest discover -s tests -v
```

Passing results support the narrowly stated claim. They cannot establish that
all exploit variants have been eliminated or that an application is ready for
deployment.
