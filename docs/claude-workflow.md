# Manual Claude-assisted patch workflow

This workflow prepares local material for a person to review and optionally use
with Claude. **No live Claude call is performed by Patchproof.** It does not read
an API key, claim a model-generated patch, or establish that a CVP grant exists.
The current repository has no recorded live Claude experiment or blocking event.

## 1. Freeze an authorized local task

Use the included synthetic labs first. Record the repository revision, selected
lab, source and manifest hashes, Python version, and execution settings before
evaluating candidates. Read the [authorization policy](authorization-policy.md).
Keep the oracle fixed: do not edit expected outputs to make a candidate pass.

## 2. Prepare a prompt locally

From the installed checkout, prepare one lab:

```sh
python -m patchproof prepare --lab path-traversal --output reports/prompts/path-traversal.json
```

The JSON prompt package contains the vulnerable source and repair objective. It
omits the reference patched implementation and manifest test answers. Review the
complete generated file before using it outside the machine; source code may
contain sensitive content when adapting this workflow to another project.
Generation is an offline operation and does not send the file anywhere.

For an initial experiment, ask for a repaired implementation with the same
fixture entry-point contract, an explanation of the change, and remaining
limitations. Keep the scope local and synthetic. Do not add the reference patch
or expected case answers to the prompt if evaluating a fresh candidate. The
public availability of reference code still prevents a claim of blinding.

## 3. Optional manual Claude interaction

If choosing to proceed, use the applicant's own permitted Claude account and
review the [control register](security-controls.md). Ordinary code review and
known-issue patching may use general Claude; do not assume CVP is needed. Use
OAuth for the interactive surfaces and keep credentials out of this repository.
For an individual CVP grant, traffic is retained and monitored; ZDR is unavailable.

The current [help article](https://support.claude.com/en/articles/14604842-cyber-verification-program)
and [security requirements](https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements)
were accessed on 2026-10-13 (Asia/Seoul). Recheck them before a real run. Do not
share a granted session or use it to provide a customer-facing service without
separate approval.

If an authorized task is blocked, preserve the response and scope accurately and
use the provider's official support route if appropriate. Do not alter the record
to suggest that a block occurred when it did not, or attempt to bypass it.

## 4. Review the candidate before execution

Save the proposed source as a separate local file, for example
`candidates/path-traversal.py`, and review its imports, top-level execution,
filesystem operations, subprocess use, network calls, and resource use. The
runner is not hostile-code isolation. Do not execute code that has not been
reviewed and trusted in this environment.

Keep the lab's baseline, reference patch, and manifest unchanged. Then evaluate
the reviewed candidate:

```sh
python -m patchproof verify --lab path-traversal --candidate candidates/path-traversal.py --format json --output reports/candidates/path-traversal.json
```

This checks the candidate against that lab's existing oracle. A result applies
only to the corpus and observed behavior. Treat crashes, timeouts, and invalid
protocol responses as errors, never as evidence that the exploit was blocked.
Inspect normal-case failures as carefully as attack-case failures.

## 5. Keep a truthful experiment record

Record the following alongside the result, with secrets removed:

- Date/time, model label shown by the provider, access surface, and actual access
  tier if known. Do not guess the backend model or grant status.
- Exact reviewed prompt package and its hash, plus any additional instructions.
- Returned candidate source and its hash; distinguish the raw response from
  human edits and record retries rather than selecting only the best attempt.
- Fixed evaluation revision and manifest identities, command, limits, complete
  result, and all failures or inconclusive outcomes.
- Any real refusal/block response, or the explicit statement that none occurred.
- Whether the candidate was human-written, model-proposed, or of unknown origin.

Until a live interaction has occurred, label the record **offline preparation
only**. Reference patches and curated mutations are not evidence of Claude's
performance. A passing report does not prove complete security, researcher
qualification, or likelihood of CVP approval.
