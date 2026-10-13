# Security policy

Patchproof is a starter project, not a security certification system or an
isolation boundary. The bundled `labs/` intentionally demonstrate vulnerable
behavior. Their documented vulnerable versions are expected to fail their
security cases; flaws in the runner, incorrect verification conclusions, or
unexpected effects outside the fixtures are useful security reports.

## Reporting

If the repository host offers a private vulnerability-reporting or security
advisory feature for this repository, use that channel. This starter does not
configure a private channel, publish a contact address, or promise a response
time. If no private channel is available, ask the repository maintainer for
one without posting sensitive exploit details publicly.

A useful report includes:

- The affected revision, Python version, and operating system.
- The smallest local reproduction and expected versus observed behavior.
- Impact, relevant logs with secrets removed, and a proposed fix if available.

Use synthetic data. Do not include credentials, personal data, or material
obtained from systems outside your authorization.

## Scope and supported versions

There is no published support or backport schedule. Reproduce issues against
the current source before reporting when practical. Reports may concern the
CLI, analyzer, runner, verifier, report output, or CI workflow.

Subprocesses run with the host account's filesystem and network privileges.
Timeouts, environment scrubbing, and temporary directories do not make
untrusted code safe to execute. Review the
[threat model](docs/threat-model.md) and
[authorization policy](docs/authorization-policy.md).

## Proposed CVP research workflow

The repository includes an application draft and local research plan for an
individual considering Anthropic's Cyber Verification Program. No CVP grant,
account-control verification, or live Claude experiment is established here.
See the [control register](docs/security-controls.md) for the official individual
requirements and a proposed incident procedure. Anthropic grant incidents follow
that procedure; reports about Patchproof itself follow the reporting section
above.

Do not commit identity documents, account-recovery material, credentials, or
private incident evidence. The offline prompt workflow requires no API key.
Review model-proposed candidates before running them: bounded subprocess
execution does not make arbitrary generated code safe.
