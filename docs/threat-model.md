# Threat model

## Purpose and assets

Patchproof checks whether a candidate patch changes a known bad result into an
explicitly expected safe result without breaking included normal cases. The
assets are the host's files and credentials, the integrity of the case corpus,
and the accuracy of the resulting verification evidence.

The default workflow assumes the operator trusts the runner, both source
versions, and the manifest. The attacker inputs are synthetic case data sent
to those reviewed fixtures. A third party that can modify fixture code can
execute Python with the operator's permissions.

## Boundaries and controls

| Boundary or risk | Starter control | Remaining limitation |
| --- | --- | --- |
| Fixture state leaks between runs | Fresh temporary working directory and separate child executions | Code can still access paths outside its working directory. |
| Child inherits credentials through environment variables | Scrubbed child environment | Code can read files accessible to the account or use other host facilities. |
| Fixture hangs or floods output | Time and output limits | These are availability safeguards, not comprehensive CPU, memory, or process isolation. |
| Descendant processes outlive a timed-out execution | POSIX process-group cleanup | Platform behavior differs; this is not a containment guarantee. |
| A crash is mistaken for a blocked attack | Execution/protocol errors are distinct from safe expected results | Expected results and fixture behavior still require review. |
| A test cannot reproduce the original issue | The baseline must satisfy its explicit expectation | Reproduction depends on the quality and coverage of the cases. |
| Reports refer to unclear source versions | Source hashes, diffs, and case evidence | Reports are not signed attestations and do not establish source provenance. |

There is no network isolation, filesystem jail, container boundary, VM, syscall
filter, or guarantee that a compromised child cannot affect the host. The name
`sandbox.py` describes subprocess supervision only. Use a separately managed
disposable isolation environment before considering untrusted code; that is
outside this starter's implementation.

## Lab-specific scope

- Path traversal uses temporary synthetic files. Its cases are not a complete
  analysis of filesystem races, platform path syntax, or every symlink scenario.
- Deserialization demonstrates unsafe pickle reconstruction with a harmless
  marker. It does not execute a shell command or contact a remote service.
- Authorization demonstrates trusting a caller-controlled role. It is not a
  full authentication service, session system, or identity provider.
- SQL injection uses an in-memory SQLite database. It does not connect to a
  production database or establish coverage across SQL dialects.

The advisory AST analyzer recognizes selected constructs and may produce false
positives or miss vulnerabilities. Absence of findings never establishes
safety. A verification pass is scoped to the exact cases and source versions
in its report. Review the patch, expand the corpus, and run application tests
before making a deployment decision.
