# Patchproof

[![Security tests](https://github.com/lejw9910-svg/patchproof/actions/workflows/security-tests.yml/badge.svg)](https://github.com/lejw9910-svg/patchproof/actions/workflows/security-tests.yml)

## 프로젝트 개요

Patchproof는 **보안 패치가 재현된 취약점을 막으면서 정상 기능을 유지하는지**
확인하는 로컬 Python 연구 도구입니다. 취약한 원본과 수정 후보를 같은 입력으로
실행하고, 공격 재현·안전한 처리·정상 동작을 각각 확인합니다. 응답만 안전해 보이는
수정이나 모든 요청을 차단하는 불완전한 패치를 구분하는 것이 목표입니다.

- **네 가지 로컬 실습:** 경로 탐색, 안전하지 않은 역직렬화, 권한 검사 우회,
  SQL 인젝션을 합성 데이터로 재현합니다.
- **동작을 근거로 검증:** 역직렬화 실습은 반환값과 별도로 Python 감사 이벤트를
  관찰하여, 객체를 재구성한 뒤 거부 응답만 반환하는 후보도 찾아냅니다.
- **잘못된 패치로 검증기 평가:** 선별한 불완전한 수정과 정상 참조 패치를 비교하고,
  입력·결과·소스 해시를 Markdown/JSON 보고서에 기록하며 재현용 증거 묶음을 만듭니다.
- **수동 Claude 작업 흐름:** 로컬에서 검토용 프롬프트를 준비하고, 사람이 검토한
  수정 후보를 별도 파일로 평가할 수 있습니다. Claude 호출이나 API 키는 필요하지
  않으며, 실제 모델 실행 결과를 주장하지 않습니다.

현재 [로컬 실행 기록](reports/application/summary.json)은 **테스트 109개 통과,
검증 사례 44개(공격 9개·회귀 35개), 정상 패치 4개 수용, 잘못된 후보 13개 거부**를
보여 줍니다. 이는 선별된 합성 사례의 결과입니다. 검토하고 신뢰하는 코드만 실행해야
하며, 실행기는 호스트 파일시스템이나 네트워크를 격리하지 않습니다. 통과 결과는
기록된 소스와 사례 범위에만 적용됩니다.

아래 Quick start로 실행하거나 [패치 검증 사례 연구](docs/case-studies/false-safe-deserialization.md)와
[수동 Claude 작업 흐름](docs/claude-workflow.md)에서 사용 방법을 확인하세요.

## Overview

Patchproof is a local security research tool for checking whether a patch fixes
a reproduced vulnerability while preserving expected behavior. It compares
baseline and candidate implementations against explicit contracts and independent
observations, then exports the source and evidence needed to reproduce the run.
It uses Python's standard library at runtime and in its tests.

A successful verification means the included cases passed for the recorded
source versions. It does not prove that a program is secure.

## Quick start

Requires Python 3.10 or newer. From this directory:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m patchproof list
python -m patchproof verify
python -m unittest discover -s tests -v

# Reproduce tests, the faulty-patch benchmark, and source evidence together.
python scripts/reproduce.py --output reports/application
```

On Windows, activate the environment with `.venv\Scripts\activate` instead.
The path traversal lab includes a symlink case and needs permission to create
symlinks; the CI workflow runs on Linux. To run directly from the checkout
without installation, prefix commands with `PYTHONPATH=src` on POSIX shells,
for example:

```sh
PYTHONPATH=src python -m patchproof verify
```

Run commands from the repository root so the bundled `labs/` directory is
available. The labs are repository fixtures rather than installed package
data. From another directory, pass their location with
`python -m patchproof verify --labs-dir /path/to/patchproof/labs` (also supported
by `list`).

## Commands

```sh
# Verify one local lab.
python -m patchproof verify --lab path-traversal

# Write a report, or emit machine-readable evidence.
python -m patchproof verify --output reports/sample-verification.md
python -m patchproof verify --format json

# Inspect source without executing it.
python -m patchproof analyze labs/sql-injection/vulnerable.py
python -m patchproof diff labs/sql-injection/vulnerable.py labs/sql-injection/patched.py

# Evaluate a separately reviewed candidate without changing the lab oracle.
python -m patchproof verify --lab path-traversal --candidate labs/path-traversal/patched.py

# Challenge the verifier with correct and intentionally faulty patches.
python -m patchproof benchmark --format json --output reports/benchmark.json

# Preserve exact source, manifests, engine source, and both report formats.
python -m patchproof verify --bundle reports/evidence.zip --output reports/verification.md
python -m patchproof check-bundle reports/evidence.zip

# Prepare a local review packet. This does not contact Claude or any API.
python -m patchproof prepare --lab insecure-deserialization --output reports/claude-packet.json
```

The analyzer uses advisory AST checks for selected risky constructs. Findings
need human review; an empty result is not a security verdict. The diff command
shows source changes, which also need review independently of case results.
Use `python -m patchproof --help` and command-specific `--help` for options.

Verification exits with `0` for a pass, `1` for a failed expectation, or `2` for
an inconclusive run, execution error, or invalid input. Analysis and diff
commands exit with `0` after successful inspection and `2` for invalid input;
their exit codes do not express a security verdict. Reports go to standard
output unless `--output` is supplied, which writes the file and sends the status
to standard error.

The curated benchmark contains four correct references and thirteen deliberately
faulty candidates: unchanged vulnerable code, blanket denials, incomplete patches,
and deserialization that executes before returning a denial. A faulty candidate is
counted as rejected only when executions complete, baseline evidence reproduces,
and its declared failing checks are observed. Crashes do not count as detections.
This is a public synthetic corpus authored with its expectations, not a held-out
evaluation or a measurement of Claude's performance. See
[the evaluation protocol](evaluation/README.md).

Evidence bundles use SHA-256 checksums to detect damaged or inconsistent files.
They are unsigned and do not authenticate the author or prove observations true.
The bundle includes enough source to rerun the selected labs with
`PYTHONPATH=src python -m patchproof verify` after manual inspection and extraction.

## Included labs

| Lab | Vulnerable behavior | Patched behavior |
| --- | --- | --- |
| `path-traversal` | A supplied path escapes the permitted directory. | Resolved paths must remain inside that directory. |
| `insecure-deserialization` | Pickle reconstruction accepts an unsafe synthetic object. | Structured data is parsed and validated without pickle reconstruction. |
| `auth-bypass` | A caller-supplied role grants privileged access. | Authorization uses a server-side identity and role lookup. |
| `sql-injection` | Input is concatenated into an in-memory SQL query. | Query parameters keep input separate from SQL syntax. |

These are small teaching fixtures, including intentionally vulnerable code.
They expose no service and require no external targets. The deserialization
fixture uses a harmless reconstruction marker, and the SQL fixture uses an
in-memory database.

## What verification checks

Each lab pairs `vulnerable.py` and `patched.py` with a manifest of attack and
regression cases. Cases contain explicit `expected_vulnerable` and
`expected_patched` JSON results. Verification requires all of the following:

1. Attack cases reproduce the specified vulnerable behavior on the baseline.
2. Patched attack cases produce the specified safe response.
3. Normal regression cases preserve their specified behavior on both versions.

For deserialization, a worker audit hook independently counts `pickle.find_class`
events. The baseline must resolve a reconstruction callable; the candidate must
not. A matching denial response after unsafe reconstruction now fails. This is a
narrow observation in the worker interpreter, not a comprehensive detector of
side effects or protection against code deliberately tampering with the harness.
Other lab checks primarily use returned values. The
[case study](docs/case-studies/false-safe-deserialization.md) explains the limit
discovered during this project's review.

An unreproduced vulnerable baseline is inconclusive, not a successful fix. A
crash, timeout, or invalid runner response is an execution error. An unmet
patched or regression expectation fails verification. Reports include case
evidence, source hashes, and source differences so reviewers can relate a
result to the code that was checked.

The runner provides a fresh temporary working directory, a scrubbed child
environment, time and output limits, and POSIX process-group cleanup. Despite
the module name `sandbox.py`, this is **not an isolation boundary for hostile
code**: it does not block network access or access to the host filesystem. Run
only trusted fixtures. See the [threat model](docs/threat-model.md) before
adapting it to other code.

## Project layout

- `src/patchproof/`: CLI, advisory analysis, subprocess execution, verification,
  source comparison, and reporting.
- `labs/`: local vulnerable/patched pairs and case manifests.
- `evaluation/`: declared candidate experiments and intentionally faulty patches.
- `tests/`: standard-library unit and regression tests.
- `reports/sample-verification.md`: an example report generated from the labs.
- `reports/application/`: actual local tests, benchmark, and reproducibility evidence.
- `scripts/reproduce.py`: one command to regenerate that evidence.
- `.github/workflows/security-tests.yml`: tests and verification in CI.
- `docs/`: [methodology](docs/research-methodology.md),
  [authorization policy](docs/authorization-policy.md), and
  [CVP use case](docs/cvp-use-case.md).

For reporting a flaw in Patchproof itself, see [SECURITY.md](SECURITY.md).
Licensed under the [MIT License](LICENSE).

## Status of the research

The local fixture engine, external-candidate verification, audit observation,
curated benchmark, and evidence packaging are implemented. Hosted GitHub Actions
results, independent review, third-party vulnerability disclosures, and live
Claude-assisted runs have not been established. Account identity, paid-plan
eligibility, MFA, and other CVP account controls must be verified by the applicant;
repository code does not establish them. See the [research plan](docs/research-plan.md)
and [security control evidence register](docs/security-controls.md).

The project also supports an **individual Claude Cyber Verification Program
(CVP) Defense Access application**. It is independently developed and makes no
claim of Anthropic affiliation, certification, or approval. The application
materials distinguish this local work from proposed Claude-assisted research
and disclose the applicant's lack of prior public security research history.

- [신청 준비 현황 — 한국어](docs/cvp-readiness.ko.md)
- [English application draft](docs/cvp-application.md)
- [Current official requirements and project fit](docs/cvp-use-case.md)
