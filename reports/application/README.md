# Local application evidence

Generated from Patchproof 0.2.0 on 2026-10-13. The JSON reports retain exact UTC
run timestamps, Python/platform information, limits, and engine source hashes.
This is local development evidence; it is not a hosted CI run, a model evaluation,
an external vulnerability disclosure, or a CVP approval.

| Artifact | What it establishes |
| --- | --- |
| [tests.txt](tests.txt) | 109 standard-library unit and integration tests passed on Python 3.12.14. |
| [verification.md](verification.md) / [JSON](verification.json) | Four reference patches pass 44 cases: 9 attacks and 35 regression controls. |
| [benchmark.md](benchmark.md) / [JSON](benchmark.json) | Four reference candidates accepted; thirteen curated faulty candidates rejected, with no errors or inconclusive classifications. |
| [case-study.json](case-study.json) | A response-only comparison would accept load-then-deny; independent audit observations reject both reconstruction attacks. |
| [evidence.zip](evidence.zip) / [integrity.json](integrity.json) | 26 source, manifest, and report files matched their checksums and recorded source identities. Unsigned integrity only. |
| [claude-packet.json](claude-packet.json) | A locally prepared review packet. It has not been sent to or evaluated by Claude. |
| [summary.json](summary.json) | Machine-readable counts and scope limitations. |

Reproduce from the repository root:

```sh
python -m pip install -e .
python scripts/reproduce.py --output reports/application
python -m patchproof check-bundle reports/application/evidence.zip
```

The benchmark is a curated public corpus authored with its expectations. A
zero false-acceptance count here is not a general accuracy guarantee. See the
[evaluation protocol](../../evaluation/README.md) and
[research plan](../../docs/research-plan.md).

The regular wheel was also installed in a separate virtual environment and
exercised outside the repository: listing labs, verifying the load-then-deny
candidate (expected exit 1), checking its evidence bundle, and preparing an
offline packet all behaved as expected. The GitHub workflow is configured for
Python 3.10/3.12/3.13, but no hosted workflow execution is claimed here.
