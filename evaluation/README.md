# Curated negative patch evaluation

This corpus checks whether Patchproof accepts four known-good reference patches
and rejects thirteen deliberately deficient candidates. These are manually
authored, synthetic examples evaluated against the same local lab cases used
to develop them. They are not held-out data, a model comparison, an independent
security audit, or evidence of performance on real applications.

`manifest.json` declares all 17 experiments, candidate sources, expected
classifications, required safe return values, and required failing case IDs.
Each experiment reruns the full lab corpus against its baseline and selected
candidate. Reports retain the full per-case evidence, source diffs, and hashes.
The checked-in candidate files are standalone and deliberately wrong.

| Family | Count | Intended observation |
| --- | ---: | --- |
| Reference `patched.py` | 4 | Every security check and functional control passes. |
| Unchanged `vulnerable.py` | 4 | The primary attack remains possible. |
| Reject every request | 4 | The primary attack gets the exact safe response, but successful functional controls fail. |
| Partial patch | 4 | The primary attack gets the exact safe response, but another attack or supported behavior fails. |
| Deserialize, then return denial | 1 | All returned values match; the independent pickle observation still detects class resolution. |

The unchanged baselines are sanity controls and inherently do not return a safe
primary attack response. Every other negative candidate is required to return
the exact expected safe response on at least the primary attack. This guards
against an evaluation made up only of obvious missing fixes or malformed output.

The four partial patches illustrate specific mistakes:

- Path traversal: resolving a path then using a string prefix admits the
  similarly named `public-backup/` sibling directory.
- Authorization: using server-held roles on the main admin route leaves the
  audit route trusting a caller-supplied role.
- SQL injection: rejecting a recognized Boolean tautology misses the UNION
  payload in the same corpus.
- Deserialization: switching to data-only JSON while rejecting valid top-level
  arrays breaks supported functionality, despite preventing pickle execution.

The deserialize-then-deny candidate demonstrates why a returned rejection is
insufficient evidence. It performs the fixed harmless pickle reconstruction and
then returns exactly the expected denial. The worker's `pickle.find_class`
counter sees the resolution before the handler returns. Both attack checks fail
because they require zero candidate class resolutions. This narrow observation
does not measure arbitrary side effects or protect against code designed to
tamper with instrumentation.

The benchmark counts a bad candidate as rejected only when every process
completes successfully, every baseline result and required baseline observation
reproduces, all intended checks match, and the verifier returns `fail`.
Crashes, timeouts, missing audit evidence, unknown cases, and inconclusive
baselines are reported separately and never credited as detections. Passing
this corpus therefore means agreement with these declared checks, not complete
security coverage. Broader empirical claims need independently selected tasks,
reviewed expectations, more realistic code, and stronger execution isolation.

After installation, from the repository root:

```sh
python -m patchproof benchmark
```

The Python API is also available:

```python
from pathlib import Path
from patchproof.benchmark import run_benchmark, render_benchmark_markdown

evidence = run_benchmark(Path("labs"), Path("evaluation"))
print(render_benchmark_markdown(evidence))
```

JSON includes each experiment's complete lab result. Markdown presents the
classification summary, hashes, and case verdicts. A benchmark `pass` requires
all expected classifications and declared experiment checks to match.
