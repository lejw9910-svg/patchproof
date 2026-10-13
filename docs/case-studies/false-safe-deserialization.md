# Case study: a denial response can hide unsafe reconstruction

This is a finding in Patchproof's own synthetic evaluation design, discovered
while reviewing the prototype for an individual CVP application. It is not a
third-party vulnerability disclosure, an assigned CVE, or a Claude-discovered
finding. No external service or real data was involved.

## Research question

Can a verifier wrongly accept a patch that reports a safe outcome after it has
already performed the unsafe operation?

The initial deserialization lab reconstructed a fixed harmless Python object
through `pickle.loads`. The reference patch rejected the pickle format before
deserializing and preserved data-only JSON behavior. The original verifier
compared only returned JSON values and process success.

During review, a deliberately incomplete candidate retained reconstruction and
then returned the exact expected denial:

```python
value = pickle.loads(serialized)
return {"status": "rejected", "reason": "unsafe-serialization-format"}
```

The vulnerable behavior still occurred, but an output-only comparison accepted
the candidate. The fixture's reconstruction expressions are fixed and harmless;
they return a sentinel or record without running commands or accessing files.

## Independent observation

The worker now installs a Python audit hook before importing the reviewed
candidate. It records the number of `pickle.find_class` events separately from
the candidate's returned value. The attack contract requires one event in the
baseline and zero in the patch. Normal JSON controls require zero on both sides.

The manifest binds the observation expectations to the same input corpus and
source hashes as the returned-value expectations. Cases cannot silently change
through nested Python dictionary mutations after loading: verification reloads
the manifest and checks both its raw hash and parsed case semantics.

## Reproduce and inspect

```sh
python -m pip install -e .
python scripts/reproduce.py --output reports/application
python -m patchproof verify --lab insecure-deserialization \
  --candidate evaluation/mutations/insecure-deserialization/load-then-deny.py \
  --format json --output reports/load-then-deny.json
```

The last command is an expected negative control and should exit with code `1`.
Inspect `patched.value`, `patched.observations`, and `expected_patched_observations`
for `pickle-callable-marker` and `pickle-callable-record`. The response matches
the denial contract; the nonzero observation causes rejection.

The [benchmark JSON](../../reports/application/benchmark.json) contains the full
observations. The [comparison record](../../reports/application/case-study.json)
computes the former output-only verdict and the current verdict from those same
observed executions. This controlled comparison isolates the policy difference;
it is not a separate historical run or a live model experiment.

## Scope and next experiments

The audit signal records Python class-resolution events in this worker only.
It is not proof that all deserialization, arbitrary code execution, filesystem,
or network effects were absent. It does not observe child interpreters, and
hostile candidate code can tamper with the process. A plain-data pickle may emit
no class-resolution event. These limits matter: the tool runs trusted, reviewed
fixtures and is not a containment system.

Path traversal, authorization, and SQL cases primarily compare returned values;
they do not yet have comprehensive independent side-effect observers. A next
study would define narrow, independently observable security properties for
each class, preregister additional cases before candidate generation, and ask
an independent reviewer to challenge the oracle. Those steps are planned and
are not presented as completed evidence.
