# Insecure deserialization — CWE-502

Pickle is an executable object-reconstruction protocol. Its `__reduce__` records
can name Python callables that run during `pickle.loads()`. The vulnerable
handler accepts this format alongside an ordinary JSON format.

The two attack inputs select fixed local pickle fixtures. Their reconstruction
calls `eval()` on hardcoded expressions that return a sentinel string or a
synthetic record containing `6 * 7`. This demonstrates callable execution during
deserialization. Neither expression performs IO, runs a shell, or accesses a
network. This educational adapter deliberately accepts fixture names instead of
arbitrary serialized blobs.

The patched handler rejects the pickle format before any reconstruction and
retains the same data-only JSON path. Controls cover valid structured JSON,
arrays, malformed data, and unsupported formats. The input contract is
`{"format": "json", "data": "<JSON text>"}`; object reconstruction is not part of
the legitimate application contract.

The worker also counts Python's `pickle.find_class` audit events independently
of the handler's returned JSON. Each attack expects one class resolution from
the baseline and zero from the candidate; JSON controls expect zero from both.
A candidate that calls `pickle.loads()` and then returns the expected denial
still fails this observation check. The curated evaluation includes that
specific misleading-return candidate.

This is a parser-policy demonstration, not a general serialization migration or
proof that all JSON input is safe for downstream consumers. Real applications
must also validate their data schema and apply resource limits. A restricted
pickle allowlist is not being proposed as a substitute for a data-only format.
The audit count measures this fixture's class-resolution event, not all forms
of execution or every possible pickle operation. Python instrumentation and
the process runner are not resistant to deliberately hostile code that tries
to tamper with the observer.

From the repository root after installation:

```sh
python -m patchproof verify --lab insecure-deserialization
```
