# Patchproof curated mutation evaluation

**Overall: PASS**

Curated synthetic mutation checks over the same four local lab corpora. Candidates and expectations were authored together; this is neither a held-out evaluation nor a measure of model performance or real-world patch correctness. A rejection is credited only after complete executions, reproduced baselines, and all declared checks. Errors and inconclusive evidence never count as detections. The runner and audit observations are not a hostile-code security boundary.

- Accepted reference patches: 4 / 4
- Rejected negative candidates: 13 / 13
- False acceptances: 0; false rejections: 0
- Errors: 0; inconclusive: 0; check mismatches: 0

Evaluation manifest SHA-256: `35981487a24c38eb8a9d7a8c7a62da3c36d8d030f33fd6f0560ea189f25a94be`

| Experiment | Expected | Observed | Classification | Intended checks |
| --- | --- | --- | --- | --- |
| `path-traversal-reference` | pass | pass | accepted\_good | 1 / 1 |
| `path-traversal-unchanged` | fail | fail | rejected\_bad | 1 / 1 |
| `path-traversal-reject-all` | fail | fail | rejected\_bad | 2 / 2 |
| `path-traversal-partial` | fail | fail | rejected\_bad | 2 / 2 |
| `insecure-deserialization-reference` | pass | pass | accepted\_good | 1 / 1 |
| `insecure-deserialization-unchanged` | fail | fail | rejected\_bad | 1 / 1 |
| `insecure-deserialization-reject-all` | fail | fail | rejected\_bad | 2 / 2 |
| `insecure-deserialization-partial` | fail | fail | rejected\_bad | 2 / 2 |
| `auth-bypass-reference` | pass | pass | accepted\_good | 1 / 1 |
| `auth-bypass-unchanged` | fail | fail | rejected\_bad | 1 / 1 |
| `auth-bypass-reject-all` | fail | fail | rejected\_bad | 2 / 2 |
| `auth-bypass-partial` | fail | fail | rejected\_bad | 2 / 2 |
| `sql-injection-reference` | pass | pass | accepted\_good | 1 / 1 |
| `sql-injection-unchanged` | fail | fail | rejected\_bad | 1 / 1 |
| `sql-injection-reject-all` | fail | fail | rejected\_bad | 2 / 2 |
| `sql-injection-partial` | fail | fail | rejected\_bad | 2 / 2 |
| `insecure-deserialization-load-then-deny` | fail | fail | rejected\_bad | 4 / 4 |

<details>
<summary>path\-traversal\-reference</summary>

The reviewed patched\.py reference must pass the complete declared lab corpus\.

Classification and all declared checks matched

- Lab manifest SHA-256: `af4817ad160ad45b5317f9e6a238a5ae74a7a73c29b1f204625f8232fd9bca83`
- Baseline SHA-256: `2cb76ce6522d718ffee2e6345aa6f5ed65ca98398f38a39788f3ed8d5dd54a67`
- Candidate SHA-256: `7a98a0d8ef30403152e7d7904141cc44a618ec0adb13fd1b65abb37ecfa6a572`

| Case | Verdict | Reason |
| --- | --- | --- |
| `parent-traversal` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `sibling-prefix` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `symlink-escape` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `public-file` | pass | Functional behavior preserved on both versions\. |
| `nested-public-file` | pass | Functional behavior preserved on both versions\. |
| `normalized-public-file` | pass | Functional behavior preserved on both versions\. |
| `missing-file` | pass | Functional behavior preserved on both versions\. |
| `empty-path` | pass | Functional behavior preserved on both versions\. |
| `invalid-path-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>path\-traversal\-unchanged</summary>

Unchanged vulnerable\.py is a detection sanity control; it deliberately does not produce a safe primary attack response\.

Classification and all declared checks matched

- Lab manifest SHA-256: `af4817ad160ad45b5317f9e6a238a5ae74a7a73c29b1f204625f8232fd9bca83`
- Baseline SHA-256: `2cb76ce6522d718ffee2e6345aa6f5ed65ca98398f38a39788f3ed8d5dd54a67`
- Candidate SHA-256: `2cb76ce6522d718ffee2e6345aa6f5ed65ca98398f38a39788f3ed8d5dd54a67`

| Case | Verdict | Reason |
| --- | --- | --- |
| `parent-traversal` | fail | Patch did not match the declared response and observations\. |
| `sibling-prefix` | fail | Patch did not match the declared response and observations\. |
| `symlink-escape` | fail | Patch did not match the declared response and observations\. |
| `public-file` | pass | Functional behavior preserved on both versions\. |
| `nested-public-file` | pass | Functional behavior preserved on both versions\. |
| `normalized-public-file` | pass | Functional behavior preserved on both versions\. |
| `missing-file` | pass | Functional behavior preserved on both versions\. |
| `empty-path` | pass | Functional behavior preserved on both versions\. |
| `invalid-path-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>path\-traversal\-reject\-all</summary>

Returning the primary safe rejection for every input prevents useful functionality and must fail its successful control\.

Classification and all declared checks matched

- Lab manifest SHA-256: `af4817ad160ad45b5317f9e6a238a5ae74a7a73c29b1f204625f8232fd9bca83`
- Baseline SHA-256: `2cb76ce6522d718ffee2e6345aa6f5ed65ca98398f38a39788f3ed8d5dd54a67`
- Candidate SHA-256: `49c1def462afc4dea8a7b7e6f1fa6a14675bc9edaf16911a95f708b1616d5304`

| Case | Verdict | Reason |
| --- | --- | --- |
| `parent-traversal` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `sibling-prefix` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `symlink-escape` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `public-file` | fail | Patch failed the functional control\. |
| `nested-public-file` | fail | Patch failed the functional control\. |
| `normalized-public-file` | fail | Patch failed the functional control\. |
| `missing-file` | fail | Patch failed the functional control\. |
| `empty-path` | fail | Patch failed the functional control\. |
| `invalid-path-type` | fail | Patch failed the functional control\. |
| `invalid-request` | fail | Patch failed the functional control\. |

</details>

<details>
<summary>path\-traversal\-partial</summary>

Resolved string\-prefix containment blocks the private path but accepts a sibling named public\-backup\.

Classification and all declared checks matched

- Lab manifest SHA-256: `af4817ad160ad45b5317f9e6a238a5ae74a7a73c29b1f204625f8232fd9bca83`
- Baseline SHA-256: `2cb76ce6522d718ffee2e6345aa6f5ed65ca98398f38a39788f3ed8d5dd54a67`
- Candidate SHA-256: `36943d0ac2c1e0164aa81cce8cfcbf051ba0a962ed3f7b859b9099ce18442804`

| Case | Verdict | Reason |
| --- | --- | --- |
| `parent-traversal` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `sibling-prefix` | fail | Patch did not match the declared response and observations\. |
| `symlink-escape` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `public-file` | pass | Functional behavior preserved on both versions\. |
| `nested-public-file` | pass | Functional behavior preserved on both versions\. |
| `normalized-public-file` | pass | Functional behavior preserved on both versions\. |
| `missing-file` | pass | Functional behavior preserved on both versions\. |
| `empty-path` | pass | Functional behavior preserved on both versions\. |
| `invalid-path-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>insecure\-deserialization\-reference</summary>

The reviewed patched\.py reference must pass the complete declared lab corpus\.

Classification and all declared checks matched

- Lab manifest SHA-256: `de65f2d56faba564fba995182e08d76352eb8f0f4482ab13738b36619f786e82`
- Baseline SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`
- Candidate SHA-256: `46f6770900ad7e0f00bf289b02c56978c8349ad771251136bcd931551ea8c9c3`

| Case | Verdict | Reason |
| --- | --- | --- |
| `pickle-callable-marker` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `pickle-callable-record` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `json-object` | pass | Functional behavior preserved on both versions\. |
| `json-array` | pass | Functional behavior preserved on both versions\. |
| `malformed-json` | pass | Functional behavior preserved on both versions\. |
| `non-finite-json` | pass | Functional behavior preserved on both versions\. |
| `overflowing-json-number` | pass | Functional behavior preserved on both versions\. |
| `invalid-data-type` | pass | Functional behavior preserved on both versions\. |
| `unsupported-format` | pass | Functional behavior preserved on both versions\. |
| `missing-format` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>insecure\-deserialization\-unchanged</summary>

Unchanged vulnerable\.py is a detection sanity control; it deliberately does not produce a safe primary attack response\.

Classification and all declared checks matched

- Lab manifest SHA-256: `de65f2d56faba564fba995182e08d76352eb8f0f4482ab13738b36619f786e82`
- Baseline SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`
- Candidate SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`

| Case | Verdict | Reason |
| --- | --- | --- |
| `pickle-callable-marker` | fail | Patch did not match the declared response and observations\. |
| `pickle-callable-record` | fail | Patch did not match the declared response and observations\. |
| `json-object` | pass | Functional behavior preserved on both versions\. |
| `json-array` | pass | Functional behavior preserved on both versions\. |
| `malformed-json` | pass | Functional behavior preserved on both versions\. |
| `non-finite-json` | pass | Functional behavior preserved on both versions\. |
| `overflowing-json-number` | pass | Functional behavior preserved on both versions\. |
| `invalid-data-type` | pass | Functional behavior preserved on both versions\. |
| `unsupported-format` | pass | Functional behavior preserved on both versions\. |
| `missing-format` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>insecure\-deserialization\-reject\-all</summary>

Returning the primary safe rejection for every input prevents useful functionality and must fail its successful control\.

Classification and all declared checks matched

- Lab manifest SHA-256: `de65f2d56faba564fba995182e08d76352eb8f0f4482ab13738b36619f786e82`
- Baseline SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`
- Candidate SHA-256: `98188edcf8d88ce434e9834689babf7b1ebd6bf0c7bdda6c831bb2e6f93960e3`

| Case | Verdict | Reason |
| --- | --- | --- |
| `pickle-callable-marker` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `pickle-callable-record` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `json-object` | fail | Patch failed the functional control\. |
| `json-array` | fail | Patch failed the functional control\. |
| `malformed-json` | fail | Patch failed the functional control\. |
| `non-finite-json` | fail | Patch failed the functional control\. |
| `overflowing-json-number` | fail | Patch failed the functional control\. |
| `invalid-data-type` | fail | Patch failed the functional control\. |
| `unsupported-format` | fail | Patch failed the functional control\. |
| `missing-format` | fail | Patch failed the functional control\. |
| `invalid-request` | fail | Patch failed the functional control\. |

</details>

<details>
<summary>insecure\-deserialization\-partial</summary>

Data\-only parsing blocks pickle but incorrectly rejects supported top\-level JSON arrays\.

Classification and all declared checks matched

- Lab manifest SHA-256: `de65f2d56faba564fba995182e08d76352eb8f0f4482ab13738b36619f786e82`
- Baseline SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`
- Candidate SHA-256: `3ce4170531fcf5980ea42a0736045794370345d8f911fd3b0731d981fb111d7a`

| Case | Verdict | Reason |
| --- | --- | --- |
| `pickle-callable-marker` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `pickle-callable-record` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `json-object` | pass | Functional behavior preserved on both versions\. |
| `json-array` | fail | Patch failed the functional control\. |
| `malformed-json` | pass | Functional behavior preserved on both versions\. |
| `non-finite-json` | pass | Functional behavior preserved on both versions\. |
| `overflowing-json-number` | pass | Functional behavior preserved on both versions\. |
| `invalid-data-type` | pass | Functional behavior preserved on both versions\. |
| `unsupported-format` | pass | Functional behavior preserved on both versions\. |
| `missing-format` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>auth\-bypass\-reference</summary>

The reviewed patched\.py reference must pass the complete declared lab corpus\.

Classification and all declared checks matched

- Lab manifest SHA-256: `c09e2e0db153e8ba762af3892fa6361601b743d78ef62ed26e58e86acd2eb2ac`
- Baseline SHA-256: `366f0673a836e0268b8b93eebe87af7f3dac2bb20ebaa9073b74e258f9c32a84`
- Candidate SHA-256: `53b977fc9b8a35c27595e53320a8fd3991f30d878e12620344280545e7868b22`

| Case | Verdict | Reason |
| --- | --- | --- |
| `member-spoofs-admin-role` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `member-reads-admin-audit` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `valid-admin` | pass | Functional behavior preserved on both versions\. |
| `valid-admin-audit` | pass | Functional behavior preserved on both versions\. |
| `member-profile` | pass | Functional behavior preserved on both versions\. |
| `member-admin-action-denied` | pass | Functional behavior preserved on both versions\. |
| `invalid-token` | pass | Functional behavior preserved on both versions\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-token-type` | pass | Functional behavior preserved on both versions\. |
| `unknown-action` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>auth\-bypass\-unchanged</summary>

Unchanged vulnerable\.py is a detection sanity control; it deliberately does not produce a safe primary attack response\.

Classification and all declared checks matched

- Lab manifest SHA-256: `c09e2e0db153e8ba762af3892fa6361601b743d78ef62ed26e58e86acd2eb2ac`
- Baseline SHA-256: `366f0673a836e0268b8b93eebe87af7f3dac2bb20ebaa9073b74e258f9c32a84`
- Candidate SHA-256: `366f0673a836e0268b8b93eebe87af7f3dac2bb20ebaa9073b74e258f9c32a84`

| Case | Verdict | Reason |
| --- | --- | --- |
| `member-spoofs-admin-role` | fail | Patch did not match the declared response and observations\. |
| `member-reads-admin-audit` | fail | Patch did not match the declared response and observations\. |
| `valid-admin` | pass | Functional behavior preserved on both versions\. |
| `valid-admin-audit` | pass | Functional behavior preserved on both versions\. |
| `member-profile` | pass | Functional behavior preserved on both versions\. |
| `member-admin-action-denied` | pass | Functional behavior preserved on both versions\. |
| `invalid-token` | pass | Functional behavior preserved on both versions\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-token-type` | pass | Functional behavior preserved on both versions\. |
| `unknown-action` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>auth\-bypass\-reject\-all</summary>

Returning the primary safe rejection for every input prevents useful functionality and must fail its successful control\.

Classification and all declared checks matched

- Lab manifest SHA-256: `c09e2e0db153e8ba762af3892fa6361601b743d78ef62ed26e58e86acd2eb2ac`
- Baseline SHA-256: `366f0673a836e0268b8b93eebe87af7f3dac2bb20ebaa9073b74e258f9c32a84`
- Candidate SHA-256: `5de541176f01d107c4781e091ce8218106bb8b96bd838dd9a9a0530c125dc04e`

| Case | Verdict | Reason |
| --- | --- | --- |
| `member-spoofs-admin-role` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `member-reads-admin-audit` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `valid-admin` | fail | Patch failed the functional control\. |
| `valid-admin-audit` | fail | Patch failed the functional control\. |
| `member-profile` | fail | Patch failed the functional control\. |
| `member-admin-action-denied` | pass | Functional behavior preserved on both versions\. |
| `invalid-token` | fail | Patch failed the functional control\. |
| `missing-credentials` | fail | Patch failed the functional control\. |
| `invalid-token-type` | fail | Patch failed the functional control\. |
| `unknown-action` | fail | Patch failed the functional control\. |
| `invalid-request-type` | fail | Patch failed the functional control\. |

</details>

<details>
<summary>auth\-bypass\-partial</summary>

Server\-held roles protect the primary admin route while the audit route still trusts client roles\.

Classification and all declared checks matched

- Lab manifest SHA-256: `c09e2e0db153e8ba762af3892fa6361601b743d78ef62ed26e58e86acd2eb2ac`
- Baseline SHA-256: `366f0673a836e0268b8b93eebe87af7f3dac2bb20ebaa9073b74e258f9c32a84`
- Candidate SHA-256: `9dc756de4c64e779808ad980ca65a7f01c5f820731cc8d7d5cb84b09c8aa3c8e`

| Case | Verdict | Reason |
| --- | --- | --- |
| `member-spoofs-admin-role` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `member-reads-admin-audit` | fail | Patch did not match the declared response and observations\. |
| `valid-admin` | pass | Functional behavior preserved on both versions\. |
| `valid-admin-audit` | pass | Functional behavior preserved on both versions\. |
| `member-profile` | pass | Functional behavior preserved on both versions\. |
| `member-admin-action-denied` | pass | Functional behavior preserved on both versions\. |
| `invalid-token` | pass | Functional behavior preserved on both versions\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-token-type` | pass | Functional behavior preserved on both versions\. |
| `unknown-action` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>sql\-injection\-reference</summary>

The reviewed patched\.py reference must pass the complete declared lab corpus\.

Classification and all declared checks matched

- Lab manifest SHA-256: `f87100aece3dee6df0c605edd4477d469fe86b909483506887c567f994cbbee4`
- Baseline SHA-256: `d8733e1685938d70fc7552212811f8a24058c9f2686ab2f6583b03b6dd2b709b`
- Candidate SHA-256: `7b50f6439cecec09a75a4370a5b0a40652beaf8b616254d185b07ca203fe9df6`

| Case | Verdict | Reason |
| --- | --- | --- |
| `boolean-login-bypass` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `union-login-bypass` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `valid-admin-login` | pass | Functional behavior preserved on both versions\. |
| `quoted-password-preserved` | pass | Functional behavior preserved on both versions\. |
| `decimal-string-id` | pass | Functional behavior preserved on both versions\. |
| `wrong-password` | pass | Functional behavior preserved on both versions\. |
| `unknown-account` | pass | Functional behavior preserved on both versions\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-password-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-id-type` | pass | Functional behavior preserved on both versions\. |
| `malformed-id` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>sql\-injection\-unchanged</summary>

Unchanged vulnerable\.py is a detection sanity control; it deliberately does not produce a safe primary attack response\.

Classification and all declared checks matched

- Lab manifest SHA-256: `f87100aece3dee6df0c605edd4477d469fe86b909483506887c567f994cbbee4`
- Baseline SHA-256: `d8733e1685938d70fc7552212811f8a24058c9f2686ab2f6583b03b6dd2b709b`
- Candidate SHA-256: `d8733e1685938d70fc7552212811f8a24058c9f2686ab2f6583b03b6dd2b709b`

| Case | Verdict | Reason |
| --- | --- | --- |
| `boolean-login-bypass` | fail | Patch did not match the declared response and observations\. |
| `union-login-bypass` | fail | Patch did not match the declared response and observations\. |
| `valid-admin-login` | pass | Functional behavior preserved on both versions\. |
| `quoted-password-preserved` | pass | Functional behavior preserved on both versions\. |
| `decimal-string-id` | pass | Functional behavior preserved on both versions\. |
| `wrong-password` | pass | Functional behavior preserved on both versions\. |
| `unknown-account` | pass | Functional behavior preserved on both versions\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-password-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-id-type` | pass | Functional behavior preserved on both versions\. |
| `malformed-id` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>sql\-injection\-reject\-all</summary>

Returning the primary safe rejection for every input prevents useful functionality and must fail its successful control\.

Classification and all declared checks matched

- Lab manifest SHA-256: `f87100aece3dee6df0c605edd4477d469fe86b909483506887c567f994cbbee4`
- Baseline SHA-256: `d8733e1685938d70fc7552212811f8a24058c9f2686ab2f6583b03b6dd2b709b`
- Candidate SHA-256: `c0a97d8f92c5871bb04654b957b702bd0ccada0d10dfbd52ceed4cd97ed83b0f`

| Case | Verdict | Reason |
| --- | --- | --- |
| `boolean-login-bypass` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `union-login-bypass` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `valid-admin-login` | fail | Patch failed the functional control\. |
| `quoted-password-preserved` | fail | Patch failed the functional control\. |
| `decimal-string-id` | fail | Patch failed the functional control\. |
| `wrong-password` | fail | Patch failed the functional control\. |
| `unknown-account` | fail | Patch failed the functional control\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-password-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-id-type` | pass | Functional behavior preserved on both versions\. |
| `malformed-id` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>sql\-injection\-partial</summary>

A tautology blacklist rejects the primary Boolean payload but misses UNION\-based account selection\.

Classification and all declared checks matched

- Lab manifest SHA-256: `f87100aece3dee6df0c605edd4477d469fe86b909483506887c567f994cbbee4`
- Baseline SHA-256: `d8733e1685938d70fc7552212811f8a24058c9f2686ab2f6583b03b6dd2b709b`
- Candidate SHA-256: `eae1c6ba63a8f359d0a851b8207606d0d77f183bed9ff59c6922d89412b99251`

| Case | Verdict | Reason |
| --- | --- | --- |
| `boolean-login-bypass` | pass | Baseline reproduced; patch matched the declared response and observations\. |
| `union-login-bypass` | fail | Patch did not match the declared response and observations\. |
| `valid-admin-login` | pass | Functional behavior preserved on both versions\. |
| `quoted-password-preserved` | pass | Functional behavior preserved on both versions\. |
| `decimal-string-id` | pass | Functional behavior preserved on both versions\. |
| `wrong-password` | pass | Functional behavior preserved on both versions\. |
| `unknown-account` | pass | Functional behavior preserved on both versions\. |
| `missing-credentials` | pass | Functional behavior preserved on both versions\. |
| `invalid-password-type` | pass | Functional behavior preserved on both versions\. |
| `invalid-id-type` | pass | Functional behavior preserved on both versions\. |
| `malformed-id` | pass | Functional behavior preserved on both versions\. |
| `invalid-request-type` | pass | Functional behavior preserved on both versions\. |

</details>

<details>
<summary>insecure\-deserialization\-load\-then\-deny</summary>

The candidate deserializes the executable fixture then returns the exact expected denial; independent pickle class\-resolution observation must reject both attacks\.

Classification and all declared checks matched

- Lab manifest SHA-256: `de65f2d56faba564fba995182e08d76352eb8f0f4482ab13738b36619f786e82`
- Baseline SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`
- Candidate SHA-256: `ee18dc548e0d066e8cf025a0dfca3fbc5c96c74edc99be707a345e5574def9bf`

| Case | Verdict | Reason |
| --- | --- | --- |
| `pickle-callable-marker` | fail | Patch did not match the declared response and observations\. |
| `pickle-callable-record` | fail | Patch did not match the declared response and observations\. |
| `json-object` | pass | Functional behavior preserved on both versions\. |
| `json-array` | pass | Functional behavior preserved on both versions\. |
| `malformed-json` | pass | Functional behavior preserved on both versions\. |
| `non-finite-json` | pass | Functional behavior preserved on both versions\. |
| `overflowing-json-number` | pass | Functional behavior preserved on both versions\. |
| `invalid-data-type` | pass | Functional behavior preserved on both versions\. |
| `unsupported-format` | pass | Functional behavior preserved on both versions\. |
| `missing-format` | pass | Functional behavior preserved on both versions\. |
| `invalid-request` | pass | Functional behavior preserved on both versions\. |

</details>
