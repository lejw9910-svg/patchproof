# Path traversal — CWE-22

The vulnerable handler joins a supplied path to `public/` and reads it. A
`../` segment can reach `private/`; a similarly named `public-backup/` directory
illustrates why a string-prefix check would also be insufficient. A symlink
inside `public/` provides another route to the private fixture.

The patched handler resolves the candidate and checks containment using
`Path.relative_to()` against the resolved public directory before reading.
Normal and nested public reads remain available. Missing files and invalid
inputs produce explicit rejection results.

All files, including synthetic secret records and the symlink target, are
created inside the runner's temporary workspace. The vulnerable version has a
separate **fixture-workspace guard** to keep this example from intentionally
reading host files; that guard does not enforce the public-directory policy.
Run the symlink case on an operating system that permits creating symlinks
(the CI workflow uses Linux).

This fix demonstrates containment for a static fixture. Resolve-then-open has a
time-of-check/time-of-use (TOCTOU) gap: another process could replace filesystem
entries between the check and the read. Production code facing concurrent
untrusted filesystem changes needs an operating-system-specific, descriptor-based
approach and an appropriate isolation boundary. These fixtures do not establish
race resistance.

From the repository root after installation:

```sh
python -m patchproof verify --lab path-traversal
```
