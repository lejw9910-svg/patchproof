# Authorization bypass (CWE-863)

This synthetic request handler authenticates a token against an in-memory account
database. The vulnerable implementation then trusts a client-supplied `role`
when authorizing administrative actions. Two authenticated members can promote
themselves and read the synthetic user list or audit events.

The patch obtains the role from the account associated with the verified token.
Valid administrator access, member profiles, denied member access, and missing
or invalid credentials remain covered by regression fixtures. All tokens and
returned data are public demonstration values; there is no HTTP server or real
identity provider.

After installing Patchproof from the repository root, run:

```sh
python -m patchproof verify --lab auth-bypass
```

The fixtures check this particular authorization decision. They do not establish
that a production authentication system handles token storage, expiration,
revocation, session management, or every administrative operation correctly.
