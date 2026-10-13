# SQL injection (CWE-89)

Each request creates a fresh, in-memory SQLite database of synthetic accounts.
The vulnerable login query binds the password but interpolates `account_id`
directly. Boolean and UNION expressions supplied in that field return an
administrator account with an incorrect password.

The patch accepts positive integer identifiers, including decimal strings, and
binds both identifier and password. Controls cover legitimate logins (including
a password containing an apostrophe), wrong passwords, unknown accounts, missing
credentials, malformed SQL, and invalid input types. Database connections close
after each request and no database file or external service is used.

After installing Patchproof from the repository root, run:

```sh
python -m patchproof verify --lab sql-injection
```

This fixture demonstrates query construction only. Its public, plaintext demo
passwords are not a production password-storage design, and the fixture suite
does not prove that unrelated queries or application endpoints resist injection.
