# Patchproof verification

**Overall: PASS** · Patchproof 0.2.0

Results cover only the declared local cases and author-supplied expectations. AST findings are advisory. The process runner is not a security isolation boundary.

## Run metadata

```json
{
  "timestamp_utc": "2026-10-13T03:32:22Z",
  "python_version": "3.12.14",
  "python_implementation": "CPython",
  "platform": {
    "system": "Linux",
    "release": "6.18.44",
    "machine": "x86_64"
  },
  "limits": {
    "timeout_seconds": 2.0,
    "max_output_bytes": 65536
  },
  "tool_source_sha256": {
    "__init__.py": "13193fd22af08b2ef4bcb57f654c382076d17dc4caacf46e6684d1bb0fb25915",
    "__main__.py": "c563d62e7a67a258ecccd911e1a7f78793bb7a52123da5b0372167378487563e",
    "_worker.py": "f16262e297b075ec3c4f1ffd20a2e9c200b43efd86997b2c49a051726e5cb8e9",
    "analyzer.py": "95403d988dca051d8bc75c09d6c9521c6f7c2ccc206101395efc5455a661b4ad",
    "benchmark.py": "e065282dd66fcd8b718f5e35604aeeb182b1b8f809113ba7ecb649850ae70252",
    "diff_engine.py": "61eeaf9002e382d445eacbd801561c98e45eaca8564e08a49f96d22c5496bb6b",
    "evidence.py": "f90fa7a3df6968db0f7f1089ca2a35df32b0f37d02990ced5b027347df220fa4",
    "provenance.py": "57541c12086907270634430033443624968b02824b608eeafe251efebbc11a54",
    "report.py": "a0fdd4eb5743038940dc70ea322c5d0586eac19697c46900fd85b7289bfd8896",
    "research.py": "d5617b40a7ce158187d2c050a91c05e568bd51a158a0b5622fc962214899de5d",
    "sandbox.py": "4efd3a99eb69cf145dedc758eff4f49959acf83f175ccce7cd420611bd5fee87",
    "verifier.py": "1de1d022c0532255baa269786375127fa65563cdc181c59e6144f61dd5a0cee7"
  }
}
```

## Results

| Lab | CWE | Result | Cases |
| --- | --- | --- | ---: |
| Client\-controlled authorization role | CWE-863 | PASS | 11 pass |
| Reject callable reconstruction and preserve data\-only JSON | CWE-502 | PASS | 11 pass |
| Contain local file reads within the public directory | CWE-22 | PASS | 10 pass |
| Interpolated SQL account identifier | CWE-89 | PASS | 12 pass |

## Client\-controlled authorization role

**PASS** · `auth-bypass` · CWE-863

- Manifest SHA-256: `c09e2e0db153e8ba762af3892fa6361601b743d78ef62ed26e58e86acd2eb2ac`
- Baseline SHA-256: `366f0673a836e0268b8b93eebe87af7f3dac2bb20ebaa9073b74e258f9c32a84`
- Patched SHA-256: `53b977fc9b8a35c27595e53320a8fd3991f30d878e12620344280545e7868b22`

### Cases

| Case | Kind | Result | Reason |
| --- | --- | --- | --- |
| `member-spoofs-admin-role` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `member-reads-admin-audit` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `valid-admin` | regression | PASS | Functional behavior preserved on both versions\. |
| `valid-admin-audit` | regression | PASS | Functional behavior preserved on both versions\. |
| `member-profile` | regression | PASS | Functional behavior preserved on both versions\. |
| `member-admin-action-denied` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-token` | regression | PASS | Functional behavior preserved on both versions\. |
| `missing-credentials` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-token-type` | regression | PASS | Functional behavior preserved on both versions\. |
| `unknown-action` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-request-type` | regression | PASS | Functional behavior preserved on both versions\. |

### Advisory source findings

- vulnerable: no supported patterns detected; this is not a safety verdict.
- patched: no supported patterns detected; this is not a safety verdict.

<details>
<summary>Case evidence (inputs, expectations, observations)</summary>

#### `member-spoofs-admin-role`

```json
{
  "id": "member-spoofs-admin-role",
  "input": {
    "token": "alice-demo-token",
    "role": "admin",
    "action": "admin_panel"
  },
  "expected_vulnerable": {
    "status": "ok",
    "data": {
      "users": [
        "admin",
        "alice",
        "bob"
      ]
    }
  },
  "expected_patched": {
    "status": "forbidden"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "users": [
            "admin",
            "alice",
            "bob"
          ]
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "forbidden"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `member-reads-admin-audit`

```json
{
  "id": "member-reads-admin-audit",
  "input": {
    "token": "bob-demo-token",
    "role": "admin",
    "action": "read_audit"
  },
  "expected_vulnerable": {
    "status": "ok",
    "data": {
      "events": [
        "demo login",
        "demo settings update"
      ]
    }
  },
  "expected_patched": {
    "status": "forbidden"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "events": [
            "demo login",
            "demo settings update"
          ]
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "forbidden"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `valid-admin`

```json
{
  "id": "valid-admin",
  "input": {
    "token": "admin-demo-token",
    "action": "admin_panel"
  },
  "expected_vulnerable": {
    "status": "ok",
    "data": {
      "users": [
        "admin",
        "alice",
        "bob"
      ]
    }
  },
  "expected_patched": {
    "status": "ok",
    "data": {
      "users": [
        "admin",
        "alice",
        "bob"
      ]
    }
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "users": [
            "admin",
            "alice",
            "bob"
          ]
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "users": [
            "admin",
            "alice",
            "bob"
          ]
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `valid-admin-audit`

```json
{
  "id": "valid-admin-audit",
  "input": {
    "token": "admin-demo-token",
    "action": "read_audit"
  },
  "expected_vulnerable": {
    "status": "ok",
    "data": {
      "events": [
        "demo login",
        "demo settings update"
      ]
    }
  },
  "expected_patched": {
    "status": "ok",
    "data": {
      "events": [
        "demo login",
        "demo settings update"
      ]
    }
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "events": [
            "demo login",
            "demo settings update"
          ]
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "events": [
            "demo login",
            "demo settings update"
          ]
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `member-profile`

```json
{
  "id": "member-profile",
  "input": {
    "token": "alice-demo-token",
    "action": "profile"
  },
  "expected_vulnerable": {
    "status": "ok",
    "data": {
      "username": "alice",
      "role": "member"
    }
  },
  "expected_patched": {
    "status": "ok",
    "data": {
      "username": "alice",
      "role": "member"
    }
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "username": "alice",
          "role": "member"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "data": {
          "username": "alice",
          "role": "member"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `member-admin-action-denied`

```json
{
  "id": "member-admin-action-denied",
  "input": {
    "token": "alice-demo-token",
    "action": "admin_panel"
  },
  "expected_vulnerable": {
    "status": "forbidden"
  },
  "expected_patched": {
    "status": "forbidden"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "forbidden"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "forbidden"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-token`

```json
{
  "id": "invalid-token",
  "input": {
    "token": "unknown-token",
    "role": "admin",
    "action": "admin_panel"
  },
  "expected_vulnerable": {
    "status": "unauthorized"
  },
  "expected_patched": {
    "status": "unauthorized"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `missing-credentials`

```json
{
  "id": "missing-credentials",
  "input": {
    "role": "admin",
    "action": "admin_panel"
  },
  "expected_vulnerable": {
    "status": "unauthorized"
  },
  "expected_patched": {
    "status": "unauthorized"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-token-type`

```json
{
  "id": "invalid-token-type",
  "input": {
    "token": [
      "admin-demo-token"
    ],
    "action": "profile"
  },
  "expected_vulnerable": {
    "status": "unauthorized"
  },
  "expected_patched": {
    "status": "unauthorized"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `unknown-action`

```json
{
  "id": "unknown-action",
  "input": {
    "token": "admin-demo-token",
    "action": "unknown"
  },
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-request-type`

```json
{
  "id": "invalid-request-type",
  "input": [],
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

</details>

<details>
<summary>Source diff</summary>

```diff
--- vulnerable.py
+++ patched.py
@@ -1,4 +1,4 @@
-"""Intentionally vulnerable, synthetic authorization fixture."""
+"""Authorization uses only roles from the server-held synthetic token database."""
 
 from pathlib import Path
 
@@ -11,7 +11,7 @@
 
 
 def run(payload: object, workspace: Path) -> dict:
-    """Run an entirely local request against a fixed synthetic token database."""
+    """Ignore client role claims after looking up an authenticated account."""
     if not isinstance(payload, dict):
         return {"status": "invalid_input"}
     token = payload.get("token")
@@ -24,9 +24,8 @@
     if action not in ("admin_panel", "read_audit"):
         return {"status": "invalid_input"}
 
-    # FLAW: an authenticated member can supply their own authorization role.
-    role = payload.get("role", account["role"])
-    if role != "admin":
+    # FIX: identity and privilege both come from authenticated server state.
+    if account["role"] != "admin":
         return {"status": "forbidden"}
     if action == "admin_panel":
         return {"status": "ok", "data": {"users": ["admin", "alice", "bob"]}}
```

</details>

## Reject callable reconstruction and preserve data\-only JSON

**PASS** · `insecure-deserialization` · CWE-502

- Manifest SHA-256: `de65f2d56faba564fba995182e08d76352eb8f0f4482ab13738b36619f786e82`
- Baseline SHA-256: `b7646ea335d5c9d9c460210cd21742f7e9b0f3f3f27d1caa7145985c2b9e9785`
- Patched SHA-256: `46f6770900ad7e0f00bf289b02c56978c8349ad771251136bcd931551ea8c9c3`

### Cases

| Case | Kind | Result | Reason |
| --- | --- | --- | --- |
| `pickle-callable-marker` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `pickle-callable-record` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `json-object` | regression | PASS | Functional behavior preserved on both versions\. |
| `json-array` | regression | PASS | Functional behavior preserved on both versions\. |
| `malformed-json` | regression | PASS | Functional behavior preserved on both versions\. |
| `non-finite-json` | regression | PASS | Functional behavior preserved on both versions\. |
| `overflowing-json-number` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-data-type` | regression | PASS | Functional behavior preserved on both versions\. |
| `unsupported-format` | regression | PASS | Functional behavior preserved on both versions\. |
| `missing-format` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-request` | regression | PASS | Functional behavior preserved on both versions\. |

### Advisory source findings

- vulnerable:53 — PP001 (CWE-502): Pickle deserialization requires trusted input\.
- patched: no supported patterns detected; this is not a safety verdict.

<details>
<summary>Case evidence (inputs, expectations, observations)</summary>

#### `pickle-callable-marker`

```json
{
  "id": "pickle-callable-marker",
  "input": {
    "format": "pickle",
    "fixture": "callable-marker"
  },
  "expected_vulnerable": {
    "status": "ok",
    "value": "PICKLE_RECONSTRUCTION_EXECUTED"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "unsafe-serialization-format"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 1
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "value": "PICKLE_RECONSTRUCTION_EXECUTED"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 1
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "unsafe-serialization-format"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `pickle-callable-record`

```json
{
  "id": "pickle-callable-record",
  "input": {
    "format": "pickle",
    "fixture": "callable-record"
  },
  "expected_vulnerable": {
    "status": "ok",
    "value": {
      "marker": "PICKLE_EXPRESSION_EXECUTED",
      "answer": 42
    }
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "unsafe-serialization-format"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 1
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "value": {
          "marker": "PICKLE_EXPRESSION_EXECUTED",
          "answer": 42
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 1
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "unsafe-serialization-format"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `json-object`

```json
{
  "id": "json-object",
  "input": {
    "format": "json",
    "data": "{\"name\":\"Ada\",\"roles\":[\"reader\"],\"active\":true}"
  },
  "expected_vulnerable": {
    "status": "ok",
    "value": {
      "name": "Ada",
      "roles": [
        "reader"
      ],
      "active": true
    }
  },
  "expected_patched": {
    "status": "ok",
    "value": {
      "name": "Ada",
      "roles": [
        "reader"
      ],
      "active": true
    }
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "value": {
          "name": "Ada",
          "roles": [
            "reader"
          ],
          "active": true
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "value": {
          "name": "Ada",
          "roles": [
            "reader"
          ],
          "active": true
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `json-array`

```json
{
  "id": "json-array",
  "input": {
    "format": "json",
    "data": "[1,\"two\",null,3.5]"
  },
  "expected_vulnerable": {
    "status": "ok",
    "value": [
      1,
      "two",
      null,
      3.5
    ]
  },
  "expected_patched": {
    "status": "ok",
    "value": [
      1,
      "two",
      null,
      3.5
    ]
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "value": [
          1,
          "two",
          null,
          3.5
        ]
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "value": [
          1,
          "two",
          null,
          3.5
        ]
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `malformed-json`

```json
{
  "id": "malformed-json",
  "input": {
    "format": "json",
    "data": "{broken"
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-json"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-json"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-json"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-json"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `non-finite-json`

```json
{
  "id": "non-finite-json",
  "input": {
    "format": "json",
    "data": "NaN"
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-json"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-json"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-json"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-json"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `overflowing-json-number`

```json
{
  "id": "overflowing-json-number",
  "input": {
    "format": "json",
    "data": "1e400"
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-json"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-json"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-json"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-json"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-data-type`

```json
{
  "id": "invalid-data-type",
  "input": {
    "format": "json",
    "data": {
      "already": "parsed"
    }
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-data"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-data"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-data"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-data"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `unsupported-format`

```json
{
  "id": "unsupported-format",
  "input": {
    "format": "yaml",
    "data": "name: Ada"
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "unsupported-format"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "unsupported-format"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "unsupported-format"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "unsupported-format"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `missing-format`

```json
{
  "id": "missing-format",
  "input": {},
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "unsupported-format"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "unsupported-format"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "unsupported-format"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "unsupported-format"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-request`

```json
{
  "id": "invalid-request",
  "input": [],
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-request"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-request"
  },
  "expected_vulnerable_observations": {
    "pickle_class_resolutions": 0
  },
  "expected_patched_observations": {
    "pickle_class_resolutions": 0
  },
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-request"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-request"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

</details>

<details>
<summary>Source diff</summary>

```diff
--- vulnerable.py
+++ patched.py
@@ -1,18 +1,8 @@
-"""Intentionally unsafe reconstruction using fixed, harmless pickle fixtures."""
+"""Accept data-only JSON and reject executable serialization formats."""
 
 import json
 import math
-import pickle
 from pathlib import Path
-
-
-class _BenignReconstruction:
-    def __init__(self, expression):
-        self.expression = expression
-
-    def __reduce__(self):
-        # These expressions are fixed below; neither invokes a shell nor uses IO.
-        return eval, (self.expression,)
 
 
 def _reject_constant(value):
@@ -30,26 +20,15 @@
     if not isinstance(payload, dict):
         return {"status": "rejected", "reason": "invalid-request"}
     format_name = payload.get("format")
-    if format_name == "json":
-        data = payload.get("data")
-        if not isinstance(data, str) or len(data) > 8192:
-            return {"status": "rejected", "reason": "invalid-data"}
-        try:
-            value = json.loads(data, parse_constant=_reject_constant, parse_float=_finite_float)
-        except (ValueError, RecursionError):
-            return {"status": "rejected", "reason": "invalid-json"}
-        return {"status": "ok", "value": value}
     if format_name == "pickle":
-        # Select local examples instead of accepting arbitrary executable blobs.
-        expressions = {
-            "callable-marker": "'PICKLE_RECONSTRUCTION_EXECUTED'",
-            "callable-record": "{'marker': 'PICKLE_EXPRESSION_EXECUTED', 'answer': 6 * 7}",
-        }
-        fixture = payload.get("fixture")
-        if not isinstance(fixture, str) or fixture not in expressions:
-            return {"status": "rejected", "reason": "unknown-fixture"}
-        serialized = pickle.dumps(_BenignReconstruction(expressions[fixture]), protocol=4)
-        # BUG: loads invokes the callable encoded by __reduce__.
-        value = pickle.loads(serialized)
-        return {"status": "ok", "value": value}
-    return {"status": "rejected", "reason": "unsupported-format"}
+        return {"status": "rejected", "reason": "unsafe-serialization-format"}
+    if format_name != "json":
+        return {"status": "rejected", "reason": "unsupported-format"}
+    data = payload.get("data")
+    if not isinstance(data, str) or len(data) > 8192:
+        return {"status": "rejected", "reason": "invalid-data"}
+    try:
+        value = json.loads(data, parse_constant=_reject_constant, parse_float=_finite_float)
+    except (ValueError, RecursionError):
+        return {"status": "rejected", "reason": "invalid-json"}
+    return {"status": "ok", "value": value}
```

</details>

## Contain local file reads within the public directory

**PASS** · `path-traversal` · CWE-22

- Manifest SHA-256: `af4817ad160ad45b5317f9e6a238a5ae74a7a73c29b1f204625f8232fd9bca83`
- Baseline SHA-256: `2cb76ce6522d718ffee2e6345aa6f5ed65ca98398f38a39788f3ed8d5dd54a67`
- Patched SHA-256: `7a98a0d8ef30403152e7d7904141cc44a618ec0adb13fd1b65abb37ecfa6a572`

### Cases

| Case | Kind | Result | Reason |
| --- | --- | --- | --- |
| `parent-traversal` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `sibling-prefix` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `symlink-escape` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `public-file` | regression | PASS | Functional behavior preserved on both versions\. |
| `nested-public-file` | regression | PASS | Functional behavior preserved on both versions\. |
| `normalized-public-file` | regression | PASS | Functional behavior preserved on both versions\. |
| `missing-file` | regression | PASS | Functional behavior preserved on both versions\. |
| `empty-path` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-path-type` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-request` | regression | PASS | Functional behavior preserved on both versions\. |

### Advisory source findings

- vulnerable: no supported patterns detected; this is not a safety verdict.
- patched: no supported patterns detected; this is not a safety verdict.

<details>
<summary>Case evidence (inputs, expectations, observations)</summary>

#### `parent-traversal`

```json
{
  "id": "parent-traversal",
  "input": {
    "path": "../private/secret.txt"
  },
  "expected_vulnerable": {
    "status": "ok",
    "content": "SYNTHETIC_PRIVATE_RECORD\n"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "outside-public-directory"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "SYNTHETIC_PRIVATE_RECORD\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "outside-public-directory"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `sibling-prefix`

```json
{
  "id": "sibling-prefix",
  "input": {
    "path": "../public-backup/secret.txt"
  },
  "expected_vulnerable": {
    "status": "ok",
    "content": "SYNTHETIC_BACKUP_RECORD\n"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "outside-public-directory"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "SYNTHETIC_BACKUP_RECORD\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "outside-public-directory"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `symlink-escape`

```json
{
  "id": "symlink-escape",
  "input": {
    "path": "shortcut/secret.txt"
  },
  "expected_vulnerable": {
    "status": "ok",
    "content": "SYNTHETIC_PRIVATE_RECORD\n"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "outside-public-directory"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "SYNTHETIC_PRIVATE_RECORD\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "outside-public-directory"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `public-file`

```json
{
  "id": "public-file",
  "input": {
    "path": "welcome.txt"
  },
  "expected_vulnerable": {
    "status": "ok",
    "content": "Welcome to Patchproof.\n"
  },
  "expected_patched": {
    "status": "ok",
    "content": "Welcome to Patchproof.\n"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "Welcome to Patchproof.\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "Welcome to Patchproof.\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `nested-public-file`

```json
{
  "id": "nested-public-file",
  "input": {
    "path": "docs/guide.txt"
  },
  "expected_vulnerable": {
    "status": "ok",
    "content": "Nested public guide.\n"
  },
  "expected_patched": {
    "status": "ok",
    "content": "Nested public guide.\n"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "Nested public guide.\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "Nested public guide.\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `normalized-public-file`

```json
{
  "id": "normalized-public-file",
  "input": {
    "path": "docs/../welcome.txt"
  },
  "expected_vulnerable": {
    "status": "ok",
    "content": "Welcome to Patchproof.\n"
  },
  "expected_patched": {
    "status": "ok",
    "content": "Welcome to Patchproof.\n"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "Welcome to Patchproof.\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "content": "Welcome to Patchproof.\n"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `missing-file`

```json
{
  "id": "missing-file",
  "input": {
    "path": "missing.txt"
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "not-found"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "not-found"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "not-found"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "not-found"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `empty-path`

```json
{
  "id": "empty-path",
  "input": {
    "path": ""
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-path"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-path"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-path"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-path"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-path-type`

```json
{
  "id": "invalid-path-type",
  "input": {
    "path": [
      "welcome.txt"
    ]
  },
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-path"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-path"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-path"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-path"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-request`

```json
{
  "id": "invalid-request",
  "input": null,
  "expected_vulnerable": {
    "status": "rejected",
    "reason": "invalid-request"
  },
  "expected_patched": {
    "status": "rejected",
    "reason": "invalid-request"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-request"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "rejected",
        "reason": "invalid-request"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

</details>

<details>
<summary>Source diff</summary>

```diff
--- vulnerable.py
+++ patched.py
@@ -1,4 +1,4 @@
-"""Intentionally vulnerable path lookup over disposable local fixtures."""
+"""Resolved-path containment for the static local path-traversal fixtures."""
 
 from pathlib import Path
 
@@ -25,16 +25,14 @@
         return {"status": "rejected", "reason": "invalid-path"}
     try:
         public = _fixtures(workspace, "shortcut" in Path(requested).parts)
-        candidate = public / requested
-        # Harness guard: even the vulnerable example may read only this workspace.
-        # This does NOT enforce the application's public-directory boundary.
-        candidate.resolve().relative_to(workspace.resolve())
+        candidate = (public / requested).resolve()
+        # Path components matter: string-prefix checks accept public-backup/.
+        candidate.relative_to(public.resolve())
     except ValueError:
-        return {"status": "rejected", "reason": "outside-fixture-workspace"}
+        return {"status": "rejected", "reason": "outside-public-directory"}
     except (OSError, RuntimeError):
         return {"status": "rejected", "reason": "fixture-unavailable"}
     try:
-        # BUG: joining a caller's path does not constrain it to public/.
         return {"status": "ok", "content": candidate.read_text(encoding="utf-8")}
     except FileNotFoundError:
         return {"status": "rejected", "reason": "not-found"}
```

</details>

## Interpolated SQL account identifier

**PASS** · `sql-injection` · CWE-89

- Manifest SHA-256: `f87100aece3dee6df0c605edd4477d469fe86b909483506887c567f994cbbee4`
- Baseline SHA-256: `d8733e1685938d70fc7552212811f8a24058c9f2686ab2f6583b03b6dd2b709b`
- Patched SHA-256: `7b50f6439cecec09a75a4370a5b0a40652beaf8b616254d185b07ca203fe9df6`

### Cases

| Case | Kind | Result | Reason |
| --- | --- | --- | --- |
| `boolean-login-bypass` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `union-login-bypass` | attack | PASS | Baseline reproduced; patch matched the declared response and observations\. |
| `valid-admin-login` | regression | PASS | Functional behavior preserved on both versions\. |
| `quoted-password-preserved` | regression | PASS | Functional behavior preserved on both versions\. |
| `decimal-string-id` | regression | PASS | Functional behavior preserved on both versions\. |
| `wrong-password` | regression | PASS | Functional behavior preserved on both versions\. |
| `unknown-account` | regression | PASS | Functional behavior preserved on both versions\. |
| `missing-credentials` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-password-type` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-id-type` | regression | PASS | Functional behavior preserved on both versions\. |
| `malformed-id` | regression | PASS | Functional behavior preserved on both versions\. |
| `invalid-request-type` | regression | PASS | Functional behavior preserved on both versions\. |

### Advisory source findings

- vulnerable:43 — PP004 (CWE-89): Dynamically constructed SQL\-like statement; review parameter binding\.
- patched: no supported patterns detected; this is not a safety verdict.

<details>
<summary>Case evidence (inputs, expectations, observations)</summary>

#### `boolean-login-bypass`

```json
{
  "id": "boolean-login-bypass",
  "input": {
    "account_id": "1 OR 1=1",
    "password": "wrong"
  },
  "expected_vulnerable": {
    "status": "ok",
    "account": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    }
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 1,
          "username": "admin",
          "role": "admin"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `union-login-bypass`

```json
{
  "id": "union-login-bypass",
  "input": {
    "account_id": "999 UNION SELECT id, username, role FROM users WHERE id = 1 OR 1 = 0",
    "password": "wrong"
  },
  "expected_vulnerable": {
    "status": "ok",
    "account": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    }
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 1,
          "username": "admin",
          "role": "admin"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `valid-admin-login`

```json
{
  "id": "valid-admin-login",
  "input": {
    "account_id": 1,
    "password": "admin-demo-only"
  },
  "expected_vulnerable": {
    "status": "ok",
    "account": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    }
  },
  "expected_patched": {
    "status": "ok",
    "account": {
      "id": 1,
      "username": "admin",
      "role": "admin"
    }
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 1,
          "username": "admin",
          "role": "admin"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 1,
          "username": "admin",
          "role": "admin"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `quoted-password-preserved`

```json
{
  "id": "quoted-password-preserved",
  "input": {
    "account_id": 2,
    "password": "reader's-demo-only"
  },
  "expected_vulnerable": {
    "status": "ok",
    "account": {
      "id": 2,
      "username": "reader",
      "role": "member"
    }
  },
  "expected_patched": {
    "status": "ok",
    "account": {
      "id": 2,
      "username": "reader",
      "role": "member"
    }
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 2,
          "username": "reader",
          "role": "member"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 2,
          "username": "reader",
          "role": "member"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `decimal-string-id`

```json
{
  "id": "decimal-string-id",
  "input": {
    "account_id": "2",
    "password": "reader's-demo-only"
  },
  "expected_vulnerable": {
    "status": "ok",
    "account": {
      "id": 2,
      "username": "reader",
      "role": "member"
    }
  },
  "expected_patched": {
    "status": "ok",
    "account": {
      "id": 2,
      "username": "reader",
      "role": "member"
    }
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 2,
          "username": "reader",
          "role": "member"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "ok",
        "account": {
          "id": 2,
          "username": "reader",
          "role": "member"
        }
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `wrong-password`

```json
{
  "id": "wrong-password",
  "input": {
    "account_id": 1,
    "password": "wrong"
  },
  "expected_vulnerable": {
    "status": "unauthorized"
  },
  "expected_patched": {
    "status": "unauthorized"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `unknown-account`

```json
{
  "id": "unknown-account",
  "input": {
    "account_id": 999,
    "password": "wrong"
  },
  "expected_vulnerable": {
    "status": "unauthorized"
  },
  "expected_patched": {
    "status": "unauthorized"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "unauthorized"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `missing-credentials`

```json
{
  "id": "missing-credentials",
  "input": {},
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-password-type`

```json
{
  "id": "invalid-password-type",
  "input": {
    "account_id": 1,
    "password": []
  },
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-id-type`

```json
{
  "id": "invalid-id-type",
  "input": {
    "account_id": true,
    "password": "admin-demo-only"
  },
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `malformed-id`

```json
{
  "id": "malformed-id",
  "input": {
    "account_id": "'",
    "password": "wrong"
  },
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

#### `invalid-request-type`

```json
{
  "id": "invalid-request-type",
  "input": null,
  "expected_vulnerable": {
    "status": "invalid_input"
  },
  "expected_patched": {
    "status": "invalid_input"
  },
  "expected_vulnerable_observations": null,
  "expected_patched_observations": null,
  "observed": {
    "vulnerable": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    },
    "patched": {
      "status": "ok",
      "value": {
        "status": "invalid_input"
      },
      "returncode": 0,
      "observations": {
        "pickle_class_resolutions": 0
      }
    }
  }
}
```

</details>

<details>
<summary>Source diff</summary>

```diff
--- vulnerable.py
+++ patched.py
@@ -1,4 +1,4 @@
-"""Intentionally vulnerable authentication against a disposable SQLite database."""
+"""Validate the identifier and bind every request value as a SQL parameter."""
 
 import sqlite3
 from contextlib import closing
@@ -24,9 +24,15 @@
         or len(password) > 128
     ):
         return {"status": "invalid_input"}
-    if isinstance(account_id, str) and not 1 <= len(account_id) <= 256:
-        return {"status": "invalid_input"}
-    if isinstance(account_id, int) and not 1 <= account_id <= 1_000_000:
+    if isinstance(account_id, str):
+        if not (
+            1 <= len(account_id) <= 256
+            and account_id.isascii()
+            and account_id.isdecimal()
+        ):
+            return {"status": "invalid_input"}
+        account_id = int(account_id)
+    if not 1 <= account_id <= 1_000_000:
         return {"status": "invalid_input"}
 
     with closing(sqlite3.connect(":memory:")) as database:
@@ -34,19 +40,14 @@
             "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)"
         )
         database.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", ACCOUNTS)
-        # FLAW: binding the password does not protect interpolated account_id.
-        query = (
-            "SELECT id, username, role FROM users "
-            f"WHERE id = {account_id} AND password = ? ORDER BY id"
-        )
+        # FIX: both request values are data, never executable SQL syntax.
+        query = "SELECT id, username, role FROM users WHERE id = ? AND password = ? ORDER BY id"
         try:
-            account = database.execute(query, (password,)).fetchone()
+            account = database.execute(query, (account_id, password)).fetchone()
         except (sqlite3.Error, UnicodeError):
             return {"status": "invalid_input"}
     if account is None:
         return {"status": "unauthorized"}
-    if not isinstance(account[0], int) or not all(isinstance(value, str) for value in account[1:]):
-        return {"status": "invalid_input"}
     return {
         "status": "ok",
         "account": {"id": account[0], "username": account[1], "role": account[2]},
```

</details>
