"""Behavioral checks for execution bounds and the worker JSON protocol."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

from patchproof.sandbox import ExecutionResult, MAX_INPUT_BYTES, run_case


class SandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="patchproof-test-")
        self.addCleanup(self.directory.cleanup)
        self.module = Path(self.directory.name) / "target.py"

    def target(self, source: str) -> Path:
        self.module.write_text(textwrap.dedent(source), encoding="utf-8")
        return self.module

    def test_success_uses_fresh_workspace_and_removes_it(self) -> None:
        target = self.target("""
            import sys
            def run(payload, workspace):
                print("target diagnostic")
                (workspace / "marker").write_text("created")
                return {"input": payload, "cwd": str(workspace),
                        "isolated": sys.flags.isolated, "no_site": sys.flags.no_site}
        """)
        result = run_case(target, {"message": "hello", "items": [1, True, None]})
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(result.value["input"], {"message": "hello", "items": [1, True, None]})
        self.assertNotEqual(result.value["cwd"], str(target.parent))
        self.assertFalse(Path(result.value["cwd"]).exists())
        self.assertEqual(result.value["isolated"], 1)
        self.assertEqual(result.value["no_site"], 1)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.observations, {"pickle_class_resolutions": 0})
        self.assertIn("target diagnostic", result.stderr)
        self.assertNotIn("target diagnostic", result.stdout)
        second = run_case(target, None)
        self.assertEqual(second.status, "ok")
        self.assertNotEqual(result.value["cwd"], second.value["cwd"])

    def test_environment_does_not_inherit_secrets_or_pythonpath(self) -> None:
        target = self.target("""
            import os
            def run(payload, workspace):
                return {"secret": os.getenv("PATCHPROOF_TEST_SECRET"),
                        "pythonpath": os.getenv("PYTHONPATH"),
                        "home_is_temporary": os.getenv("HOME") == str(workspace),
                        "temp_is_temporary": os.getenv("TMPDIR") == str(workspace)}
        """)
        with patch.dict(os.environ, {"PATCHPROOF_TEST_SECRET": "test-only", "PYTHONPATH": "/bad"}):
            result = run_case(target, None)
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(result.value, {"secret": None, "pythonpath": None,
                                       "home_is_temporary": True, "temp_is_temporary": True})

    def test_exception_and_system_exit_are_errors(self) -> None:
        for statement in ("raise RuntimeError('broken case')", "raise SystemExit(0)"):
            with self.subTest(statement=statement):
                target = self.target(f"def run(payload, workspace):\n    {statement}\n")
                result = run_case(target, None)
                self.assertEqual(result.status, "error")
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(result.value)
                self.assertEqual(result.observations, {})

    def test_audit_observes_reconstruction_even_when_target_returns_denial(self) -> None:
        target = self.target("""
            import pickle
            def run(payload, workspace):
                reconstructed = pickle.loads(payload.encode("ascii"))
                assert reconstructed == "proof marker"
                return {"accepted": False, "error": "pickle disabled"}
        """)
        # A harmless protocol-0 proof resolves builtins.str and reconstructs a
        # marker string. Its observation survives an apparently safe response.
        proof = "cbuiltins\nstr\n(Vproof marker\ntR."
        result = run_case(target, proof)
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(result.value, {"accepted": False, "error": "pickle disabled"})
        self.assertEqual(result.observations, {"pickle_class_resolutions": 1})

    def test_audit_hook_is_active_before_target_import(self) -> None:
        target = self.target("""
            import pickle
            proof = b"cbuiltins\\nstr\\n(Vproof marker\\ntR."
            imported = pickle.loads(proof)
            def run(payload, workspace):
                return [imported, pickle.loads(proof)]
        """)
        result = run_case(target, None)
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(result.value, ["proof marker", "proof marker"])
        self.assertEqual(result.observations, {"pickle_class_resolutions": 2})

    def test_audit_counts_class_resolution_not_all_unpickling(self) -> None:
        target = self.target("""
            import pickle
            def run(payload, workspace):
                return pickle.loads(pickle.dumps({"item": 1}))
        """)
        result = run_case(target, None)
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(result.value, {"item": 1})
        self.assertEqual(result.observations, {"pickle_class_resolutions": 0})

    def test_execution_result_preserves_positions_and_independent_defaults(self) -> None:
        first = ExecutionResult("error", None, "output", "error", 1, 0.5)
        second = ExecutionResult("error")
        first.observations["pickle_class_resolutions"] = 1
        self.assertEqual(first.duration_seconds, 0.5)
        self.assertEqual(second.observations, {})

    def test_timeout_terminates_worker_promptly(self) -> None:
        target = self.target("""
            import time
            def run(payload, workspace):
                time.sleep(10)
        """)
        result = run_case(target, None, timeout=0.15)
        self.assertEqual(result.status, "timeout")
        self.assertLess(result.duration_seconds, 3)
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(os.name == "posix", "Process-group cleanup is POSIX-specific")
    def test_timeout_also_terminates_descendants(self) -> None:
        marker = Path(self.directory.name) / "child-survived"
        child_code = f"import time; from pathlib import Path; time.sleep(0.6); Path({str(marker)!r}).write_text('alive')"
        target = self.target(f"""
            import subprocess
            import sys
            import time
            def run(payload, workspace):
                subprocess.Popen([sys.executable, "-c", {child_code!r}])
                time.sleep(10)
        """)
        result = run_case(target, None, timeout=0.2)
        self.assertEqual(result.status, "timeout")
        time.sleep(0.7)
        self.assertFalse(marker.exists(), "Descendant survived worker timeout")

    @unittest.skipUnless(os.name == "posix", "Process-group cleanup is POSIX-specific")
    def test_success_cleans_background_processes_holding_pipes(self) -> None:
        target = self.target("""
            import subprocess
            import sys
            def run(payload, workspace):
                subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
                return "done"
        """)
        result = run_case(target, None, timeout=1.0)
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(result.value, "done")
        self.assertLess(result.duration_seconds, 1.0)

    def test_output_limit_applies_to_either_stream(self) -> None:
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor):
                target = self.target(f"""
                    import os
                    def run(payload, workspace):
                        for _ in range(100):
                            os.write({descriptor}, b"x" * 8192)
                        return None
                """)
                result = run_case(target, None, max_output_bytes=1024)
                self.assertEqual(result.status, "output_limit")
                self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024)
                self.assertLess(result.duration_seconds, 3)

    def test_output_budget_is_shared_across_streams(self) -> None:
        target = self.target("""
            import os
            def run(payload, workspace):
                os.write(1, b"x" * 700)
                os.write(2, b"x" * 700)
                return None
        """)
        result = run_case(target, None, max_output_bytes=1024)
        self.assertEqual(result.status, "output_limit")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024)

    def test_output_limit_also_bounds_serialized_return_values(self) -> None:
        target = self.target("def run(payload, workspace):\n    return 'x' * 100000\n")
        result = run_case(target, None, max_output_bytes=1024)
        self.assertEqual(result.status, "output_limit")
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024)

    def test_malformed_worker_response_is_error(self) -> None:
        observations = b'"observations":{"pickle_class_resolutions":0}'
        responses = [
            b"not-json", b'{"value":null,' + observations + b'} {}',
            b'{"value":NaN,' + observations + b'}',
            b'{"value":1e400,' + observations + b'}',
            b'{"value":1,"value":2,' + observations + b'}',
            b'{"value":null,"extra":true,' + observations + b'}',
            b'{"value":null}', b'{' + observations + b'}', b"[]", b"\xff",
        ]
        for response in responses:
            with self.subTest(response=response):
                target = self.target(f"""
                    import os
                    def run(payload, workspace):
                        os.write(1, {response!r})
                        os._exit(0)
                """)
                result = run_case(target, None)
                self.assertEqual(result.status, "error")
                self.assertIn("Invalid worker response", result.stderr)
                self.assertEqual(result.observations, {})

    def test_malformed_observations_are_errors(self) -> None:
        observations = [
            None, [], {}, {"unknown": 0},
            {"pickle_class_resolutions": True}, {"pickle_class_resolutions": False},
            {"pickle_class_resolutions": -1}, {"pickle_class_resolutions": 1.0},
            {"pickle_class_resolutions": "0"}, {"pickle_class_resolutions": None},
            {"pickle_class_resolutions": 0, "unknown": 1},
        ]
        for observed in observations:
            with self.subTest(observations=observed):
                response = json.dumps({"value": "denied", "observations": observed}).encode("utf-8")
                target = self.target(f"""
                    import os
                    def run(payload, workspace):
                        os.write(1, {response!r})
                        os._exit(0)
                """)
                result = run_case(target, None)
                self.assertEqual(result.status, "error")
                self.assertIn("Invalid worker response", result.stderr)
                self.assertEqual(result.observations, {})
                self.assertIsNone(result.value)

    def test_non_json_input_and_output_are_errors(self) -> None:
        target = self.target("def run(payload, workspace):\n    return float('nan')\n")
        self.assertEqual(run_case(target, None).status, "error")
        for payload in (float("nan"), float("inf"), object(), "x" * MAX_INPUT_BYTES):
            with self.subTest(payload_type=type(payload).__name__):
                result = run_case(target, payload)
                self.assertEqual(result.status, "error")
                self.assertIsNone(result.returncode)

    def test_worker_rejects_non_strict_input(self) -> None:
        import patchproof.sandbox as sandbox

        target = self.target("def run(payload, workspace):\n    return payload\n")
        worker = Path(sandbox.__file__).with_name("_worker.py")
        for payload in (b"NaN", b"1e400", b"{} {}", b'{"x": 1, "x": 2}'):
            with self.subTest(payload=payload):
                result = subprocess.run(
                    [sys.executable, "-I", "-B", "-S", str(worker), str(target)],
                    input=payload, capture_output=True, timeout=2, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_missing_module_returns_error(self) -> None:
        result = run_case(Path(self.directory.name) / "missing.py", None)
        self.assertEqual(result.status, "error")
        self.assertIsNone(result.returncode)

    def test_invalid_settings_raise_value_error(self) -> None:
        target = self.target("def run(payload, workspace):\n    return payload\n")
        for timeout in (0, -1, float("nan"), float("inf"), True, "1", None, 10 ** 1000):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                run_case(target, None, timeout=timeout)
        for budget in (0, -1, 1.5, True, "100", None):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                run_case(target, None, max_output_bytes=budget)


if __name__ == "__main__":
    unittest.main()
