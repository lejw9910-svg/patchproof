import tempfile
import textwrap
import unittest
from pathlib import Path

from patchproof.analyzer import Finding, analyze_file


class AnalyzerTests(unittest.TestCase):
    def analyze(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.py"
            path.write_text(textwrap.dedent(source).lstrip("\n"), encoding="utf-8")
            return analyze_file(path)

    def test_pickle_aliases_are_detected_at_correct_lines(self):
        findings = self.analyze("""
            import pickle as p
            from pickle import loads as decode
            p.load(stream)
            decode(payload)
        """)
        self.assertEqual([(f.rule_id, f.cwe, f.line) for f in findings], [
            ("PP001", "CWE-502", 3), ("PP001", "CWE-502", 4),
        ])
        self.assertTrue(all(f.severity == "warning" for f in findings))

    def test_eval_exec_and_builtin_alias(self):
        findings = self.analyze("""
            import builtins as b
            from builtins import eval as evaluate
            eval(text)
            exec(text)
            b.eval(text)
            evaluate(text)
        """)
        self.assertEqual([f.rule_id for f in findings], ["PP002"] * 4)

    def test_shadowed_builtins_and_imports_are_not_reported(self):
        self.assertEqual(self.analyze("""
            import pickle as p
            p = custom_parser
            p.loads(data)
            def process(eval, exec):
                eval(data)
                exec(data)
        """), [])

    def test_yaml_requires_known_safe_loader(self):
        findings = self.analyze("""
            import yaml as y
            from yaml import load as read, SafeLoader as Safe
            from yaml import CSafeLoader
            y.load(data)
            read(data, Loader=y.Loader)
            y.load(data, Loader=y.SafeLoader)
            read(data, Safe)
            read(data, Loader=CSafeLoader)
            y.safe_load(data)
            y.unsafe_load(data)
        """)
        self.assertEqual([(f.rule_id, f.line) for f in findings], [
            ("PP003", 4), ("PP003", 5), ("PP003", 10),
        ])

    def test_dynamic_sql_forms_and_local_alias(self):
        findings = self.analyze("""
            cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
            cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
            cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
            cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
            query = f"SELECT * FROM users WHERE name = '{name}'"
            alias = query
            cursor.execute(alias)
            cursor.execute(query=query)
        """)
        self.assertEqual([f.line for f in findings], [1, 2, 3, 4, 7, 8])
        self.assertTrue(all(f.rule_id == "PP004" and f.cwe == "CWE-89" for f in findings))

    def test_parameter_binding_and_static_sql_are_not_reported(self):
        self.assertEqual(self.analyze("""
            cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
            cursor.execute("SELECT * FROM users " + "WHERE name = ?", (name,))
            cursor.execute(f"SELECT 1")
            query = f"SELECT {value}"
            query = "SELECT 1"
            cursor.execute(query)
        """), [])

    def test_function_scopes_do_not_leak(self):
        findings = self.analyze("""
            import pickle as p
            def first():
                p = custom_parser
                query = f"SELECT {value}"
            def second():
                p.loads(payload)
                cursor.execute(query)
        """)
        self.assertEqual([(f.rule_id, f.line) for f in findings], [("PP001", 6)])

    def test_deterministic_findings(self):
        source = "import pickle\ncursor.execute(f'SELECT {eval(pickle.loads(data))}')\n"
        first = self.analyze(source)
        self.assertEqual(first, self.analyze(source))
        self.assertEqual([f.rule_id for f in first], ["PP001", "PP002", "PP004"])
        self.assertIsInstance(first[0], Finding)

    def test_invalid_source_propagates_syntax_error(self):
        with self.assertRaises(SyntaxError):
            self.analyze("def invalid(:\n")


if __name__ == "__main__":
    unittest.main()
