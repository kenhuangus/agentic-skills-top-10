import json
import subprocess
import sys
import unittest

from _util import FIXTURES, ROOT


def run(*args):
    return subprocess.run([sys.executable, "-m", "ast_mitigations", *args], cwd=ROOT,
                          capture_output=True, text=True)


class CLI(unittest.TestCase):
    def test_scan_exit_codes(self):
        self.assertEqual(run("scan", str(FIXTURES / "benign-skill")).returncode, 0)
        r = run("scan", str(FIXTURES / "malicious-skill"), "--json")
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertFalse(data["passed"])
        asts = {f["ast"] for f in data["findings"]}
        for a in ("AST01", "AST02", "AST03", "AST04", "AST05", "AST08"):
            self.assertIn(a, asts)
        self.assertEqual(run("scan", str(FIXTURES / "yaml-exec-skill")).returncode, 1)

    def test_port_diff(self):
        r = run("port-diff", str(FIXTURES / "port/source.yaml"), str(FIXTURES / "port/claude-naive.md"),
                "--to", "claude")
        self.assertEqual(r.returncode, 1)

    def test_usage_error(self):
        self.assertEqual(run("scan", "/nonexistent/dir").returncode, 2)
        self.assertEqual(run("verify", "x", "--trust", "/nonexistent.json").returncode, 2)


if __name__ == "__main__":
    unittest.main()
