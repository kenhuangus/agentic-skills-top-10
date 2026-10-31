import os
import sys
import tempfile
import unittest
from pathlib import Path

from _util import FIXTURES, rules
from ast_mitigations import ast06_isolation as m


class Container(unittest.TestCase):
    def test_hardened_defaults_lint_clean(self):
        argv = m.container_command(str(FIXTURES / "benign-skill"), "python:3.12-slim", ["python3", "x.py"])
        self.assertIn("none", argv[argv.index("--network") + 1])
        self.assertEqual(m.check_container_command(argv), [])

    def test_lint_flags(self):
        argv = ["docker", "run", "--privileged", "--network", "host", "-v",
                "/var/run/docker.sock:/var/run/docker.sock", "img"]
        found = m.check_container_command(argv)
        self.assertTrue(any(f.severity == "critical" for f in found))
        self.assertIn("AST06-WRITABLE-ROOTFS", rules(found))

    def test_seccomp(self):
        p = m.seccomp_profile()
        self.assertIn("ptrace", p["syscalls"][0]["names"])


@unittest.skipIf(sys.platform == "win32", "POSIX only")
class LocalSandbox(unittest.TestCase):
    def test_env_scrubbed(self):
        os.environ["FAKE_API_KEY"] = "should-not-leak"
        try:
            r = m.run_sandboxed([sys.executable, "-c", "import os;print(os.environ.get('FAKE_API_KEY'));print(os.getcwd())"])
        finally:
            del os.environ["FAKE_API_KEY"]
        out = r.stdout.splitlines()
        self.assertEqual(out[0], "None")
        self.assertIn("skill-sbx-", out[1])

    def test_memory_limit(self):
        r = m.run_sandboxed([sys.executable, "-c", "x = bytearray(1024*1024*1024)"], mem_mb=256)
        self.assertNotEqual(r.returncode, 0)


class Listener(unittest.TestCase):
    def test_bad(self):
        found = rules(m.check_listener_config({"host": "0.0.0.0"}))
        self.assertTrue({"AST06-BIND-ALL", "AST06-NO-AUTH", "AST06-NO-ORIGIN-CHECK", "AST06-NO-RATE-LIMIT"} <= found)

    def test_good(self):
        self.assertEqual(m.check_listener_config({
            "host": "127.0.0.1", "auth": {"type": "token", "token_bytes": 32},
            "allowed_origins": ["app://agent"], "rate_limit_per_min": 30}), [])


class WebSocket(unittest.TestCase):
    def test_admission(self):
        ws = m.WebSocketAdmission(token="t" * 43, allowed_origins={"app://agent"}, rate_per_min=100,
                                  lockout_after=3)
        self.assertEqual(ws.admit("127.0.0.1", "https://evil.example", "t" * 43, now=0)[0], False)
        self.assertTrue(ws.admit("127.0.0.1", "app://agent", "t" * 43, now=0)[0])
        for i in range(3):
            self.assertFalse(ws.admit("127.0.0.1", "app://agent", "guess", now=1 + i)[0])
        self.assertEqual(ws.admit("127.0.0.1", "app://agent", "t" * 43, now=5), (False, "locked out"))

    def test_rate_limit(self):
        ws = m.WebSocketAdmission(token="x", allowed_origins={"o"}, rate_per_min=2)
        ws.admit("c", "o", "x", now=0); ws.admit("c", "o", "x", now=1)
        self.assertEqual(ws.admit("c", "o", "x", now=2), (False, "rate limited"))
        self.assertTrue(ws.admit("c", "o", "x", now=120)[0])


class Shadowing(unittest.TestCase):
    def test_detect(self):
        base = Path(tempfile.mkdtemp())
        for tier, names in (("workspace", ["git-helper", "local-only"]), ("bundled", ["git-helper"])):
            for n in names:
                (base / tier / n).mkdir(parents=True)
                (base / tier / n / "SKILL.md").write_text("---\nname: %s\n---\n" % n)
        tiers = [("workspace", base / "workspace"), ("bundled", base / "bundled")]
        found = m.detect_shadowing(tiers)
        self.assertEqual(len(found), 1)
        self.assertIn("git-helper", found[0].message)
        self.assertEqual(m.detect_shadowing(tiers, approved_overrides={"workspace:git-helper"}), [])


if __name__ == "__main__":
    unittest.main()
