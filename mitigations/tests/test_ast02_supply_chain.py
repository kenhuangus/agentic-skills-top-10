import json
import tempfile
import unittest
from pathlib import Path

from _util import FIXTURES, rules
from ast_mitigations import ast02_supply_chain as m


class TransparencyLogTest(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "tlog.jsonl"
        self.log = m.TransparencyLog(self.path)
        self.log.append("publish", "weather", "1.0.0", "sha256:aa", "did:web:p", 1)
        self.log.append("update", "weather", "1.1.0", "sha256:bb", "did:web:p", 2)
        self.log.append("revoke", "weather", "1.0.0", "sha256:aa", "registry", 3)

    def test_verify_and_state(self):
        self.assertEqual(self.log.verify(), [])
        self.assertTrue(self.log.is_logged("weather", "sha256:bb"))
        self.assertFalse(self.log.is_logged("weather", "sha256:aa"))  # revoked
        self.assertFalse(self.log.is_logged("weather", "sha256:zz"))  # never published

    def test_tamper_detected_after_reload(self):
        lines = self.path.read_text().splitlines()
        e = json.loads(lines[1]); e["digest"] = "sha256:evil"; lines[1] = json.dumps(e)
        self.path.write_text("\n".join(lines) + "\n")
        self.assertIn("AST02-TLOG-TAMPER", rules(m.TransparencyLog(self.path).verify()))

    def test_deletion_detected(self):
        lines = self.path.read_text().splitlines()
        del lines[1]
        self.path.write_text("\n".join(lines) + "\n")
        found = rules(m.TransparencyLog(self.path).verify())
        self.assertTrue(found & {"AST02-TLOG-CHAIN", "AST02-TLOG-SEQ"})

    def test_root_changes(self):
        r1 = self.log.root()
        self.log.append("publish", "other", "1.0.0", "sha256:cc", "did:web:q", 4)
        self.assertNotEqual(r1, self.log.root())


class Pins(unittest.TestCase):
    def test_benign_pinned(self):
        self.assertEqual(m.check_dependency_pins(FIXTURES / "benign-skill"), [])

    def test_malicious_unpinned(self):
        found = rules(m.check_dependency_pins(FIXTURES / "malicious-skill"))
        self.assertIn("AST02-UNPINNED-DEP", found)

    def test_package_json(self):
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "^1.3.0"},
                                                    "scripts": {"postinstall": "node x.js"}}))
        found = rules(m.check_dependency_pins(d))
        self.assertTrue({"AST02-UNPINNED-DEP", "AST02-INSTALL-SCRIPT", "AST02-NO-LOCKFILE"} <= found)


class RepoConfig(unittest.TestCase):
    def test_hooks_and_endpoint_override(self):
        found = rules(m.scan_repo_config(FIXTURES / "malicious-skill"))
        self.assertIn("AST02-CONFIG-HOOKS", found)
        self.assertIn("AST02-CONFIG-ENDPOINT-OVERRIDE", found)

    def test_trusted_host_allowed(self):
        d = Path(tempfile.mkdtemp()); (d / ".claude").mkdir()
        (d / ".claude" / "settings.json").write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://gw.corp.example"}}))
        self.assertEqual(m.scan_repo_config(d, trusted_hosts=("corp.example",)), [])

    def test_vscode_autorun(self):
        d = Path(tempfile.mkdtemp()); (d / ".vscode").mkdir()
        (d / ".vscode" / "tasks.json").write_text('{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}')
        self.assertIn("AST02-CONFIG-AUTORUN", rules(m.scan_repo_config(d)))


class Allowlist(unittest.TestCase):
    def test_permits(self):
        a = m.SkillAllowlist({"weather": {"sha256:aa"}})
        self.assertTrue(a.permits("weather", "sha256:aa"))
        self.assertFalse(a.permits("weather", "sha256:bb"))


if __name__ == "__main__":
    unittest.main()
