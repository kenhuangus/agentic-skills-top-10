import tempfile
import unittest
from pathlib import Path

from _util import copy_fixture, rules
from ast_mitigations import ast01_malicious as sig
from ast_mitigations import ast07_update_drift as m


def bump(skill_dir: Path, version: str):
    p = skill_dir / "SKILL.md"
    text = p.read_text()
    import re
    p.write_text(re.sub(r"^version: .*$", f"version: {version}", text, count=1, flags=re.M))


class Lock(unittest.TestCase):
    def setUp(self):
        self.install = Path(tempfile.mkdtemp())
        self.skill = copy_fixture("benign-skill")
        self.skill = self.skill.rename(self.install / "weather-lookup")
        self.lock = m.SkillLock.load(self.install / "skills.lock.json")
        self.lock.pin("weather-lookup", "1.2.0", self.skill)
        self.lock.save()

    def test_clean(self):
        self.assertEqual(m.verify_installed(self.lock, self.install), [])

    def test_drift(self):
        (self.skill / "SKILL.md").write_text((self.skill / "SKILL.md").read_text() + "\nnew instruction\n")
        self.assertIn("AST07-DRIFT", rules(m.verify_installed(self.lock, self.install)))

    def test_unpinned(self):
        other = self.install / "rogue"
        other.mkdir()
        (other / "SKILL.md").write_text("---\nname: rogue\n---\n")
        self.assertIn("AST07-UNPINNED", rules(m.verify_installed(self.lock, self.install)))

    def test_hot_reload_guard(self):
        g = m.HotReloadGuard()
        g.load("weather-lookup", self.skill)
        g.check("weather-lookup")
        (self.skill / "SKILL.md").write_text("tampered")
        with self.assertRaises(RuntimeError):
            g.check("weather-lookup")


class Policy(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.lock = m.SkillLock(self.tmp / "lock.json")
        self.v1 = copy_fixture("benign-skill")
        self.lock.pin("weather-lookup", "1.2.0", self.v1)
        self.priv, self.pub = sig.generate_keypair()
        self.trust = sig.TrustStore()
        self.trust.add("did:web:publisher.example.com", self.pub)

    def candidate(self, version, approved="alice", sign=True):
        d = copy_fixture("benign-skill")
        bump(d, version)
        if sign:
            sig.sign_skill(d, self.priv, "did:web:publisher.example.com", "weather-lookup", version)
        return m.UpdateCandidate("weather-lookup", version, str(d), approved_by=approved)

    def test_good_update(self):
        ok, f = m.UpdatePolicy().apply(self.lock, self.candidate("1.3.0"), trust=self.trust)
        self.assertTrue(ok, f)
        self.assertEqual(self.lock.skills["weather-lookup"]["version"], "1.3.0")

    def test_rollback(self):
        ok, f = m.UpdatePolicy().evaluate(self.lock, self.candidate("1.1.0"), trust=self.trust)
        self.assertFalse(ok)
        self.assertIn("AST07-ROLLBACK", rules(f))

    def test_unsigned(self):
        ok, f = m.UpdatePolicy().evaluate(self.lock, self.candidate("1.3.0", sign=False), trust=self.trust)
        self.assertIn("AST01-UNSIGNED", rules(f))

    def test_unapproved_and_frozen(self):
        ok, f = m.UpdatePolicy(freeze=True).evaluate(self.lock, self.candidate("1.3.0", approved=None),
                                                     trust=self.trust)
        self.assertTrue({"AST07-FROZEN", "AST07-UNAPPROVED"} <= rules(f))

    def test_republished_version(self):
        c = self.candidate("1.2.0")
        Path(c.skill_dir, "SKILL.md").write_text(Path(c.skill_dir, "SKILL.md").read_text() + "\n# changed\n")
        ok, f = m.UpdatePolicy(require_signature=False).evaluate(self.lock, c)
        self.assertIn("AST07-SAME-VERSION-DIFFERENT-CONTENT", rules(f))

    def test_advisories(self):
        adv = [{"id": "ADV-1", "skill": "weather-lookup", "affected": ">=1.0.0,<1.3.0", "fixed": "1.3.0"},
               {"id": "ADV-2", "skill": "weather-lookup", "affected": ">=2.0.0"}]
        found = m.match_advisories(self.lock, adv)
        self.assertEqual([f.message.split(" by ")[1].split(";")[0] for f in found], ["ADV-1"])

    def test_stale(self):
        self.lock.skills["weather-lookup"]["verified_at"] = 0
        self.assertIn("AST07-STALE-VERIFICATION", rules(m.UpdatePolicy().stale(self.lock)))

    def test_version_order(self):
        self.assertLess(m.parse_version("1.0.0-rc.1"), m.parse_version("1.0.0"))
        self.assertLess(m.parse_version("1.9.0"), m.parse_version("1.10.0"))


if __name__ == "__main__":
    unittest.main()
