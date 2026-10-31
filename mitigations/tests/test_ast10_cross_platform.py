import unittest

import yaml

from _util import FIXTURES, rules
from ast_mitigations import ast10_cross_platform as m
from ast_mitigations.common import split_frontmatter


def load(name):
    text = (FIXTURES / "port" / name).read_text()
    fm, _ = split_frontmatter(text)
    return yaml.safe_load(fm or text)


class Diff(unittest.TestCase):
    def test_naive_port_flagged(self):
        found = m.check_port(load("source.yaml"), "universal", load("claude-naive.md"), "claude")
        msgs = " ".join(f.message for f in found)
        self.assertIn("risk_tier", msgs)
        self.assertIn("unrestricted egress", msgs)
        self.assertIn("deny_write", msgs)
        self.assertIn("signature", msgs)

    def test_lossless_port_all_platforms(self):
        src = load("source.yaml")
        for platform in ("claude", "cursor", "vscode", "openclaw"):
            ported = m.port_to(m.to_universal(src, "universal"), platform)
            self.assertEqual(m.check_port(src, "universal", ported, platform), [], platform)

    def test_round_trip(self):
        src = load("source.yaml")
        there = m.port_to(src, "cursor")
        back = m.to_universal(there, "cursor")
        self.assertEqual(m.diff_security(src, back), [])

    def test_risk_tier_downgrade(self):
        src = load("source.yaml")
        tgt = dict(src, risk_tier="L1")
        self.assertIn("AST10-PROPERTY-WEAKENED", rules(m.diff_security(src, tgt)))

    def test_content_changed(self):
        src = load("source.yaml")
        tgt = dict(src, content_hash="sha256:other")
        self.assertIn("AST10-CONTENT-CHANGED", rules(m.diff_security(src, tgt)))

    def test_threat_intel_record(self):
        r = m.threat_intel_record("sha256:abc", {"skills.sh": "x", "clawhub": "y"}, ["b", "a", "a"], "high", "r")
        self.assertEqual(r["indicators"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
