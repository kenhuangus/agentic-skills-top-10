import json
import tempfile
import time
import unittest
from pathlib import Path

from _util import REPO, copy_fixture, rules
from ast_mitigations import ast09_governance as m


class Workflow(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.inv = m.SkillInventory(self.tmp / "inventory.json")
        self.skill = copy_fixture("benign-skill")
        self.inv.request("weather-lookup", "1.2.0", self.skill, installer="dev:bob", risk_tier="L1")

    def test_requires_scan_and_separation_of_duties(self):
        with self.assertRaises(m.GovernanceError):
            self.inv.approve("weather-lookup", "sec:alice")  # no scan yet
        self.inv.record_scan("weather-lookup", "pass")
        with self.assertRaises(m.GovernanceError):
            self.inv.approve("weather-lookup", "dev:bob")    # self-approval
        rec = self.inv.approve("weather-lookup", "sec:alice")
        self.assertEqual(rec.nhi, "nhi:skill:weather-lookup")
        self.assertTrue(self.inv.is_permitted("weather-lookup", self.skill))

    def test_l3_requires_security(self):
        self.inv.records["weather-lookup"].risk_tier = "L3"
        self.inv.record_scan("weather-lookup", "pass")
        with self.assertRaises(m.GovernanceError):
            self.inv.approve("weather-lookup", "dev:carol")
        self.inv.approve("weather-lookup", "security:dana")

    def test_drift_after_approval_blocks_load(self):
        self.inv.record_scan("weather-lookup", "pass")
        self.inv.approve("weather-lookup", "sec:alice")
        (self.skill / "SKILL.md").write_text("changed")
        self.assertFalse(self.inv.is_permitted("weather-lookup", self.skill))
        self.assertIn("AST09-SHADOW-SKILL", rules(self.inv.find_shadow({"weather-lookup": self.skill})))

    def test_offboarding_and_orphans(self):
        self.inv.record_scan("weather-lookup", "pass")
        self.inv.approve("weather-lookup", "sec:alice")
        self.assertIn("AST09-ORPHANED", rules(self.inv.audit(active_identities={"sec:alice"})))
        self.assertEqual(self.inv.offboard("dev:bob", actor="hr-system"), ["weather-lookup"])
        self.assertEqual(self.inv.records["weather-lookup"].state, "revoked")
        self.assertFalse(self.inv.is_permitted("weather-lookup", self.skill))

    def test_persistence_and_export(self):
        self.inv.record_scan("weather-lookup", "pass")
        self.inv.approve("weather-lookup", "sec:alice")
        again = m.SkillInventory(self.tmp / "inventory.json")
        self.assertEqual(again.records["weather-lookup"].state, "approved")
        csv_text = again.export_csv()
        self.assertIn("weather-lookup", csv_text.splitlines()[1])

    def test_unknown_skill_is_shadow(self):
        self.assertIn("AST09-SHADOW-SKILL", rules(self.inv.find_shadow({"rogue": self.skill})))


class Receipts(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "receipts.jsonl"
        self.log = m.ReceiptLog(self.path)

    @unittest.skipUnless((REPO / "examples" / "ast09-execution-receipts" / "deny-admission-receipt.json").exists(),
                         "AST09 receipt vector not present in this checkout")
    def test_matches_repo_vector(self):
        vec = json.loads((REPO / "examples" / "ast09-execution-receipts" / "deny-admission-receipt.json").read_text())
        r = m.admission_receipt(vec["agent_id"], vec["action_type"], vec["scope"], vec["policy_version"],
                                vec["decision"], vec["timestamp_ms"])
        self.assertEqual(r["attempt_id"], vec["attempt_id"])

    def test_clean_log(self):
        a = self.log.admit(agent_id="nhi:skill:w", action_type="http.get", scope="api.example.com",
                           policy_version="p1", decision="ALLOW", timestamp_ms=1)
        self.log.outcome(a["attempt_id"], "ok", "sha256:r", timestamp_ms=2)
        self.log.admit(agent_id="nhi:skill:w", action_type="fs.delete", scope="/", policy_version="p1",
                       decision="DENY", timestamp_ms=3)
        self.assertEqual(m.ReceiptLog(self.path).verify(), [])

    def test_outcome_after_deny(self):
        a = self.log.admit(agent_id="a", action_type="fs.delete", scope="/", policy_version="p1",
                           decision="DENY", timestamp_ms=1)
        self.log.outcome(a["attempt_id"], "ok")
        self.assertIn("AST09-OUTCOME-AFTER-DENY", rules(self.log.verify()))

    def test_tamper_and_delete(self):
        for i in range(3):
            a = self.log.admit(agent_id="a", action_type="x", scope=str(i), policy_version="p", decision="ALLOW",
                               timestamp_ms=i)
            self.log.outcome(a["attempt_id"], "ok", timestamp_ms=i)
        lines = self.path.read_text().splitlines()
        e = json.loads(lines[0]); e["receipt"]["scope"] = "/etc"; lines[0] = json.dumps(e)
        del lines[3]
        self.path.write_text("\n".join(lines) + "\n")
        found = rules(m.ReceiptLog(self.path).verify())
        self.assertTrue({"AST09-RECEIPT-TAMPER", "AST09-ATTEMPT-ID", "AST09-RECEIPT-CHAIN",
                         "AST09-MISSING-OUTCOME"} <= found)


if __name__ == "__main__":
    unittest.main()
