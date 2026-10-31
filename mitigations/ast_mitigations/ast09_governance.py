"""AST09 -- No Governance: reference mitigations.

1. Centralised inventory (name, version, hash, install date, installer,
   last scan)                                      -> ``SkillInventory``
2. Approval workflow                               -> ``SkillInventory.request / approve / reject``
3. Agentic (non-human) identity with scoped,
   rotated credentials                             -> ``SkillInventory.nhi`` + ``ast03.ScopedCredentialBroker``
4. Audit logging of every skill action             -> ``ReceiptLog`` (admission + outcome receipts,
                                                      hash-chained; compatible with
                                                      ``examples/ast09-execution-receipts``)
5. CMDB / ITSM export                              -> ``SkillInventory.export_csv``
6. Revocation tied to offboarding / IR             -> ``SkillInventory.offboard / revoke``
"""

from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .common import Finding, canonical_digest, jcs, sha256_bytes

AST = "AST09"

STATES = ("requested", "approved", "rejected", "revoked")


@dataclass
class InventoryRecord:
    name: str
    version: str
    digest: str
    installer: str
    owner: str
    state: str = "requested"
    risk_tier: str = ""
    requested_at: int = field(default_factory=lambda: int(time.time()))
    approved_by: str = ""
    approved_at: int = 0
    last_scan_at: int = 0
    last_scan_result: str = ""
    nhi: str = ""                 # non-human identity assigned to this skill
    credential_rotated_at: int = 0
    history: list[dict] = field(default_factory=list)


class GovernanceError(Exception):
    pass


class SkillInventory:
    """JSON-backed inventory + approval workflow. Production deployments should
    back this with the CMDB; the state machine and checks stay the same."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.records: dict[str, InventoryRecord] = {}
        if self.path.exists():
            for k, v in json.loads(self.path.read_text(encoding="utf-8")).items():
                self.records[k] = InventoryRecord(**v)

    def save(self) -> None:
        self.path.write_text(json.dumps({k: asdict(v) for k, v in sorted(self.records.items())},
                                        indent=2) + "\n", encoding="utf-8")

    def _event(self, rec: InventoryRecord, event: str, actor: str, **extra) -> None:
        rec.history.append({"event": event, "actor": actor, "ts": int(time.time()), **extra})

    # -- workflow --
    def request(self, name: str, version: str, skill_dir: str | Path, installer: str,
                owner: str | None = None, risk_tier: str = "") -> InventoryRecord:
        rec = InventoryRecord(name=name, version=version, digest=canonical_digest(skill_dir),
                              installer=installer, owner=owner or installer, risk_tier=risk_tier)
        self._event(rec, "requested", installer)
        self.records[name] = rec
        self.save()
        return rec

    def record_scan(self, name: str, result: str) -> None:
        rec = self.records[name]
        rec.last_scan_at, rec.last_scan_result = int(time.time()), result
        self._event(rec, "scanned", "scanner", result=result)
        self.save()

    def approve(self, name: str, approver: str, nhi: str | None = None) -> InventoryRecord:
        rec = self.records[name]
        if rec.state != "requested":
            raise GovernanceError(f"{name} is {rec.state}, not requested")
        if approver == rec.installer:
            raise GovernanceError("separation of duties: installer cannot approve their own request")
        if rec.last_scan_result != "pass":
            raise GovernanceError("cannot approve without a passing security scan")
        if rec.risk_tier == "L3" and not approver.startswith("security:"):
            raise GovernanceError("L3 (destructive) skills require approval from the security team")
        rec.state, rec.approved_by, rec.approved_at = "approved", approver, int(time.time())
        rec.nhi = nhi or f"nhi:skill:{name}"
        rec.credential_rotated_at = int(time.time())
        self._event(rec, "approved", approver, nhi=rec.nhi)
        self.save()
        return rec

    def reject(self, name: str, approver: str, reason: str) -> None:
        rec = self.records[name]
        rec.state = "rejected"
        self._event(rec, "rejected", approver, reason=reason)
        self.save()

    def revoke(self, name: str, actor: str, reason: str) -> None:
        rec = self.records[name]
        rec.state = "revoked"
        self._event(rec, "revoked", actor, reason=reason)
        self.save()

    def is_permitted(self, name: str, skill_dir: str | Path) -> bool:
        """Load-time gate: only approved skills whose on-disk digest still
        matches the approved digest may run."""
        rec = self.records.get(name)
        return bool(rec and rec.state == "approved" and canonical_digest(skill_dir) == rec.digest)

    # -- hygiene --
    def offboard(self, identity: str, actor: str, reassign_to: str | None = None) -> list[str]:
        """Offboarding hook: revoke (or reassign) every skill installed/owned by
        ``identity`` so nothing keeps running on a departed user's authority."""
        touched = []
        for rec in self.records.values():
            if rec.state == "approved" and identity in (rec.installer, rec.owner):
                if reassign_to:
                    rec.owner = reassign_to
                    self._event(rec, "reassigned", actor, frm=identity, to=reassign_to)
                else:
                    rec.state = "revoked"
                    self._event(rec, "revoked", actor, reason=f"offboarding {identity}")
                touched.append(rec.name)
        self.save()
        return touched

    def audit(self, active_identities: set[str], max_scan_age_days: int = 30,
              max_credential_age_days: int = 90, now: float | None = None) -> list[Finding]:
        now = time.time() if now is None else now
        out = []
        for rec in sorted(self.records.values(), key=lambda r: r.name):
            if rec.state != "approved":
                continue
            if rec.owner not in active_identities:
                out.append(Finding(AST, "AST09-ORPHANED", "high",
                                   f"{rec.name}: owner {rec.owner!r} is no longer an active identity"))
            if now - rec.last_scan_at > max_scan_age_days * 86400:
                out.append(Finding(AST, "AST09-STALE-SCAN", "medium",
                                   f"{rec.name}: last scanned {int((now - rec.last_scan_at) / 86400)} days ago"))
            if now - rec.credential_rotated_at > max_credential_age_days * 86400:
                out.append(Finding(AST, "AST09-CREDENTIAL-ROTATION", "medium",
                                   f"{rec.name}: NHI credential not rotated in {max_credential_age_days} days"))
        return out

    def find_shadow(self, installed: dict[str, str | Path]) -> list[Finding]:
        """Compare what is actually installed against the inventory (shadow AI)."""
        out = []
        for name, d in sorted(installed.items()):
            if not self.is_permitted(name, d):
                rec = self.records.get(name)
                why = "not in inventory" if rec is None else f"state={rec.state}" if rec.state != "approved" \
                    else "on-disk digest differs from approved digest"
                out.append(Finding(AST, "AST09-SHADOW-SKILL", "high", f"{name}: {why}", str(d)))
        return out

    def export_csv(self) -> str:
        """Flat export for CMDB / ITSM / CASB ingestion."""
        buf = io.StringIO()
        cols = ["name", "version", "digest", "state", "risk_tier", "installer", "owner", "approved_by",
                "approved_at", "last_scan_at", "last_scan_result", "nhi"]
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for rec in sorted(self.records.values(), key=lambda r: r.name):
            w.writerow({c: getattr(rec, c) for c in cols})
        return buf.getvalue()


# ---------------------------------------------------------------------------
# 4. Execution receipts
# ---------------------------------------------------------------------------

ADMISSION_PREIMAGE = ("agent_id", "action_type", "scope", "policy_version", "timestamp_ms")


def admission_receipt(agent_id: str, action_type: str, scope: str, policy_version: str,
                      decision: str, timestamp_ms: int | None = None) -> dict:
    """Seven-field admission receipt as in AST09 'Execution Receipts'. The
    ``attempt_id`` derivation matches ``examples/ast09-execution-receipts``."""
    if decision not in ("ALLOW", "DENY"):
        raise ValueError("decision must be ALLOW or DENY")
    rec = {"agent_id": agent_id, "action_type": action_type, "scope": scope,
           "policy_version": policy_version,
           "timestamp_ms": int(time.time() * 1000) if timestamp_ms is None else timestamp_ms}
    rec["attempt_id"] = sha256_bytes(jcs({k: rec[k] for k in ADMISSION_PREIMAGE}).encode())
    rec["decision"] = decision
    return rec


class ReceiptLog:
    """Append-only, hash-chained JSONL of admission and outcome receipts.

    ``verify`` detects: altered receipts (attempt_id no longer recomputes),
    deleted / reordered entries (chain break), outcomes for actions that were
    denied or never admitted, and admitted actions with no outcome."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.entries: list[dict] = []
        if self.path.exists():
            self.entries = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _append(self, kind: str, receipt: dict) -> dict:
        prev = self.entries[-1]["chain"] if self.entries else "0" * 64
        entry = {"kind": kind, "receipt": receipt, "prev": prev}
        entry["chain"] = sha256_bytes(jcs(entry).encode())
        self.entries.append(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(jcs(entry) + "\n")
        return entry

    def admit(self, **kw) -> dict:
        r = admission_receipt(**kw)
        self._append("admission", r)
        return r

    def outcome(self, attempt_id: str, status: str, result_digest: str = "", timestamp_ms: int | None = None) -> dict:
        r = {"attempt_id": attempt_id, "status": status, "result_digest": result_digest,
             "timestamp_ms": int(time.time() * 1000) if timestamp_ms is None else timestamp_ms}
        self._append("outcome", r)
        return r

    def verify(self, require_outcomes: bool = True) -> list[Finding]:
        out = []
        prev = "0" * 64
        admissions: dict[str, str] = {}
        outcomes: set[str] = set()
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "chain"}
            if e.get("prev") != prev:
                out.append(Finding(AST, "AST09-RECEIPT-CHAIN", "critical", f"entry {i}: chain broken (deleted/reordered)"))
            if sha256_bytes(jcs(body).encode()) != e.get("chain"):
                out.append(Finding(AST, "AST09-RECEIPT-TAMPER", "critical", f"entry {i}: entry content altered"))
            prev = e.get("chain", "")
            r = e.get("receipt", {})
            if e.get("kind") == "admission":
                expect = sha256_bytes(jcs({k: r.get(k) for k in ADMISSION_PREIMAGE}).encode())
                if r.get("attempt_id") != expect:
                    out.append(Finding(AST, "AST09-ATTEMPT-ID", "critical", f"entry {i}: attempt_id does not recompute"))
                admissions[r.get("attempt_id")] = r.get("decision")
            elif e.get("kind") == "outcome":
                aid = r.get("attempt_id")
                if aid not in admissions:
                    out.append(Finding(AST, "AST09-OUTCOME-WITHOUT-ADMISSION", "critical",
                                       f"entry {i}: outcome for un-admitted attempt {str(aid)[:16]}"))
                elif admissions[aid] == "DENY":
                    out.append(Finding(AST, "AST09-OUTCOME-AFTER-DENY", "critical",
                                       f"entry {i}: denied action {str(aid)[:16]} was executed anyway"))
                outcomes.add(aid)
        if require_outcomes:
            for aid, dec in admissions.items():
                if dec == "ALLOW" and aid not in outcomes:
                    out.append(Finding(AST, "AST09-MISSING-OUTCOME", "medium",
                                       f"allowed attempt {aid[:16]} has no outcome receipt"))
        return out
