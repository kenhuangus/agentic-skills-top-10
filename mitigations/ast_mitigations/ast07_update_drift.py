"""AST07 -- Update Drift: reference mitigations.

1. Pin installed skills to content hashes           -> ``SkillLock``
2. Signature verification on every update           -> ``UpdatePolicy.evaluate`` (via AST01 ``verify_skill``)
3. Freeze mode / no hot-reload in production        -> ``UpdatePolicy.freeze``, ``HotReloadGuard``
4. Advisory matching                                -> ``match_advisories``
5. Human approval for updates                       -> ``UpdatePolicy.require_approval``
6. Inventory with version / hash / last-verified    -> ``SkillLock`` + ``verify_installed``

Rollback attacks are blocked by refusing any update whose version is lower
than the pinned one unless explicitly allowed for a recorded incident.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from .common import Finding, canonical_digest

AST = "AST07"


def parse_version(v: str) -> tuple:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", str(v))
    if not m:
        raise ValueError(f"not a semver: {v!r}")
    major, minor, patch, pre = m.groups()
    # pre-releases sort before the release
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


# ---------------------------------------------------------------------------
# 1/6. Lockfile
# ---------------------------------------------------------------------------

@dataclass
class SkillLock:
    """``skills.lock.json``: name -> {version, digest, key_id, source, verified_at}."""
    path: Path
    skills: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "SkillLock":
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        return cls(p, data.get("skills", {}))

    def save(self) -> None:
        self.path.write_text(json.dumps({"lockfile_version": 1, "skills": self.skills},
                                        indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def pin(self, name: str, version: str, skill_dir: str | Path, key_id: str = "",
            source: str = "") -> dict:
        entry = {"version": version, "digest": canonical_digest(skill_dir), "key_id": key_id,
                 "source": source, "verified_at": int(time.time())}
        self.skills[name] = entry
        return entry


def verify_installed(lock: SkillLock, install_root: str | Path, touch: bool = True) -> list[Finding]:
    """Recompute every installed skill's digest and compare to the lock. Also
    reports skills present on disk but missing from the lock (unmanaged)."""
    root = Path(install_root)
    out = []
    on_disk = {d.name for d in root.iterdir() if (d / "SKILL.md").is_file()} if root.is_dir() else set()
    for name, entry in sorted(lock.skills.items()):
        d = root / name
        if not d.is_dir():
            out.append(Finding(AST, "AST07-MISSING", "medium", f"{name} is locked but not installed"))
            continue
        actual = canonical_digest(d)
        if actual != entry["digest"]:
            out.append(Finding(AST, "AST07-DRIFT", "critical",
                               f"{name} content differs from pinned digest (modified in place or silently updated)",
                               str(d)))
        elif touch:
            entry["verified_at"] = int(time.time())
    for name in sorted(on_disk - set(lock.skills)):
        out.append(Finding(AST, "AST07-UNPINNED", "high", f"{name} is installed but not in the lockfile",
                           str(root / name)))
    return out


# ---------------------------------------------------------------------------
# 2/3/5. Update policy
# ---------------------------------------------------------------------------

@dataclass
class UpdateCandidate:
    name: str
    version: str
    skill_dir: str
    approved_by: str | None = None


@dataclass
class UpdatePolicy:
    freeze: bool = False              # production: no updates outside a change window
    require_signature: bool = True
    require_approval: bool = True
    allow_downgrade: bool = False
    max_verified_age_days: int = 30

    def evaluate(self, lock: SkillLock, cand: UpdateCandidate, trust=None, revocations=None) -> tuple[bool, list[Finding]]:
        out: list[Finding] = []
        if self.freeze:
            out.append(Finding(AST, "AST07-FROZEN", "high", "deployment is frozen; updates are refused"))
        current = lock.skills.get(cand.name)
        if current:
            try:
                if parse_version(cand.version) < parse_version(current["version"]) and not self.allow_downgrade:
                    out.append(Finding(AST, "AST07-ROLLBACK", "critical",
                                       f"downgrade {current['version']} -> {cand.version} refused (rollback attack)"))
                elif parse_version(cand.version) == parse_version(current["version"]) and \
                        canonical_digest(cand.skill_dir) != current["digest"]:
                    out.append(Finding(AST, "AST07-SAME-VERSION-DIFFERENT-CONTENT", "critical",
                                       f"{cand.name}@{cand.version} content differs from pinned build "
                                       "(republished version)"))
            except ValueError as e:
                out.append(Finding(AST, "AST07-BAD-VERSION", "high", str(e)))
        if self.require_signature:
            if trust is None:
                out.append(Finding(AST, "AST07-NO-TRUST-STORE", "high", "signature required but no trust store given"))
            else:
                from .ast01_malicious import verify_skill
                out += verify_skill(cand.skill_dir, trust, revocations)
        if self.require_approval and not cand.approved_by:
            out.append(Finding(AST, "AST07-UNAPPROVED", "high", "update requires human approval"))
        ok = not any(f.severity in ("high", "critical") for f in out)
        return ok, out

    def apply(self, lock: SkillLock, cand: UpdateCandidate, key_id: str = "", **kw) -> tuple[bool, list[Finding]]:
        ok, findings = self.evaluate(lock, cand, **kw)
        if ok:
            lock.pin(cand.name, cand.version, cand.skill_dir, key_id=key_id)
            lock.skills[cand.name]["approved_by"] = cand.approved_by
            lock.save()
        return ok, findings

    def stale(self, lock: SkillLock, now: float | None = None) -> list[Finding]:
        now = time.time() if now is None else now
        limit = self.max_verified_age_days * 86400
        return [Finding(AST, "AST07-STALE-VERIFICATION", "medium",
                        f"{n} last verified {int((now - e.get('verified_at', 0)) / 86400)} days ago")
                for n, e in sorted(lock.skills.items()) if now - e.get("verified_at", 0) > limit]


# ---------------------------------------------------------------------------
# 4. Advisories
# ---------------------------------------------------------------------------

def _in_range(version: str, spec: str) -> bool:
    """spec: comma-separated constraints like ``>=1.0.0,<1.4.2`` or ``==2.0.0``."""
    v = parse_version(version)
    for c in [c.strip() for c in spec.split(",") if c.strip()]:
        m = re.match(r"^(>=|<=|==|<|>)\s*(.+)$", c)
        if not m:
            raise ValueError(f"bad constraint {c!r}")
        op, rhs = m.group(1), parse_version(m.group(2))
        if not {"<": v < rhs, "<=": v <= rhs, ">": v > rhs, ">=": v >= rhs, "==": v == rhs}[op]:
            return False
    return True


def match_advisories(lock: SkillLock, advisories: list[dict]) -> list[Finding]:
    """advisories: ``[{"id": "GHSA-...", "skill": "x", "affected": ">=1.0.0,<1.2.0",
    "digests": [...], "severity": "high", "fixed": "1.2.0"}]``."""
    out = []
    for adv in advisories:
        entry = lock.skills.get(adv.get("skill", ""))
        if not entry:
            continue
        hit = entry["digest"] in adv.get("digests", [])
        if not hit and adv.get("affected"):
            try:
                hit = _in_range(entry["version"], adv["affected"])
            except ValueError:
                hit = False
        if hit:
            out.append(Finding(AST, "AST07-ADVISORY", adv.get("severity", "high"),
                               f"{adv['skill']}@{entry['version']} affected by {adv.get('id', '?')}"
                               + (f"; fixed in {adv['fixed']}" if adv.get("fixed") else "")))
    return out


# ---------------------------------------------------------------------------
# 3. Hot-reload guard
# ---------------------------------------------------------------------------

class HotReloadGuard:
    """Record each loaded skill's digest at session start; before every
    invocation call ``check(name)``. A mid-session modification (writable skill
    directory) raises instead of being silently picked up."""

    def __init__(self):
        self._digests: dict[str, tuple[Path, str]] = {}

    def load(self, name: str, skill_dir: str | Path) -> str:
        d = canonical_digest(skill_dir)
        self._digests[name] = (Path(skill_dir), d)
        return d

    def check(self, name: str) -> None:
        path, expected = self._digests[name]
        if canonical_digest(path) != expected:
            raise RuntimeError(f"skill {name!r} changed on disk mid-session; restart and re-verify required")
