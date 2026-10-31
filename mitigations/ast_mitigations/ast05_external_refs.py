"""AST05 -- Untrusted External Instructions: reference mitigations.

1. Pin and verify referenced content on every load  -> ``ReferencePins`` + ``VerifiedFetcher``
2. Prefer inlining over fetching                    -> ``snapshot_references`` (vendor into package)
3. Allowlist reference domains                      -> ``ReferencePolicy``
4. Audit references transitively                    -> ``audit_transitive``
5. Fleet-wide inventory of referenced sources       -> ``ReferenceInventory``
6. Rescan continuously                              -> ``VerifiedFetcher.rescan``

The fetcher is injectable (``fetch(url) -> bytes``) so the same code serves
review tooling, CI, and the runtime loader, and so tests run offline.
"""

from __future__ import annotations

import fnmatch
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .common import Finding, Skill, sha256_bytes

AST = "AST05"
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"'`\]]+", re.I)
Fetch = Callable[[str], bytes]


class ReferenceRefused(Exception):
    pass


def extract_references(text: str) -> list[str]:
    seen, out = set(), []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?*")
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def skill_references(skill: Skill) -> list[str]:
    refs = extract_references(skill.body)
    for r in skill.manifest.get("references") or []:
        url = r.get("url") if isinstance(r, dict) else r
        if isinstance(url, str) and url not in refs:
            refs.append(url)
    return refs


# ---------------------------------------------------------------------------
# 3. Domain allowlist
# ---------------------------------------------------------------------------

@dataclass
class ReferencePolicy:
    allow: list[str] = field(default_factory=list)   # host globs or URL globs
    max_depth: int = 2
    require_https: bool = True

    def permits(self, url: str) -> tuple[bool, str]:
        parts = urlsplit(url)
        if self.require_https and parts.scheme != "https":
            return False, f"scheme {parts.scheme!r} not allowed"
        host = (parts.hostname or "").lower()
        if parts.username or parts.password:
            return False, "credentials in URL"
        if re.fullmatch(r"[\d.]+|\[[0-9a-f:]+\]", host):
            return False, "raw IP address"
        for pat in self.allow:
            pat = pat.lower()
            if "/" in pat:
                if fnmatch.fnmatch(url.lower(), pat if "://" in pat else "https://" + pat):
                    return True, f"URL glob {pat}"
            elif host == pat or fnmatch.fnmatch(host, pat):
                return True, f"host glob {pat}"
        return False, f"host {host!r} not in reference allowlist"


# ---------------------------------------------------------------------------
# 1. Pins
# ---------------------------------------------------------------------------

@dataclass
class ReferencePins:
    """url -> {"sha256": ..., "reviewed_at": ..., "reviewer": ...}. Ship this file
    inside the signed skill package so pins are covered by the signature."""
    pins: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "ReferencePins":
        p = Path(path)
        return cls(json.loads(p.read_text(encoding="utf-8")) if p.exists() else {})

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def pin(self, url: str, content: bytes, reviewer: str) -> str:
        h = "sha256:" + sha256_bytes(content)
        self.pins[url] = {"sha256": h, "reviewer": reviewer, "reviewed_at": int(time.time())}
        return h


class VerifiedFetcher:
    """Runtime loader: refuses content that is off-allowlist, unpinned, or has
    drifted from the reviewed version. Serving different bytes to the agent
    than to the reviewer (bait-and-switch) therefore fails closed."""

    def __init__(self, fetch: Fetch, policy: ReferencePolicy, pins: ReferencePins):
        self.fetch, self.policy, self.pins = fetch, policy, pins

    def get(self, url: str) -> bytes:
        ok, why = self.policy.permits(url)
        if not ok:
            raise ReferenceRefused(f"{url}: {why}")
        pin = self.pins.pins.get(url)
        if not pin:
            raise ReferenceRefused(f"{url}: not pinned at review time")
        body = self.fetch(url)
        got = "sha256:" + sha256_bytes(body)
        if got != pin["sha256"]:
            raise ReferenceRefused(f"{url}: content drifted from reviewed version ({got[:19]} != {pin['sha256'][:19]})")
        return body

    def rescan(self) -> list[Finding]:
        """Re-fetch every pinned reference; schedule this (e.g. hourly) so drift
        is noticed even when no agent happens to load the skill."""
        out = []
        for url in sorted(self.pins.pins):
            try:
                self.get(url)
            except ReferenceRefused as e:
                out.append(Finding(AST, "AST05-REFERENCE-DRIFT", "high", str(e)))
            except Exception as e:  # network errors are surfaced, not ignored
                out.append(Finding(AST, "AST05-REFERENCE-UNREACHABLE", "medium", f"{url}: {e}"))
        return out


# ---------------------------------------------------------------------------
# Static review of a skill's references
# ---------------------------------------------------------------------------

def check_skill(skill: Skill, policy: ReferencePolicy | None = None,
                pins: ReferencePins | None = None) -> list[Finding]:
    out = []
    refs = skill_references(skill)
    instr_re = re.compile(r"(read|follow|fetch|load|consult|obey)[^\n]{0,60}(https?://)", re.I)
    if refs and instr_re.search(skill.body):
        out.append(Finding(AST, "AST05-RUNTIME-INSTRUCTIONS", "medium",
                           f"skill tells the agent to load {len(refs)} external document(s) at runtime; "
                           "content becomes instructions -- inline or pin it", "SKILL.md"))
    for url in refs:
        if policy is not None:
            ok, why = policy.permits(url)
            if not ok:
                out.append(Finding(AST, "AST05-REFERENCE-NOT-ALLOWED", "high", f"{url}: {why}", "SKILL.md"))
        elif not url.startswith("https://"):
            out.append(Finding(AST, "AST05-REFERENCE-INSECURE", "high", f"{url}: non-TLS reference", "SKILL.md"))
        if pins is not None and url not in pins.pins:
            out.append(Finding(AST, "AST05-REFERENCE-UNPINNED", "high", f"{url}: no content pin", "SKILL.md"))
    return out


# ---------------------------------------------------------------------------
# 2. Inline / snapshot
# ---------------------------------------------------------------------------

def snapshot_references(skill: Skill, fetch: Fetch, policy: ReferencePolicy,
                        dest_dir: str = "references", reviewer: str = "publisher") -> ReferencePins:
    """Vendor every allowed reference into ``<skill>/references/`` and pin it.
    After snapshotting, rewrite SKILL.md links to the local copies, re-sign, and
    the referenced content becomes part of the reviewed, signed package."""
    out_dir = skill.root / dest_dir
    out_dir.mkdir(exist_ok=True)
    pins = ReferencePins()
    for url in skill_references(skill):
        ok, _ = policy.permits(url)
        if not ok:
            continue
        body = fetch(url)
        h = pins.pin(url, body, reviewer)
        (out_dir / (h.split(":")[1][:16] + ".txt")).write_bytes(body)
    pins.save(skill.root / "reference-pins.json")
    return pins


# ---------------------------------------------------------------------------
# 4. Transitive audit
# ---------------------------------------------------------------------------

def audit_transitive(start: list[str], fetch: Fetch, policy: ReferencePolicy) -> tuple[dict[str, int], list[Finding]]:
    """Breadth-first walk of references-of-references up to ``policy.max_depth``.
    Returns (url -> depth, findings). Anything beyond max depth, or off-allowlist
    at any depth, is reported -- the attacker only needs the deepest link."""
    seen: dict[str, int] = {}
    out: list[Finding] = []
    frontier = [(u, 0) for u in start]
    while frontier:
        url, depth = frontier.pop(0)
        if url in seen:
            continue
        seen[url] = depth
        ok, why = policy.permits(url)
        if not ok:
            out.append(Finding(AST, "AST05-TRANSITIVE-NOT-ALLOWED", "high", f"depth {depth}: {url}: {why}"))
            continue
        try:
            body = fetch(url).decode("utf-8", errors="replace")
        except Exception as e:
            out.append(Finding(AST, "AST05-REFERENCE-UNREACHABLE", "medium", f"{url}: {e}"))
            continue
        children = extract_references(body)
        if depth + 1 > policy.max_depth and children:
            out.append(Finding(AST, "AST05-TRANSITIVE-TOO-DEEP", "high",
                               f"{url} references {len(children)} further document(s) beyond max depth "
                               f"{policy.max_depth}"))
            continue
        frontier += [(c, depth + 1) for c in children]
    return seen, out


# ---------------------------------------------------------------------------
# 5. Fleet inventory
# ---------------------------------------------------------------------------

@dataclass
class ReferenceInventory:
    by_source: dict[str, set[str]] = field(default_factory=dict)  # host -> skills

    def record(self, skill: Skill) -> None:
        for url in skill_references(skill):
            host = (urlsplit(url).hostname or "").lower()
            self.by_source.setdefault(host, set()).add(skill.name)

    def affected_by(self, host: str) -> set[str]:
        host = host.lower()
        return set().union(*[s for h, s in self.by_source.items() if h == host or h.endswith("." + host)] or [set()])

    def to_json(self) -> str:
        return json.dumps({h: sorted(s) for h, s in sorted(self.by_source.items())}, indent=2)
