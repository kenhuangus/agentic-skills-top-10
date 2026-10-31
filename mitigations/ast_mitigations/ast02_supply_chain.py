"""AST02 -- Supply Chain Compromise: reference mitigations.

1. Provenance: signature over a canonical package digest  -> ``ast01_malicious.sign_skill``
   (digest is ``common.canonical_digest``: SKILL.md + every resource file)
2. Transparency log for publish/update/delete              -> ``TransparencyLog``
3. Pin nested dependencies to immutable hashes             -> ``check_dependency_pins``
4. Treat repo config files as executable code              -> ``scan_repo_config``
5. Scan recursive dependency trees                         -> ``check_dependency_pins`` walks
   every requirements / package manifest in the package, not just the top level
6. Internal mirror / allowlist                             -> ``SkillAllowlist``
7. Revocation infrastructure (key, digest, publisher)      -> ``RevocationList``
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .common import Finding, iter_package_files, jcs, sha256_bytes

AST = "AST02"


# ---------------------------------------------------------------------------
# 2. Transparency log (append-only, hash-chained, Merkle root)
# ---------------------------------------------------------------------------

def _leaf_hash(entry: dict) -> str:
    return sha256_bytes(b"\x00" + jcs(entry).encode())


def _node_hash(a: str, b: str) -> str:
    return sha256_bytes(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b))


def merkle_root(leaves: list[str]) -> str:
    """RFC 6962-style Merkle tree hash (domain-separated leaves/nodes)."""
    if not leaves:
        return sha256_bytes(b"")
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_node_hash(level[i], level[i + 1]) if i + 1 < len(level) else level[i])
        level = nxt
    return level[0]


class TransparencyLog:
    """Append-only JSONL log. Every entry commits to the previous entry hash,
    so deleting, reordering or editing a past entry breaks ``verify()``.
    Publishing the ``root()`` periodically (e.g. in a signed checkpoint) lets
    clients detect a registry that serves different histories to different
    users -- the Certificate Transparency model applied to skills."""

    OPS = ("publish", "update", "delete", "revoke")

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.entries: list[dict] = []
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.entries.append(json.loads(line))

    def append(self, op: str, skill: str, version: str, digest: str, actor: str,
               timestamp_ms: int | None = None) -> dict:
        if op not in self.OPS:
            raise ValueError(f"op must be one of {self.OPS}")
        prev = self.entries[-1]["entry_hash"] if self.entries else "0" * 64
        body = {"seq": len(self.entries), "op": op, "skill": skill, "version": version,
                "digest": digest, "actor": actor, "prev": prev,
                "timestamp_ms": int(time.time() * 1000) if timestamp_ms is None else timestamp_ms}
        entry = dict(body, entry_hash=_leaf_hash(body))
        self.entries.append(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(jcs(entry) + "\n")
        return entry

    def root(self) -> str:
        return merkle_root([e["entry_hash"] for e in self.entries])

    def verify(self) -> list[Finding]:
        out = []
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            body = {k: v for k, v in e.items() if k != "entry_hash"}
            if e.get("seq") != i:
                out.append(Finding(AST, "AST02-TLOG-SEQ", "critical", f"entry {i} has seq {e.get('seq')}"))
            if e.get("prev") != prev:
                out.append(Finding(AST, "AST02-TLOG-CHAIN", "critical", f"entry {i} breaks hash chain"))
            if _leaf_hash(body) != e.get("entry_hash"):
                out.append(Finding(AST, "AST02-TLOG-TAMPER", "critical", f"entry {i} content altered"))
            prev = e.get("entry_hash", "")
        return out

    def is_logged(self, skill: str, digest: str) -> bool:
        """True iff ``digest`` was published/updated for ``skill`` and not later
        deleted or revoked. Install only logged digests."""
        state = False
        for e in self.entries:
            if e["skill"] == skill and e["digest"] == digest:
                state = e["op"] in ("publish", "update")
        return state


# ---------------------------------------------------------------------------
# 3/5. Dependency pinning (recursive)
# ---------------------------------------------------------------------------

_REQ_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\],]+==[^\s;]+")
_EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def _check_requirements(text: str, rel: str) -> list[Finding]:
    out = []
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, line in enumerate(text.splitlines(), 1):
        stripped = re.sub(r"(^|\s)#.*$", "", line).rstrip()
        if not buf:
            start = n
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        if buf.strip():
            logical.append((start, buf.strip()))
        buf = ""
    for n, req in logical:
        loc = f"{rel}:{n}"
        if req.startswith(("-r ", "--requirement", "-c ")):
            continue  # nested file is scanned on its own
        if req.startswith(("-e ", "--editable", "git+", "http://", "https://")) or "://" in req:
            out.append(Finding(AST, "AST02-UNPINNED-URL-DEP", "high",
                               f"dependency installed from URL/VCS without hash: {req[:80]}", loc))
            continue
        if req.startswith(("--index-url", "-i ", "--extra-index-url")):
            out.append(Finding(AST, "AST02-EXTRA-INDEX", "high",
                               f"custom package index (dependency-confusion vector): {req[:80]}", loc))
            continue
        if req.startswith("-"):
            continue
        if not _REQ_PINNED.match(req):
            out.append(Finding(AST, "AST02-UNPINNED-DEP", "high",
                               f"dependency not pinned with '==': {req[:80]}", loc))
        elif "--hash=sha256:" not in req:
            out.append(Finding(AST, "AST02-NO-HASH", "medium",
                               f"dependency pinned but lacks --hash=sha256: {req.split()[0]}", loc))
    return out


def _check_package_json(text: str, rel: str) -> list[Finding]:
    out = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [Finding(AST, "AST02-BAD-PACKAGE-JSON", "medium", "unparseable package.json", rel)]
    for section in ("dependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if not isinstance(spec, str) or not _EXACT_SEMVER.match(spec):
                out.append(Finding(AST, "AST02-UNPINNED-DEP", "high",
                                   f"{section}.{name} = {spec!r} is not an exact version", rel))
    for hook in ("preinstall", "install", "postinstall", "prepare"):
        if hook in (data.get("scripts") or {}):
            out.append(Finding(AST, "AST02-INSTALL-SCRIPT", "high",
                               f"npm lifecycle script {hook!r} runs code at install time", rel))
    return out


def check_dependency_pins(root: str | Path) -> list[Finding]:
    """Walk *every* dependency manifest in the package (nested ones included)."""
    root = Path(root)
    out: list[Finding] = []
    has_pkg_json = has_lock = False
    for p in iter_package_files(root):
        rel = p.relative_to(root).as_posix()
        name = p.name
        if p.is_symlink():
            continue
        if re.match(r"^requirements.*\.(txt|in)$", name):
            out += _check_requirements(p.read_text(encoding="utf-8", errors="replace"), rel)
        elif name == "package.json":
            has_pkg_json = True
            out += _check_package_json(p.read_text(encoding="utf-8", errors="replace"), rel)
        elif name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            has_lock = True
        elif name == "pyproject.toml":
            text = p.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*(>=|~=|>|\^|\*)[^"]*"', text):
                out.append(Finding(AST, "AST02-UNPINNED-DEP", "medium",
                                   f"pyproject dependency uses a range: {m.group(0)}", rel))
    if has_pkg_json and not has_lock:
        out.append(Finding(AST, "AST02-NO-LOCKFILE", "medium",
                           "package.json without a lockfile; transitive deps are unpinned"))
    return out


# ---------------------------------------------------------------------------
# 4. Repository config files are executable code
# ---------------------------------------------------------------------------

BASE_URL_ENV_RE = re.compile(r"\b([A-Z0-9_]*(BASE_URL|API_BASE|ENDPOINT|PROXY))\b[\"']?\s*[=:]\s*[\"']?([^\s\"',}]+)")
CONFIG_PATHS = {
    ".claude/settings.json": "Claude Code settings (hooks / env / permissions)",
    ".claude/settings.local.json": "Claude Code local settings",
    ".mcp.json": "MCP server definitions (spawn commands)",
    ".cursor/mcp.json": "Cursor MCP server definitions",
    ".vscode/settings.json": "VS Code workspace settings",
    ".vscode/tasks.json": "VS Code tasks",
    ".envrc": "direnv script (runs on cd)",
    ".env": "environment overrides",
}


def scan_repo_config(root: str | Path, trusted_hosts: tuple[str, ...] = ()) -> list[Finding]:
    """Flag config files that turn 'open the project' into 'run code'."""
    root = Path(root)
    out: list[Finding] = []
    for p in iter_package_files(root):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            continue
        if rel.startswith(".git/hooks/") or "/.git/hooks/" in rel or rel.startswith(".githooks/"):
            out.append(Finding(AST, "AST02-GIT-HOOK", "high", "git hook shipped in package", rel))
            continue
        desc = CONFIG_PATHS.get(rel)
        if not desc:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        data: Any = None
        if rel.endswith(".json"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = None
        if isinstance(data, dict) and data.get("hooks"):
            out.append(Finding(AST, "AST02-CONFIG-HOOKS", "critical",
                               f"{desc}: defines hooks that execute shell commands automatically", rel))
        if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
            for name, srv in data["mcpServers"].items():
                if isinstance(srv, dict) and srv.get("command"):
                    out.append(Finding(AST, "AST02-CONFIG-MCP-COMMAND", "high",
                                       f"MCP server {name!r} spawns {srv.get('command')!r}", rel))
        if isinstance(data, dict) and isinstance(data.get("permissions"), dict):
            allow = data["permissions"].get("allow") or []
            if any(a in ("Bash", "Bash(*)", "*") for a in allow):
                out.append(Finding(AST, "AST02-CONFIG-BROAD-ALLOW", "high",
                                   "settings pre-approve unrestricted shell", rel))
        if rel == ".vscode/tasks.json" and "folderOpen" in text:
            out.append(Finding(AST, "AST02-CONFIG-AUTORUN", "critical",
                               "VS Code task runs automatically on folder open", rel))
        if rel == ".envrc":
            out.append(Finding(AST, "AST02-CONFIG-ENVRC", "high", desc, rel))
        for m in BASE_URL_ENV_RE.finditer(text):
            host = re.sub(r"^[a-z]+://", "", m.group(3)).split("/")[0]
            if not any(host == h or host.endswith("." + h) for h in trusted_hosts):
                out.append(Finding(AST, "AST02-CONFIG-ENDPOINT-OVERRIDE", "critical",
                                   f"{m.group(1)} redirects traffic to {host!r} (credential interception)", rel))
    return out


# ---------------------------------------------------------------------------
# 6. Allowlist / internal mirror
# ---------------------------------------------------------------------------

@dataclass
class SkillAllowlist:
    """Enterprise allowlist: only (name, digest) pairs approved here install."""
    entries: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "SkillAllowlist":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls({k: set(v) for k, v in data.items()})

    def permits(self, name: str, digest: str) -> bool:
        return digest in self.entries.get(name, set())


# ---------------------------------------------------------------------------
# 7. Revocation
# ---------------------------------------------------------------------------

@dataclass
class RevocationList:
    """Revocation state consulted at load time. ``max_age_s`` bounds how stale a
    cached copy may be before hosts must refuse to load (fail closed)."""
    keys: set[str] = field(default_factory=set)
    digests: set[str] = field(default_factory=set)
    publishers: set[str] = field(default_factory=set)
    fetched_at: float = field(default_factory=time.time)
    max_age_s: float = 24 * 3600

    @classmethod
    def from_dict(cls, d: dict, fetched_at: float | None = None) -> "RevocationList":
        return cls(set(d.get("keys", [])), set(d.get("digests", [])), set(d.get("publishers", [])),
                   time.time() if fetched_at is None else fetched_at, d.get("max_age_s", 24 * 3600))

    @classmethod
    def load(cls, path: str | Path) -> "RevocationList":
        p = Path(path)
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")), p.stat().st_mtime)

    def is_fresh(self, now: float | None = None) -> bool:
        return ((now or time.time()) - self.fetched_at) <= self.max_age_s

    def check(self, *, key_id: str = "", digest: str = "", publisher: str = "",
              now: float | None = None) -> list[Finding]:
        out = []
        if not self.is_fresh(now):
            out.append(Finding(AST, "AST02-REVOCATION-STALE", "high",
                               "revocation list is older than its freshness window; refusing (fail closed)"))
        if key_id and key_id in self.keys:
            out.append(Finding(AST, "AST02-REVOKED-KEY", "critical", f"signing key {key_id} is revoked"))
        if digest and digest in self.digests:
            out.append(Finding(AST, "AST02-REVOKED-DIGEST", "critical", f"skill version {digest} is revoked"))
        if publisher and publisher in self.publishers:
            out.append(Finding(AST, "AST02-REVOKED-PUBLISHER", "critical", f"publisher {publisher} is revoked"))
        return out


def check_skill_dir(root: str | Path, trusted_hosts: tuple[str, ...] = ()) -> list[Finding]:
    return check_dependency_pins(root) + scan_repo_config(root, trusted_hosts)
