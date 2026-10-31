"""Shared primitives for the OWASP AST10 reference mitigations.

Everything here is deliberately small and dependency-light:

* ``Finding`` / ``Report`` -- a uniform result model every control returns.
* ``load_skill`` -- reads a skill directory and parses ``SKILL.md`` frontmatter
  with a *safe* YAML loader (never ``yaml.load``), see AST04.
* ``canonical_digest`` -- a deterministic sha256 over ``SKILL.md`` plus every
  file in the package, used by AST01/AST02/AST07 for signing and pinning.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Agent identity / persistence files that skills must not touch without an
# explicit, reviewed grant (AST01 #7, AST03 #3).
IDENTITY_FILES = ("SOUL.md", "MEMORY.md", "AGENTS.md", "IDENTITY.md", "CLAUDE.md")

RISK_TIERS = ("L0", "L1", "L2", "L3")


@dataclass
class Finding:
    ast: str            # e.g. "AST04"
    rule: str           # stable rule id, e.g. "AST04-ZERO-WIDTH"
    severity: str       # one of SEVERITIES
    message: str
    location: str = ""  # file[:line] when known

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    subject: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, *findings: Finding) -> "Report":
        self.findings.extend(findings)
        return self

    def extend(self, findings: Iterable[Finding]) -> "Report":
        self.findings.extend(findings)
        return self

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=_SEV_RANK.__getitem__)

    def blocking(self, threshold: str = "high") -> list[Finding]:
        t = _SEV_RANK[threshold]
        return [f for f in self.findings if _SEV_RANK[f.severity] >= t]

    def passed(self, threshold: str = "high") -> bool:
        return not self.blocking(threshold)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "max_severity": self.max_severity,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def severity_at_least(sev: str, threshold: str) -> bool:
    return _SEV_RANK[sev] >= _SEV_RANK[threshold]


# --------------------------------------------------------------------------
# Hashing helpers
# --------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs(value: Any) -> str:
    """Canonical JSON (RFC 8785 subset adequate for str/int/bool/list/dict)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def iter_package_files(root: Path) -> list[Path]:
    """Every regular file in the package, including hidden files, sorted.

    Symlinks are *not* followed and are returned so callers can flag them;
    a package must never reach outside its own directory (AST06)."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            out.append(Path(dirpath) / name)
    return out


def canonical_digest(root: str | os.PathLike, exclude: Iterable[str] = ("SIGNATURE", "SIGNATURE.json")) -> str:
    """sha256 over a canonical listing of ``relative_path\\0sha256(content)``.

    The signature file itself is excluded so the digest can be signed and the
    signature stored alongside the package."""
    root = Path(root)
    excl = set(exclude)
    lines = []
    for p in iter_package_files(root):
        rel = p.relative_to(root).as_posix()
        if rel in excl:
            continue
        if p.is_symlink():
            content = ("symlink:" + os.readlink(p)).encode()
        else:
            content = p.read_bytes()
        lines.append(f"{rel}\0{sha256_bytes(content)}")
    return "sha256:" + sha256_bytes("\n".join(lines).encode())


# --------------------------------------------------------------------------
# Skill loading
# --------------------------------------------------------------------------

class UnsafeMetadataError(ValueError):
    """Raised when skill metadata cannot be parsed safely (AST04)."""


def split_frontmatter(text: str) -> tuple[str, str]:
    """Return (frontmatter_text, body). Empty frontmatter if none present."""
    if not text.startswith("---"):
        return "", text
    lines = text.splitlines(keepends=True)
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "".join(lines[1:i]), "".join(lines[i + 1:])
    raise UnsafeMetadataError("unterminated YAML frontmatter")


def safe_yaml_load(text: str) -> Any:
    """Parse YAML with the safe loader only. Python object tags are rejected
    by ``yaml.safe_load``; we additionally refuse any ``!!python`` tag up front
    so the failure is explicit and auditable."""
    if "!!python" in text or "!python/" in text:
        raise UnsafeMetadataError("python object tag in YAML metadata")
    try:
        import yaml  # PyYAML
    except ImportError as e:  # pragma: no cover - environment dependent
        raise RuntimeError("PyYAML is required: pip install pyyaml") from e
    try:
        return yaml.safe_load(text) if text.strip() else {}
    except yaml.YAMLError as e:
        raise UnsafeMetadataError(f"invalid YAML: {e}") from e


@dataclass
class Skill:
    root: Path
    manifest: dict
    body: str
    raw: str

    @property
    def name(self) -> str:
        return str(self.manifest.get("name", self.root.name))

    def files(self) -> list[Path]:
        return iter_package_files(self.root)


def load_skill(root: str | os.PathLike) -> Skill:
    root = Path(root)
    skill_md = root / "SKILL.md"
    if not skill_md.is_file():
        raise FileNotFoundError(f"{skill_md} not found")
    raw = skill_md.read_text(encoding="utf-8", errors="replace")
    fm, body = split_frontmatter(raw)
    manifest = safe_yaml_load(fm)
    if manifest is None:
        manifest = {}
    if not isinstance(manifest, dict):
        raise UnsafeMetadataError("frontmatter must be a mapping")
    return Skill(root=root, manifest=manifest, body=body, raw=raw)


def get_path(d: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur
