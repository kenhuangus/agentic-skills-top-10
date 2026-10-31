"""AST04 -- Insecure Metadata: reference mitigations.

Implements the AST04 preventive mitigations:

1. Safe parsers by default and a key allowlist   -> ``common.safe_yaml_load``,
   ``safe_json_loads``, ``validate_schema``
2. Schema validation before use                    -> ``validate_schema``
3. Static analysis of metadata and prose for hidden
   content (zero-width, bidi, Unicode tag / ASCII
   smuggling, base64 payloads, hidden HTML comments) -> ``find_hidden_content``
4. ``risk_tier`` cross-checked against permissions  -> ``check_risk_tier_consistency``
6. Brand / trademark impersonation                  -> ``check_brand_impersonation``

Mitigation 5 (parse in an isolated subprocess) is provided by
``ast06_isolation.run_sandboxed`` -- see ``parse_in_subprocess`` below.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from typing import Any, Iterable

from .common import (
    IDENTITY_FILES,
    RISK_TIERS,
    Finding,
    Skill,
    UnsafeMetadataError,
    get_path,
)

AST = "AST04"

# ---------------------------------------------------------------------------
# 1/2. Schema + key allowlist
# ---------------------------------------------------------------------------

# Top-level keys the loader accepts. Everything else is rejected, closing the
# "unexpected field" injection path (prototype keys, loader directives, etc.).
ALLOWED_TOP_LEVEL_KEYS = {
    "name", "version", "description", "author", "license", "platforms",
    "permissions", "requires", "risk_tier", "scan_status", "signature",
    "content_hash", "changelog", "references", "homepage", "tags",
    # widely used platform keys that are safe to carry through
    "allowed-tools", "model", "metadata",
}

PROTOTYPE_KEYS = {"__proto__", "constructor", "prototype"}

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")

_TYPES: dict[str, type | tuple[type, ...]] = {
    "name": str, "version": str, "description": str, "author": (dict, str),
    "license": str, "platforms": list, "permissions": dict, "requires": dict,
    "risk_tier": str, "scan_status": dict, "signature": str, "content_hash": str,
    "changelog": list, "references": list, "homepage": str, "tags": list,
    "allowed-tools": (list, str), "model": str, "metadata": dict,
}


def _walk_keys(obj: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            yield p, str(k)
            yield from _walk_keys(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_keys(v, f"{path}[{i}]")


def validate_schema(manifest: dict, location: str = "SKILL.md") -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(manifest, dict) or not manifest:
        return [Finding(AST, "AST04-NO-METADATA", "high", "skill has no frontmatter metadata", location)]

    for key in manifest:
        if key not in ALLOWED_TOP_LEVEL_KEYS:
            out.append(Finding(AST, "AST04-UNKNOWN-KEY", "medium",
                               f"unexpected top-level metadata key {key!r} (not in allowlist)", location))
        elif not isinstance(manifest[key], _TYPES[key]):
            out.append(Finding(AST, "AST04-BAD-TYPE", "medium",
                               f"metadata key {key!r} has type {type(manifest[key]).__name__}", location))

    for path, key in _walk_keys(manifest):
        if key in PROTOTYPE_KEYS:
            out.append(Finding(AST, "AST04-PROTO-KEY", "critical",
                               f"prototype-pollution key at {path}", location))

    for required in ("name", "description", "version"):
        if required not in manifest:
            out.append(Finding(AST, "AST04-MISSING-FIELD", "medium",
                               f"required field {required!r} missing", location))

    name = manifest.get("name")
    if isinstance(name, str) and not NAME_RE.match(name):
        out.append(Finding(AST, "AST04-BAD-NAME", "medium",
                           f"name {name!r} must be lowercase ASCII [a-z0-9-] (blocks homoglyph names)", location))
    version = manifest.get("version")
    if isinstance(version, str) and not SEMVER_RE.match(version):
        out.append(Finding(AST, "AST04-BAD-VERSION", "low", f"version {version!r} is not semver", location))
    tier = manifest.get("risk_tier")
    if tier is not None and tier not in RISK_TIERS:
        out.append(Finding(AST, "AST04-BAD-RISK-TIER", "medium",
                           f"risk_tier {tier!r} not in {RISK_TIERS}", location))
    desc = manifest.get("description")
    if isinstance(desc, str) and len(desc) > 1024:
        out.append(Finding(AST, "AST04-LONG-DESCRIPTION", "low",
                           "description longer than 1024 chars (common padding / injection carrier)", location))
    return out


def safe_json_loads(text: str) -> Any:
    """JSON loader that rejects duplicate keys and prototype-pollution keys.

    Duplicate keys are a parser-differential vector: Python keeps the last
    value while some JS loaders keep the first, so reviewers and runtimes may
    see different manifests."""

    def hook(pairs: list[tuple[str, Any]]) -> dict:
        seen: dict[str, Any] = {}
        for k, v in pairs:
            if k in PROTOTYPE_KEYS:
                raise UnsafeMetadataError(f"prototype-pollution key {k!r} in JSON")
            if k in seen:
                raise UnsafeMetadataError(f"duplicate key {k!r} in JSON")
            seen[k] = v
        return seen

    try:
        return json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError as e:
        raise UnsafeMetadataError(f"invalid JSON: {e}") from e


# ---------------------------------------------------------------------------
# 3. Hidden content detection
# ---------------------------------------------------------------------------

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "᠎", "­"}
BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮",
                 "⁦", "⁧", "⁨", "⁩", "‎", "‏"}
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
INSTRUCTION_HINT_RE = re.compile(
    r"\b(ignore|disregard|override|execute|run|curl|wget|bash|send|upload|exfiltrat|"
    r"secret|token|password|api[_ -]?key|do not (tell|mention|show))\b", re.I)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def decode_tag_smuggling(text: str) -> str:
    """Decode Unicode 'tag' characters (U+E0000-U+E007F) into the ASCII they
    smuggle. Invisible in most renderers, but read by tokenizers."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F)


def try_decode_base64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in s)
    return s if s and printable / len(s) > 0.9 else None


def find_hidden_content(text: str, location: str = "") -> list[Finding]:
    out: list[Finding] = []

    zw = [(i, c) for i, c in enumerate(text) if c in ZERO_WIDTH]
    # A single leading BOM is benign.
    if zw and not (len(zw) == 1 and zw[0] == (0, "﻿")):
        out.append(Finding(AST, "AST04-ZERO-WIDTH", "high",
                           f"{len(zw)} zero-width character(s) -- invisible to reviewers",
                           f"{location}:{_line_of(text, zw[0][0])}"))

    bidi = [i for i, c in enumerate(text) if c in BIDI_CONTROLS]
    if bidi:
        out.append(Finding(AST, "AST04-BIDI", "high",
                           f"{len(bidi)} bidirectional control character(s) (Trojan Source)",
                           f"{location}:{_line_of(text, bidi[0])}"))

    smuggled = decode_tag_smuggling(text)
    if smuggled:
        idx = next(i for i, c in enumerate(text) if 0xE0000 <= ord(c) <= 0xE007F)
        out.append(Finding(AST, "AST04-ASCII-SMUGGLING", "critical",
                           f"Unicode tag characters smuggle hidden text: {smuggled[:80]!r}",
                           f"{location}:{_line_of(text, idx)}"))

    for m in BASE64_RE.finditer(text):
        decoded = try_decode_base64(m.group(0))
        if decoded is None:
            continue
        sev = "high" if INSTRUCTION_HINT_RE.search(decoded) else "medium"
        out.append(Finding(AST, "AST04-BASE64-PAYLOAD", sev,
                           f"base64 blob decodes to text: {decoded[:80]!r}",
                           f"{location}:{_line_of(text, m.start())}"))

    for m in HTML_COMMENT_RE.finditer(text):
        if INSTRUCTION_HINT_RE.search(m.group(1)):
            out.append(Finding(AST, "AST04-HIDDEN-COMMENT", "high",
                               f"HTML comment (hidden when rendered) contains instructions: "
                               f"{m.group(1).strip()[:80]!r}",
                               f"{location}:{_line_of(text, m.start())}"))

    # Mixed-script confusables in what should be identifiers / headings.
    for m in re.finditer(r"\S+", text):
        tok = m.group(0)
        scripts = {unicodedata.name(c, "").split(" ")[0] for c in tok if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            out.append(Finding(AST, "AST04-CONFUSABLE", "medium",
                               f"mixed-script token {tok!r} (homoglyph)",
                               f"{location}:{_line_of(text, m.start())}"))
            break
    return out


# ---------------------------------------------------------------------------
# 4. risk_tier vs permission consistency
# ---------------------------------------------------------------------------

def implied_min_tier(manifest: dict) -> str:
    perms = manifest.get("permissions") or {}
    if not isinstance(perms, dict):
        return "L2"
    files = perms.get("files") or {}
    writes = (files.get("write") or []) if isinstance(files, dict) else []
    shell = perms.get("shell", False)
    net = perms.get("network")
    net_allow = net.get("allow") if isinstance(net, dict) else None

    if any(str(w).split("/")[-1] in IDENTITY_FILES for w in writes):
        return "L3"
    if shell or net is True or net_allow in ("*", ["*"]):
        return "L3" if shell and writes else "L2"
    if writes:
        return "L2"
    if net_allow:
        return "L1"
    return "L0"


def check_risk_tier_consistency(manifest: dict, location: str = "SKILL.md") -> list[Finding]:
    declared = manifest.get("risk_tier")
    implied = implied_min_tier(manifest)
    if declared is None:
        return [Finding(AST, "AST04-NO-RISK-TIER", "low",
                        f"no risk_tier declared (permissions imply at least {implied})", location)]
    if declared in RISK_TIERS and RISK_TIERS.index(declared) < RISK_TIERS.index(implied):
        return [Finding(AST, "AST04-RISK-TIER-UNDERSTATED", "high",
                        f"risk_tier {declared} understates declared permissions (imply >= {implied})",
                        location)]
    return []


# ---------------------------------------------------------------------------
# 6. Brand impersonation
# ---------------------------------------------------------------------------

# brand token -> identity suffixes allowed to publish under that brand.
DEFAULT_PROTECTED_BRANDS: dict[str, tuple[str, ...]] = {
    "google": ("google.com",), "gmail": ("google.com",),
    "microsoft": ("microsoft.com",), "github": ("github.com",),
    "anthropic": ("anthropic.com",), "claude": ("anthropic.com",),
    "openai": ("openai.com",), "aws": ("amazon.com", "aws.amazon.com"),
    "slack": ("slack.com", "salesforce.com"), "stripe": ("stripe.com",),
    "owasp": ("owasp.org",),
}


def check_brand_impersonation(manifest: dict, brands: dict[str, tuple[str, ...]] | None = None,
                              location: str = "SKILL.md") -> list[Finding]:
    brands = brands or DEFAULT_PROTECTED_BRANDS
    name = str(manifest.get("name", "")).lower()
    author = manifest.get("author")
    identity = ""
    if isinstance(author, dict):
        identity = str(author.get("identity", "")).lower()
    tokens = set(re.split(r"[^a-z0-9]+", name))
    out = []
    for brand, owners in brands.items():
        if brand in tokens and not any(identity.endswith(o) or identity.endswith(":" + o) for o in owners):
            out.append(Finding(AST, "AST04-BRAND-IMPERSONATION", "high",
                               f"name uses protected brand {brand!r} but author identity "
                               f"{identity or '(none)'!r} is not a verified owner", location))
    return out


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def check_skill(skill: Skill, brands: dict[str, tuple[str, ...]] | None = None) -> list[Finding]:
    out = validate_schema(skill.manifest)
    out += check_risk_tier_consistency(skill.manifest)
    out += check_brand_impersonation(skill.manifest, brands)
    out += find_hidden_content(skill.raw, "SKILL.md")
    for p in skill.files():
        rel = p.relative_to(skill.root).as_posix()
        if p.suffix == ".json" and not p.is_symlink():
            try:
                safe_json_loads(p.read_text(encoding="utf-8"))
            except UnsafeMetadataError as e:
                out.append(Finding(AST, "AST04-UNSAFE-JSON", "critical", str(e), rel))
    return out


def check_skill_dir(root) -> list[Finding]:
    """Like ``check_skill`` but converts unsafe-parse failures into findings."""
    from .common import load_skill
    try:
        skill = load_skill(root)
    except FileNotFoundError:
        return [Finding(AST, "AST04-NO-SKILL-MD", "high", "no SKILL.md in package", str(root))]
    except UnsafeMetadataError as e:
        return [Finding(AST, "AST04-UNSAFE-YAML", "critical", f"refused to parse metadata: {e}", "SKILL.md")]
    return check_skill(skill)


def parse_in_subprocess(skill_root: str, timeout: float = 10.0) -> dict:
    """Mitigation 5: parse untrusted metadata in a resource-limited child
    process with a scrubbed environment, so a parser bug cannot reach the
    host agent's credentials. Returns the parsed manifest or raises."""
    import sys
    from .ast06_isolation import run_sandboxed

    code = (
        "import json,sys;"
        "from ast_mitigations.common import load_skill;"
        "print(json.dumps(load_skill(sys.argv[1]).manifest, default=str))"
    )
    import os
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    res = run_sandboxed([sys.executable, "-I", "-c", f"import sys;sys.path.insert(0,{pkg_parent!r});" + code,
                         os.path.abspath(skill_root)], timeout=timeout)
    if res.returncode != 0:
        raise UnsafeMetadataError(f"sandboxed parse failed: {res.stderr.strip()[-300:]}")
    return json.loads(res.stdout)


__all__ = [
    "validate_schema", "safe_json_loads", "find_hidden_content", "decode_tag_smuggling",
    "check_risk_tier_consistency", "implied_min_tier", "check_brand_impersonation",
    "check_skill", "check_skill_dir", "parse_in_subprocess", "get_path",
]
