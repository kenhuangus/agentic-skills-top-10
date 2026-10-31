"""AST10 -- Cross-Platform Reuse: reference mitigations.

1. Universal Skill Format as the source of truth   -> ``to_universal``
2. Re-validate security metadata on every port     -> ``diff_security`` / ``check_port``
3. Cross-registry threat-intel sharing             -> ``threat_intel_record`` (digest-keyed, platform-neutral)
4. Platform-agnostic scanning                      -> ``ast08_scanning.scan_directory`` (content layer only)
5. Normalise risk_tier / permissions / signature    -> ``normalise_security`` + ``port_to``

``port_to`` never silently drops a security property: anything the target
format cannot express natively is carried in an ``x-owasp-ast`` extension
block, and ``check_port`` fails if a property is lost or weakened.
"""

from __future__ import annotations

import copy
from typing import Any

from .common import RISK_TIERS, Finding, get_path

AST = "AST10"
EXT_KEY = "x-owasp-ast"
PLATFORMS = ("universal", "openclaw", "claude", "cursor", "vscode")

# Platform tool names -> universal capability, used to infer permissions when a
# platform only exposes a tool list (e.g. Claude Code ``allowed-tools``).
_TOOL_CAPS = {
    "bash": "shell", "shell": "shell", "terminal": "shell", "run_in_terminal": "shell",
    "webfetch": "network", "web_fetch": "network", "fetch": "network", "websearch": "network",
    "write": "files.write", "edit": "files.write", "multiedit": "files.write", "create_file": "files.write",
    "read": "files.read", "glob": "files.read", "grep": "files.read", "read_file": "files.read",
}


def _tools_list(v: Any) -> list[str]:
    if isinstance(v, str):
        return [t.strip() for t in v.replace(",", " ").split() if t.strip()]
    return [str(t) for t in v or []]


def to_universal(manifest: dict, platform: str) -> dict:
    """Map a platform-specific manifest into the Universal Skill Format shape.
    Unknown platforms are treated as universal. An ``x-owasp-ast`` block, if
    present, is authoritative for security fields."""
    m = copy.deepcopy(manifest or {})
    ext = m.pop(EXT_KEY, None) or {}
    if platform == "vscode":
        contrib = m.get("contributes", {}) or {}
        u = {"name": m.get("name"), "version": m.get("version"), "description": m.get("description"),
             "author": {"name": m.get("publisher")}, "permissions": {}}
        caps = set(m.get("capabilities", {}).keys()) if isinstance(m.get("capabilities"), dict) else set()
        if "untrustedWorkspaces" in caps and m["capabilities"]["untrustedWorkspaces"].get("supported") is True:
            u["permissions"]["shell"] = True
        if contrib.get("languageModelTools"):
            u["permissions"]["tools"] = [t.get("name") for t in contrib["languageModelTools"]]
    elif platform == "cursor":
        # .mdc rule frontmatter: description, globs, alwaysApply -- no security fields.
        u = {"name": m.get("name"), "description": m.get("description"), "version": m.get("version")}
    elif platform == "claude":
        u = {k: m.get(k) for k in ("name", "description", "version", "license") if k in m}
        tools = _tools_list(m.get("allowed-tools"))
        if tools:
            perms: dict[str, Any] = {"tools": tools}
            caps = {_TOOL_CAPS.get(t.split("(")[0].lower()) for t in tools}
            if "shell" in caps:
                perms["shell"] = True
            if "network" in caps:
                perms["network"] = True     # Claude tool lists do not carry domain scope
            u["permissions"] = perms
        for k in ("permissions", "risk_tier", "signature", "content_hash", "author"):
            if k in m:
                u[k] = m[k]
    else:  # universal / openclaw share field names
        u = m
    for k, v in ext.items():
        u[k] = v
    return {k: v for k, v in u.items() if v is not None}


def normalise_security(u: dict) -> dict:
    """Project the security-relevant properties into a comparable form."""
    perms = u.get("permissions") if isinstance(u.get("permissions"), dict) else None
    net = perms.get("network") if perms else None
    if isinstance(net, dict):
        allow = net.get("allow", [])
        allow = sorted([allow] if isinstance(allow, str) else allow)
        network = "any" if "*" in allow else allow
    elif net is True:
        network = "any"
    elif net is False:
        network = []
    else:
        network = None
    files = (perms or {}).get("files") or {}
    return {
        "has_permissions": perms is not None,
        "network": network,
        "shell": (perms or {}).get("shell") if perms else None,
        "files_write": sorted(files.get("write", []) or []) if isinstance(files, dict) else None,
        "deny_write": sorted(files.get("deny_write", []) or []) if isinstance(files, dict) else [],
        "tools": sorted(_tools_list((perms or {}).get("tools"))) if perms and "tools" in perms else None,
        "risk_tier": u.get("risk_tier"),
        "signature": u.get("signature"),
        "content_hash": u.get("content_hash"),
        "author_identity": get_path(u, "author.identity"),
        "scan_status": get_path(u, "scan_status.result"),
    }


def diff_security(source: dict, target: dict) -> list[Finding]:
    """Compare normalised security properties of a source and a ported target.
    Both arguments are universal-shaped manifests (see ``to_universal``)."""
    s, t = normalise_security(source), normalise_security(target)
    out: list[Finding] = []

    def lost(field: str, sev: str, msg: str):
        out.append(Finding(AST, "AST10-PROPERTY-LOST", sev, f"{field}: {msg}"))

    def weakened(field: str, sev: str, msg: str):
        out.append(Finding(AST, "AST10-PROPERTY-WEAKENED", sev, f"{field}: {msg}"))

    if s["has_permissions"] and not t["has_permissions"]:
        lost("permissions", "critical", "permission manifest dropped in translation")
    if isinstance(s["network"], list) and t["network"] == "any":
        weakened("network", "high", f"allowlist {s['network']} became unrestricted egress")
    elif isinstance(s["network"], list) and isinstance(t["network"], list) and set(t["network"]) - set(s["network"]):
        weakened("network", "high", f"new egress hosts {sorted(set(t['network']) - set(s['network']))}")
    elif s["network"] is not None and t["network"] is None and t["has_permissions"]:
        lost("network", "high", "network scope no longer declared")
    if s["shell"] in (False, None) and t["shell"] is True and s["has_permissions"]:
        weakened("shell", "high", "shell access granted on target but not on source")
    if s["files_write"] is not None and t["files_write"] is not None and set(t["files_write"]) - set(s["files_write"]):
        weakened("files.write", "high", f"new writable paths {sorted(set(t['files_write']) - set(s['files_write']))}")
    if set(s["deny_write"]) - set(t["deny_write"]):
        lost("files.deny_write", "high", f"identity-file protections dropped: {sorted(set(s['deny_write']) - set(t['deny_write']))}")
    if s["tools"] is not None and t["tools"] is not None and set(t["tools"]) - set(s["tools"]):
        weakened("tools", "medium", f"new tools {sorted(set(t['tools']) - set(s['tools']))}")
    if s["risk_tier"] and not t["risk_tier"]:
        lost("risk_tier", "high", f"{s['risk_tier']} warning silently dropped")
    elif s["risk_tier"] in RISK_TIERS and t["risk_tier"] in RISK_TIERS and \
            RISK_TIERS.index(t["risk_tier"]) < RISK_TIERS.index(s["risk_tier"]):
        weakened("risk_tier", "high", f"{s['risk_tier']} downgraded to {t['risk_tier']}")
    for k, sev in (("signature", "high"), ("content_hash", "high"), ("author_identity", "medium"),
                   ("scan_status", "low")):
        if s[k] and not t[k]:
            lost(k, sev, "dropped")
    if s["content_hash"] and t["content_hash"] and s["content_hash"] != t["content_hash"]:
        out.append(Finding(AST, "AST10-CONTENT-CHANGED", "high",
                           "content_hash differs: ported package is not the reviewed package; re-scan and re-sign"))
    return out


def check_port(source: dict, source_platform: str, target: dict, target_platform: str) -> list[Finding]:
    return diff_security(to_universal(source, source_platform), to_universal(target, target_platform))


# ---------------------------------------------------------------------------
# 5. Port without loss
# ---------------------------------------------------------------------------

SECURITY_FIELDS = ("permissions", "risk_tier", "signature", "content_hash", "scan_status", "author")


def port_to(universal: dict, platform: str) -> dict:
    """Emit a target-platform manifest from a universal one, carrying every
    security field the target cannot natively express in ``x-owasp-ast``.
    Hosts that understand the extension enforce it; hosts that do not still
    preserve it, so a later port back does not lose it."""
    u = copy.deepcopy(universal)
    sec = {k: u[k] for k in SECURITY_FIELDS if k in u}
    if platform in ("universal", "openclaw"):
        return u
    if platform == "claude":
        out: dict[str, Any] = {k: u[k] for k in ("name", "description", "version", "license") if k in u}
        tools = get_path(u, "permissions.tools")
        if tools:
            out["allowed-tools"] = list(tools)
    elif platform == "cursor":
        out = {"description": u.get("description", ""), "globs": [], "alwaysApply": False}
    elif platform == "vscode":
        out = {"name": u.get("name"), "version": u.get("version"), "description": u.get("description"),
               "publisher": get_path(u, "author.name", "")}
    else:
        raise ValueError(f"unknown platform {platform!r}; expected one of {PLATFORMS}")
    out[EXT_KEY] = sec
    return out


# ---------------------------------------------------------------------------
# 3. Threat-intel record
# ---------------------------------------------------------------------------

def threat_intel_record(content_hash: str, names: dict[str, str], indicators: list[str],
                        severity: str, reporter: str) -> dict:
    """Platform-neutral record keyed on content hash, so a takedown on one
    registry can be matched on every other registry carrying the same payload
    under a different name (multi-platform campaigns, cross-registry arbitrage)."""
    return {"schema": "owasp-ast/threat-intel/v1", "content_hash": content_hash,
            "names": names,  # platform -> listed name
            "indicators": sorted(set(indicators)), "severity": severity, "reporter": reporter}
