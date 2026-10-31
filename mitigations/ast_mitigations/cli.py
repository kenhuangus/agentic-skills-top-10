"""Command-line entry point: ``python -m ast_mitigations <command> ...``.

Exit codes: 0 = pass, 1 = blocking findings / verification failure, 2 = usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import (ast01_malicious, ast02_supply_chain, ast03_privilege, ast04_metadata,
               ast05_external_refs, ast06_isolation, ast07_update_drift, ast08_scanning,
               ast10_cross_platform)
from .common import SEVERITIES, Report, UnsafeMetadataError, load_skill, safe_yaml_load, split_frontmatter

_SEV_ICON = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}


def _print(report: Report, as_json: bool, threshold: str) -> int:
    if as_json:
        d = report.to_dict()
        d["threshold"] = threshold
        d["passed"] = report.passed(threshold)
        print(json.dumps(d, indent=2))
    else:
        order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
        for f in sorted(report.findings, key=lambda f: (order[f.severity], f.ast, f.rule)):
            loc = f" ({f.location})" if f.location else ""
            print(f"[{_SEV_ICON[f.severity]}] {f.ast} {f.rule}: {f.message}{loc}")
        verdict = "PASS" if report.passed(threshold) else "BLOCK"
        print(f"\n{len(report.findings)} finding(s); max severity {report.max_severity}; "
              f"threshold {threshold} -> {verdict}")
    return 0 if report.passed(threshold) else 1


def cmd_scan(a) -> int:
    root = Path(a.skill_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"{root} is not a directory")
    report = Report(subject=str(root))
    report.extend(ast04_metadata.check_skill_dir(root))
    try:
        skill = load_skill(root)
    except (UnsafeMetadataError, FileNotFoundError):
        skill = None  # already reported by ast04_metadata.check_skill_dir
    if skill is not None:
        report.extend(ast01_malicious.detect_malicious_patterns(skill))
        if a.known_names:
            known = [l.strip() for l in Path(a.known_names).read_text().splitlines() if l.strip()]
            report.extend(ast01_malicious.check_typosquat(skill.name, known))
        report.extend(ast03_privilege.validate_permission_manifest(skill.manifest))
        policy = ast05_external_refs.ReferencePolicy(allow=a.allow_domain) if a.allow_domain else None
        pins = None
        pin_file = root / "reference-pins.json"
        if pin_file.exists():
            pins = ast05_external_refs.ReferencePins.load(pin_file)
        report.extend(ast05_external_refs.check_skill(skill, policy, pins))
    report.extend(ast02_supply_chain.check_skill_dir(root, tuple(a.trusted_host or ())))
    report.extend(ast08_scanning.scan_directory(root).findings)
    # one finding per (rule, location)
    seen, uniq = set(), []
    for f in report.findings:
        if (f.rule, f.location) not in seen:
            seen.add((f.rule, f.location))
            uniq.append(f)
    report.findings = uniq
    return _print(report, a.json, a.threshold)


def cmd_keygen(a) -> int:
    priv, pub = ast01_malicious.generate_keypair()
    Path(a.out + ".key").write_text(priv + "\n")
    Path(a.out + ".key").chmod(0o600)
    Path(a.out + ".pub").write_text(pub + "\n")
    print(f"wrote {a.out}.key (private, 0600) and {a.out}.pub; key id {ast01_malicious.key_id_for(pub)}")
    return 0


def cmd_sign(a) -> int:
    skill = load_skill(a.skill_dir)
    rec = ast01_malicious.sign_skill(a.skill_dir, Path(a.key).read_text().strip(), a.publisher,
                                     skill.name, str(skill.manifest.get("version", "0.0.0")))
    print(json.dumps(rec, indent=2))
    return 0


def cmd_verify(a) -> int:
    trust = ast01_malicious.TrustStore.load(a.trust)
    rev = ast02_supply_chain.RevocationList.load(a.revocations) if a.revocations else None
    report = Report(subject=a.skill_dir).extend(ast01_malicious.verify_skill(a.skill_dir, trust, rev))
    if not report.findings:
        print("signature valid; publisher trusted; digest matches; not revoked")
    return _print(report, a.json, "high")


def cmd_lock(a) -> int:
    lock = ast07_update_drift.SkillLock.load(a.lock)
    root = Path(a.install_root)
    for d in sorted(root.iterdir()):
        if (d / "SKILL.md").is_file():
            s = load_skill(d)
            e = lock.pin(s.name if s.name == d.name else d.name, str(s.manifest.get("version", "0.0.0")), d)
            print(f"pinned {d.name} {e['version']} {e['digest']}")
    lock.save()
    return 0


def cmd_verify_lock(a) -> int:
    lock = ast07_update_drift.SkillLock.load(a.lock)
    report = Report(subject=a.install_root).extend(ast07_update_drift.verify_installed(lock, a.install_root))
    lock.save()
    return _print(report, a.json, "high")


def _load_manifest(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return ast04_metadata.safe_json_loads(text)
    fm, _ = split_frontmatter(text)
    return safe_yaml_load(fm if fm else text) or {}


def cmd_port_diff(a) -> int:
    src, tgt = _load_manifest(a.source), _load_manifest(a.target)
    report = Report(subject=f"{a.source} -> {a.target}")
    report.extend(ast10_cross_platform.check_port(src, a.source_platform, tgt, a.target_platform))
    return _print(report, a.json, a.threshold)


def cmd_port(a) -> int:
    import yaml
    src = ast10_cross_platform.to_universal(_load_manifest(a.source), a.source_platform)
    out = ast10_cross_platform.port_to(src, a.target_platform)
    if a.target_platform == "vscode":
        print(json.dumps(out, indent=2))
    else:
        print("---\n" + yaml.safe_dump(out, sort_keys=False) + "---")
    return 0


def cmd_container(a) -> int:
    argv = ast06_isolation.container_command(a.skill_dir, a.image, a.command or ["true"],
                                             runtime=a.runtime, egress_proxy=a.egress_network)
    print(" ".join(argv))
    return 0


def cmd_seccomp(a) -> int:
    print(json.dumps(ast06_isolation.seccomp_profile(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ast_mitigations", description="OWASP AST10 reference mitigations")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="static checks for AST01-05 and AST08 on one skill directory")
    s.add_argument("skill_dir")
    s.add_argument("--json", action="store_true")
    s.add_argument("--threshold", default="high", choices=SEVERITIES)
    s.add_argument("--known-names", help="file of established skill names (typosquat check)")
    s.add_argument("--allow-domain", action="append", help="reference allowlist entry (repeatable)")
    s.add_argument("--trusted-host", action="append", help="host allowed in *_BASE_URL overrides")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("keygen", help="generate an ed25519 publisher keypair")
    s.add_argument("--out", default="publisher")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("sign", help="sign a skill package (AST01/AST02)")
    s.add_argument("skill_dir")
    s.add_argument("--key", required=True)
    s.add_argument("--publisher", required=True, help="e.g. did:web:example.com")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("verify", help="verify a skill signature against a trust store")
    s.add_argument("skill_dir")
    s.add_argument("--trust", required=True)
    s.add_argument("--revocations")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("lock", help="pin every installed skill to its content digest (AST07)")
    s.add_argument("install_root")
    s.add_argument("--lock", default="skills.lock.json")
    s.set_defaults(fn=cmd_lock)

    s = sub.add_parser("verify-lock", help="detect drift against the lockfile (AST07)")
    s.add_argument("install_root")
    s.add_argument("--lock", default="skills.lock.json")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify_lock)

    for name, fn, helptext in (("port-diff", cmd_port_diff, "find security properties lost in a port (AST10)"),
                               ("port", cmd_port, "port a manifest without losing security fields (AST10)")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("source")
        if name == "port-diff":
            s.add_argument("target")
            s.add_argument("--json", action="store_true")
            s.add_argument("--threshold", default="high", choices=SEVERITIES)
        s.add_argument("--from", dest="source_platform", default="universal",
                       choices=ast10_cross_platform.PLATFORMS)
        s.add_argument("--to", dest="target_platform", default="universal" if name == "port-diff" else "claude",
                       choices=ast10_cross_platform.PLATFORMS)
        s.set_defaults(fn=fn)

    s = sub.add_parser("container-cmd", help="print a hardened container command for a skill (AST06)")
    s.add_argument("skill_dir")
    s.add_argument("--image", required=True)
    s.add_argument("--runtime", default="docker")
    s.add_argument("--egress-network", help="network that routes through an allowlisting egress proxy")
    s.add_argument("command", nargs="*")
    s.set_defaults(fn=cmd_container)

    s = sub.add_parser("seccomp", help="print the escape-syscall seccomp profile (AST06)")
    s.set_defaults(fn=cmd_seccomp)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except (FileNotFoundError, UnsafeMetadataError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
