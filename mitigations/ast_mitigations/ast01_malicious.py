"""AST01 -- Malicious Skills: reference mitigations.

1. ed25519 signatures bound to a resolvable, revocable publisher identity
                                                  -> ``sign_skill`` / ``verify_skill`` / ``TrustStore``
2. Merkle-root registry signing                   -> ``ast02_supply_chain.TransparencyLog.root``
3. Publish- and install-time scanning             -> ``detect_malicious_patterns`` (+ ``ast08_scanning``)
4. Isolated execution                             -> ``ast06_isolation``
5. Structured audit of skill actions              -> ``ast09_governance.ReceiptLog``
6. Reputation / name hygiene                      -> ``check_typosquat``
7. Protect identity artifacts (SOUL.md, MEMORY.md) -> ``IdentityFileGuard``

A valid signature proves *authorship, not safety*: ``admit_skill`` therefore
requires a valid signature **and** a clean behavioural scan **and** a
non-revoked publisher before a skill may be installed.
"""

from __future__ import annotations

import base64
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .ast02_supply_chain import RevocationList
from .common import IDENTITY_FILES, Finding, Skill, canonical_digest, sha256_bytes

AST = "AST01"
SIGNATURE_FILE = "SIGNATURE.json"


# ---------------------------------------------------------------------------
# 1. Signatures bound to publisher identity
# ---------------------------------------------------------------------------

def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("the 'cryptography' package is required: pip install cryptography") from e
    return ed25519, serialization


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex)."""
    ed25519, serialization = _ed25519()
    sk = ed25519.Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return priv, pub


def key_id_for(public_key_hex: str) -> str:
    return "ed25519:" + sha256_bytes(bytes.fromhex(public_key_hex))[:16]


def _statement(publisher: str, key_id: str, name: str, version: str, digest: str) -> bytes:
    # The signed statement binds identity + skill identity + content digest, so a
    # signature cannot be replayed onto a different skill, version or publisher.
    return json.dumps({"type": "owasp-ast/skill-signature/v1", "publisher": publisher,
                       "key_id": key_id, "name": name, "version": version, "digest": digest},
                      sort_keys=True, separators=(",", ":")).encode()


def sign_skill(root: str | Path, private_key_hex: str, publisher: str,
               name: str, version: str) -> dict:
    """Sign the canonical digest of the whole package and write SIGNATURE.json."""
    ed25519, serialization = _ed25519()
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    kid = key_id_for(pub)
    digest = canonical_digest(root)
    sig = sk.sign(_statement(publisher, kid, name, version, digest))
    record = {"alg": "ed25519", "publisher": publisher, "key_id": kid, "name": name,
              "version": version, "digest": digest, "signature": base64.b64encode(sig).decode()}
    (Path(root) / SIGNATURE_FILE).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


@dataclass
class TrustStore:
    """Maps key ids to publisher identities and public keys. In production this
    is resolved from the publisher's identity anchor (e.g. ``did:web`` document or
    ``https://<domain>/.well-known/skill-keys.json``) and cached."""
    keys: dict[str, dict] = field(default_factory=dict)  # key_id -> {publisher, public_key}

    def add(self, publisher: str, public_key_hex: str) -> str:
        kid = key_id_for(public_key_hex)
        self.keys[kid] = {"publisher": publisher, "public_key": public_key_hex}
        return kid

    @classmethod
    def load(cls, path: str | Path) -> "TrustStore":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.keys, indent=2) + "\n", encoding="utf-8")


def verify_skill(root: str | Path, trust: TrustStore,
                 revocations: RevocationList | None = None) -> list[Finding]:
    """Verify SIGNATURE.json. Returns an empty list only when the signature is
    valid, the key is trusted for the claimed publisher, the digest matches the
    package on disk, and nothing is revoked."""
    ed25519, _ = _ed25519()
    from cryptography.exceptions import InvalidSignature

    root = Path(root)
    sig_path = root / SIGNATURE_FILE
    if not sig_path.is_file():
        return [Finding(AST, "AST01-UNSIGNED", "critical", "skill is unsigned; refusing install", SIGNATURE_FILE)]
    try:
        rec = json.loads(sig_path.read_text(encoding="utf-8"))
        kid, publisher = rec["key_id"], rec["publisher"]
        claimed_digest, sig = rec["digest"], base64.b64decode(rec["signature"])
        name, version = rec["name"], rec["version"]
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        return [Finding(AST, "AST01-BAD-SIGNATURE-FILE", "critical", f"malformed signature: {e}", SIGNATURE_FILE)]

    out: list[Finding] = []
    entry = trust.keys.get(kid)
    if entry is None:
        out.append(Finding(AST, "AST01-UNTRUSTED-KEY", "critical", f"key {kid} not in trust store", SIGNATURE_FILE))
    elif entry["publisher"] != publisher:
        out.append(Finding(AST, "AST01-PUBLISHER-MISMATCH", "critical",
                           f"key {kid} belongs to {entry['publisher']!r}, not {publisher!r}", SIGNATURE_FILE))
    else:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
        try:
            pk.verify(sig, _statement(publisher, kid, name, version, claimed_digest))
        except InvalidSignature:
            out.append(Finding(AST, "AST01-BAD-SIGNATURE", "critical", "signature does not verify", SIGNATURE_FILE))

    actual = canonical_digest(root)
    if actual != claimed_digest:
        out.append(Finding(AST, "AST01-DIGEST-MISMATCH", "critical",
                           "package content changed after signing (tampered or unsigned files added)",
                           SIGNATURE_FILE))
    if revocations is not None:
        for f in revocations.check(key_id=kid, digest=actual, publisher=publisher):
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# 3. Malicious pattern detection (install-time, deterministic layer)
# ---------------------------------------------------------------------------

_IDENT = "|".join(re.escape(f) for f in IDENTITY_FILES)
MALICIOUS_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    ("AST01-PIPE-TO-SHELL", "critical", "download piped directly into a shell",
     re.compile(r"(curl|wget|iwr|Invoke-WebRequest)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b|"
                r"(curl|wget)[^\n]{0,200}\|\s*(python|node|perl|iex)", re.I)),
    ("AST01-CLICKFIX", "high", "coerces user to paste/run commands manually (ClickFix)",
     re.compile(r"(paste|copy)[^\n]{0,60}(terminal|powershell|run dialog|command prompt)|"
                r"(terminal|powershell|command prompt|run dialog)[^\n]{0,60}(paste|copy)|"
                r"(win\s*\+\s*r|press\s+windows\s*\+\s*r)|"
                r"(setup|verification|action) required[^\n]{0,80}(run|paste|terminal)", re.I)),
    ("AST01-IDENTITY-WRITE", "critical", "writes to agent identity/memory file (persistence backdoor)",
     re.compile(rf"(?<![\w-])(append|write|add|insert|echo)\b[^\n]{{0,80}}\b({_IDENT})\b|"
                rf">>?\s*[\"']?[~\w./$-]*\b({_IDENT})\b|"
                rf"open\([^\n]{{0,80}}\b({_IDENT})\b[^\n]{{0,20}}['\"][wa]|"
                rf"\b({_IDENT})\b[^\n]{{0,40}}(write_text|write_bytes)", re.I)),
    ("AST01-IDENTITY-READ-EXFIL", "high", "reads identity files for exfiltration (identity cloning)",
     re.compile(rf"\b({_IDENT})\b[^\n]{{0,120}}(send|upload|post|exfil|requests\.|fetch\()", re.I)),
    ("AST01-CREDENTIAL-ACCESS", "high", "accesses credential stores",
     re.compile(r"~/\.ssh/|id_rsa|id_ed25519|\.aws/credentials|(?<!\w)\.env\b(?!\.)|\.npmrc|\.pypirc|"
                r"wallet\.dat|keychain|Login Data|cookies\.sqlite|\.kube/config", re.I)),
    ("AST01-REVERSE-SHELL", "critical", "reverse shell pattern",
     re.compile(r"/dev/tcp/|nc\s+-e\s|ncat\s.*-e\s|bash\s+-i\s*>&|socket\.socket\([^)]*\).*connect", re.I)),
    ("AST01-WEBSOCKET-C2", "high", "persistent websocket to raw IP or unusual host (C2)",
     re.compile(r"wss?://(\d{1,3}\.){3}\d{1,3}|wss?://[^\s'\"]+\.(onion|top|xyz|ru|tk)\b", re.I)),
    ("AST01-MEMORY-POISON", "high", "instructs agent to persist instructions for future sessions",
     re.compile(r"(remember|always|in (all|future) sessions?)[^\n]{0,80}"
                r"(run|execute|send|ignore (previous|prior)|disable)", re.I)),
    ("AST01-SECURITY-DISABLE", "high", "instructs disabling of safety/sandbox/approval",
     re.compile(r"(disable|turn off|bypass|skip)[^\n]{0,40}(sandbox|approval|confirmation|"
                r"safety|antivirus|defender|gatekeeper|permission prompt)", re.I)),
]

TEXT_SUFFIXES = {".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".ts", ".ps1",
                 ".rb", ".pl", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ""}


def detect_malicious_patterns(skill: Skill) -> list[Finding]:
    out: list[Finding] = []
    for p in skill.files():
        if p.is_symlink() or p.suffix.lower() not in TEXT_SUFFIXES or p.name == SIGNATURE_FILE:
            continue
        rel = p.relative_to(skill.root).as_posix()
        text = unicodedata.normalize("NFKC", p.read_text(encoding="utf-8", errors="replace"))
        for rule, sev, msg, rx in MALICIOUS_PATTERNS:
            m = rx.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                out.append(Finding(AST, rule, sev, f"{msg}: {m.group(0)[:80]!r}", f"{rel}:{line}"))
    return out


# ---------------------------------------------------------------------------
# 6. Typosquatting
# ---------------------------------------------------------------------------

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
                             "_": "-", ".": "-"})


def _skeleton(name: str) -> str:
    s = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    s = s.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    return re.sub(r"-+", "-", s).strip("-")


def damerau_levenshtein(a: str, b: str) -> int:
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def check_typosquat(name: str, known: list[str], max_distance: int = 2) -> list[Finding]:
    """Flag ``name`` if it is confusingly close to an established skill name."""
    out = []
    sk = _skeleton(name)
    for k in known:
        if k == name:
            continue
        ks = _skeleton(k)
        dist = damerau_levenshtein(sk, ks)
        limit = 1 if len(ks) <= 6 else max_distance
        if sk == ks or dist <= limit:
            out.append(Finding(AST, "AST01-TYPOSQUAT", "high",
                               f"name {name!r} is confusable with established skill {k!r} "
                               f"(skeleton distance {dist})"))
    return out


# ---------------------------------------------------------------------------
# 7. Identity artifact protection
# ---------------------------------------------------------------------------

class IdentityFileGuard:
    """Snapshot identity files before a skill runs and verify them after.

    Any change made while a skill was active -- or by an uninstalled skill --
    is reported, which catches SOUL.md / MEMORY.md persistence backdoors. Pair
    with OS-level read-only mounts (see ``ast06_isolation``)."""

    def __init__(self, agent_home: str | Path, names: tuple[str, ...] = IDENTITY_FILES):
        self.home = Path(agent_home)
        self.names = names
        self.baseline: dict[str, str | None] = {}

    def _hash(self, name: str) -> str | None:
        p = self.home / name
        return sha256_bytes(p.read_bytes()) if p.is_file() else None

    def snapshot(self) -> dict[str, str | None]:
        self.baseline = {n: self._hash(n) for n in self.names}
        return dict(self.baseline)

    def verify(self) -> list[Finding]:
        out = []
        for n in self.names:
            now = self._hash(n)
            before = self.baseline.get(n)
            if now != before:
                what = "created" if before is None else "deleted" if now is None else "modified"
                out.append(Finding(AST, "AST01-IDENTITY-TAMPER", "critical",
                                   f"identity file {n} was {what} during skill execution", n))
        return out


# ---------------------------------------------------------------------------
# Admission decision
# ---------------------------------------------------------------------------

def admit_skill(root: str | Path, trust: TrustStore, revocations: RevocationList | None = None,
                known_names: list[str] | None = None) -> tuple[bool, list[Finding]]:
    """Install gate: signature AND scan AND name hygiene must all pass."""
    from .common import load_skill
    from . import ast04_metadata, ast08_scanning

    findings = verify_skill(root, trust, revocations)
    findings += ast04_metadata.check_skill_dir(root)
    try:
        skill = load_skill(root)
    except Exception:
        skill = None
    if skill is not None:
        findings += detect_malicious_patterns(skill)
        if known_names:
            findings += check_typosquat(skill.name, known_names)
    findings += ast08_scanning.scan_directory(root).findings
    ok = not any(f.severity in ("high", "critical") for f in findings)
    return ok, findings
