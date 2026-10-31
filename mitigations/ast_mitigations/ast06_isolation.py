"""AST06 -- Weak Isolation: reference mitigations.

1. Container isolation by default                    -> ``container_command``
2. Control interfaces on localhost with auth         -> ``check_listener_config``
3. seccomp / syscall restriction                     -> ``seccomp_profile`` (layered on runtime default)
4. Per-skill process isolation                       -> ``run_sandboxed`` (local fallback) / one container per skill
5. Restrict workspace precedence / shadowing         -> ``detect_shadowing``
6. Rate-limit + authenticate WebSocket connections   -> ``WebSocketAdmission``
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .common import IDENTITY_FILES, Finding

AST = "AST06"


# ---------------------------------------------------------------------------
# 1/3/4. Container profile
# ---------------------------------------------------------------------------

def container_command(skill_dir: str, image: str, command: list[str], *, runtime: str = "docker",
                      egress_proxy: str | None = None, memory: str = "512m", cpus: str = "1",
                      pids: int = 128, seccomp_path: str | None = None,
                      workdir_rw: str | None = None) -> list[str]:
    """Build a hardened ``docker run`` / ``podman run`` argv for one skill.

    * no network unless an egress proxy that enforces the skill's domain
      allowlist is supplied (then the container joins only that network)
    * read-only root fs, skill mounted read-only, tmpfs scratch
    * all capabilities dropped, no-new-privileges, non-root uid
    * memory / cpu / pid limits; never mounts the host home, docker socket,
      or identity files
    """
    skill_dir = os.path.abspath(skill_dir)
    argv = [runtime, "run", "--rm", "--init",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            "--memory", memory, "--cpus", cpus, "--pids-limit", str(pids),
            "--ipc", "none",
            "-v", f"{skill_dir}:/skill:ro", "-w", "/skill",
            "--env", "HOME=/tmp"]
    if seccomp_path:
        argv += ["--security-opt", f"seccomp={seccomp_path}"]
    if egress_proxy:
        argv += ["--network", egress_proxy]
    else:
        argv += ["--network", "none"]
    if workdir_rw:
        argv += ["-v", f"{os.path.abspath(workdir_rw)}:/work:rw"]
    argv += [image, *command]
    return argv


def check_container_command(argv: list[str]) -> list[Finding]:
    """Lint an existing run command for isolation-breaking flags."""
    joined = " ".join(argv)
    out = []
    bad = {
        "--privileged": ("critical", "privileged container"),
        "--network host": ("high", "host network namespace"),
        "--network=host": ("high", "host network namespace"),
        "--pid host": ("high", "host PID namespace"),
        "--pid=host": ("high", "host PID namespace"),
        "docker.sock": ("critical", "docker socket mounted (host root)"),
        "seccomp=unconfined": ("high", "seccomp disabled"),
        "apparmor=unconfined": ("high", "AppArmor disabled"),
        "--cap-add ALL": ("critical", "all capabilities added"),
        "--cap-add=ALL": ("critical", "all capabilities added"),
        "SYS_ADMIN": ("high", "CAP_SYS_ADMIN granted"),
    }
    for needle, (sev, msg) in bad.items():
        if needle in joined:
            out.append(Finding(AST, "AST06-CONTAINER-FLAG", sev, f"{msg} ({needle})"))
    for i, a in enumerate(argv):
        if a in ("-v", "--volume", "--mount") and i + 1 < len(argv):
            src = argv[i + 1].split(":")[0].replace("source=", "").split(",")[0]
            if src in ("/", os.path.expanduser("~"), "$HOME", "~") or any(src.endswith(f) for f in IDENTITY_FILES):
                out.append(Finding(AST, "AST06-HOST-MOUNT", "critical", f"mounts sensitive host path {src!r}"))
    if "--read-only" not in argv:
        out.append(Finding(AST, "AST06-WRITABLE-ROOTFS", "medium", "root filesystem is writable"))
    if not any(a.startswith("--cap-drop") for a in argv):
        out.append(Finding(AST, "AST06-CAPS", "medium", "capabilities not dropped"))
    return out


# Syscalls that a skill never needs and that underpin container escapes.
DENIED_SYSCALLS = [
    "mount", "umount", "umount2", "pivot_root", "chroot", "ptrace", "process_vm_readv",
    "process_vm_writev", "kexec_load", "kexec_file_load", "init_module", "finit_module",
    "delete_module", "bpf", "perf_event_open", "unshare", "setns", "keyctl", "add_key",
    "request_key", "userfaultfd", "open_by_handle_at", "name_to_handle_at", "swapon", "swapoff",
    "reboot", "acct", "quotactl", "lookup_dcookie", "iopl", "ioperm", "mount_setattr",
    "move_mount", "open_tree", "fsopen", "fsmount", "fspick",
]


def seccomp_profile() -> dict:
    """An OCI seccomp profile that denies escape-relevant syscalls with EPERM.
    Apply *in addition to* the runtime's default profile (or merge into it)."""
    return {
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
        "syscalls": [{"names": DENIED_SYSCALLS, "action": "SCMP_ACT_ERRNO", "errnoRet": 1}],
    }


# ---------------------------------------------------------------------------
# 4. Local sandbox fallback (when containers are unavailable)
# ---------------------------------------------------------------------------

SAFE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")


def run_sandboxed(argv: list[str], *, timeout: float = 30.0, cpu_s: int = 10, mem_mb: int = 512,
                  max_files: int = 64, max_procs: int = 32, max_fsize_mb: int = 16,
                  cwd: str | None = None, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a skill subprocess with a scrubbed environment (no API keys, no HOME),
    a throwaway working directory, POSIX resource limits and a wall-clock timeout.

    This is *defence in depth*, not a substitute for a container / VM: it does
    not restrict network or filesystem reads. Use ``container_command`` in
    production."""
    env = {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}
    tmp = tempfile.mkdtemp(prefix="skill-sbx-")
    env.update({"HOME": tmp, "TMPDIR": tmp})
    if extra_env:
        env.update(extra_env)

    def limits():  # pragma: no cover - runs in child
        import resource
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
        resource.setrlimit(resource.RLIMIT_NOFILE, (max_files, max_files))
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_fsize_mb << 20, max_fsize_mb << 20))
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (max_procs, max_procs))
        except (ValueError, OSError):
            pass
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return subprocess.run(argv, cwd=cwd or tmp, env=env, capture_output=True, text=True,
                          timeout=timeout, preexec_fn=limits if sys.platform != "win32" else None,
                          stdin=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# 2. Listener configuration
# ---------------------------------------------------------------------------

def check_listener_config(cfg: dict) -> list[Finding]:
    """cfg example: ``{"host": "127.0.0.1", "port": 7777, "auth": {"type": "token",
    "token_bytes": 32}, "allowed_origins": ["app://agent"], "rate_limit_per_min": 30}``."""
    out = []
    host = str(cfg.get("host", "0.0.0.0"))
    try:
        ip = ipaddress.ip_address(host if host != "localhost" else "127.0.0.1")
        if not ip.is_loopback:
            out.append(Finding(AST, "AST06-BIND-ALL", "high" if ip.is_unspecified else "medium",
                               f"control interface binds {host}; bind to 127.0.0.1 / ::1 or a unix socket"))
    except ValueError:
        out.append(Finding(AST, "AST06-BIND-HOSTNAME", "medium", f"binds hostname {host!r}; use loopback IP"))
    auth = cfg.get("auth") or {}
    if not auth or auth.get("type") in (None, "none"):
        out.append(Finding(AST, "AST06-NO-AUTH", "critical", "control interface has no authentication"))
    elif auth.get("type") == "token" and int(auth.get("token_bytes", 0)) < 32:
        out.append(Finding(AST, "AST06-WEAK-TOKEN", "high", "session token < 256 bits (brute-forceable from a browser tab)"))
    if not cfg.get("allowed_origins") or "*" in cfg.get("allowed_origins", []):
        out.append(Finding(AST, "AST06-NO-ORIGIN-CHECK", "high",
                           "no Origin allowlist: any web page can open a WebSocket to localhost"))
    if not cfg.get("rate_limit_per_min"):
        out.append(Finding(AST, "AST06-NO-RATE-LIMIT", "medium", "no connection/auth rate limit"))
    return out


# ---------------------------------------------------------------------------
# 6. WebSocket admission
# ---------------------------------------------------------------------------

@dataclass
class WebSocketAdmission:
    token: str
    allowed_origins: set[str]
    rate_per_min: int = 30
    lockout_after: int = 5
    lockout_s: int = 300
    _buckets: dict[str, list[float]] = field(default_factory=dict)
    _failures: dict[str, int] = field(default_factory=dict)
    _locked_until: dict[str, float] = field(default_factory=dict)

    def admit(self, client: str, origin: str | None, presented_token: str | None,
              now: float | None = None) -> tuple[bool, str]:
        """Call from the WebSocket upgrade handler -- for *every* client,
        including 127.0.0.1, since browser tabs connect from loopback."""
        now = time.time() if now is None else now
        if self._locked_until.get(client, 0) > now:
            return False, "locked out"
        window = [t for t in self._buckets.get(client, []) if now - t < 60]
        if len(window) >= self.rate_per_min:
            self._buckets[client] = window
            return False, "rate limited"
        window.append(now)
        self._buckets[client] = window
        if origin is None or origin not in self.allowed_origins:
            return False, f"origin {origin!r} not allowed"
        if not presented_token or not hmac.compare_digest(presented_token.encode(), self.token.encode()):
            n = self._failures.get(client, 0) + 1
            self._failures[client] = n
            if n >= self.lockout_after:
                self._locked_until[client] = now + self.lockout_s
                self._failures[client] = 0
            return False, "bad token"
        self._failures.pop(client, None)
        return True, "ok"


# ---------------------------------------------------------------------------
# 5. Skill shadowing
# ---------------------------------------------------------------------------

def _skill_names(directory: Path) -> dict[str, Path]:
    out = {}
    if directory.is_dir():
        for d in sorted(directory.iterdir()):
            if (d / "SKILL.md").is_file():
                out[d.name] = d
    return out


def detect_shadowing(tiers: list[tuple[str, str | Path]], approved_overrides: set[str] = frozenset()) -> list[Finding]:
    """``tiers`` is highest-precedence first, e.g.
    ``[("workspace", "./skills"), ("managed", "~/.agent/skills"), ("bundled", "/opt/agent/skills")]``.
    Any higher tier that shadows a lower-tier skill without an explicit, recorded
    approval is reported; hosts should refuse to load it until confirmed."""
    out = []
    resolved = [(label, _skill_names(Path(os.path.expanduser(str(p))))) for label, p in tiers]
    for i, (label, names) in enumerate(resolved):
        for name in names:
            for lower_label, lower in resolved[i + 1:]:
                if name in lower and f"{label}:{name}" not in approved_overrides:
                    out.append(Finding(AST, "AST06-SKILL-SHADOWING", "high",
                                       f"{label} skill {name!r} shadows {lower_label} skill of the same name; "
                                       "require explicit confirmation", str(names[name])))
                    break
    return out
