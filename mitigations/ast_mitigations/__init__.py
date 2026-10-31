"""OWASP Agentic Skills Top 10 -- reference mitigations.

One module per risk (``ast01_malicious`` ... ``ast10_cross_platform``) plus a
CLI (``python -m ast_mitigations``). See ``mitigations/README.md``.
"""

__version__ = "0.1.0"

from .common import Finding, Report, Skill, canonical_digest, load_skill  # noqa: F401
