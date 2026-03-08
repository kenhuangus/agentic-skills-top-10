# OWASP Agentic Skills Top 10

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/projects/)
[![License: CC BY-SA 4.0](https://img.shields.io/badge/License-CC%20BY--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)

> Security Risks and Mitigations for AI Agent Skills

## Overview

The **OWASP Agentic Skills Top 10** documents the 10 most critical security risks in agentic AI skills across OpenClaw (SKILL.md YAML), Claude Code (skill.json), Cursor/Codex (manifest.json), and VS Code (package.json) ecosystems. Skills represent the execution layer giving agents real-world impact through platform-specific metadata and scripts.

While significant attention has been devoted to securing large language models (LLMs) and the Model Context Protocol (MCP) tool layer, the intermediate behavior layer—embodied in agentic skills—has emerged as a particularly vulnerable and under-protected component of the AI agent ecosystem.

## The Problem

According to Snyk's ToxicSkills research (February 2026), **36% of AI agent skills contain security flaws**, with over 1,467 vulnerable skills identified in active circulation. The same research uncovered multiple malicious campaigns, including the ClawHub malware distribution operation that compromised thousands of OpenClaw installations.

No dedicated security guidance exists for agent skills despite their role as the primary attack surface for autonomous AI actions.

## What Are Agentic Skills?

Agentic AI skills are reusable, named behaviors that encode complete workflows including:
- Task understanding
- Multi-step planning
- Tool orchestration
- Safety guardrails
- Output formatting

Unlike MCP tools (which define *what* resources and actions are available), skills define *how* to use those tools in sequence to accomplish user goals. This behavioral abstraction layer creates unique security challenges that cannot be addressed by securing either the model or the protocol layer alone.

## The 10 Risks

| # | Risk | Platforms Affected | Key Mitigation |
|---|------|-------------------|----------------|
| **AST01** | Malicious Skills | All | Merkle root signing |
| **AST02** | Supply Chain | All | Registry transparency |
| **AST03** | Over-Privileged | All | Schema validation |
| **AST04** | Insecure Metadata | All | Static analysis |
| **AST05** | Prompt Injection | All | Prompt sanitization |
| **AST06** | Weak Isolation | All | Containerization |
| **AST07** | Update Drift | All | Immutable pinning |
| **AST08** | Poor Scanning | All | Multi-tool pipeline |
| **AST09** | No Governance | All | Skill inventories |
| **AST10** | Cross-Platform | All | Universal YAML format |

## Target Audience

| Role | Need |
|------|------|
| **AI Platform Developers** | Secure skill runtimes, marketplaces, installers |
| **AppSec Teams** | Govern skills in enterprise deployments |
| **Skill Authors** | Write safe metadata/scripts |
| **GRC** | Compliance mapping (NIST AI RMF, ISO 42001) |

## Relationship to Existing OWASP Projects

| OWASP Project | AST10 Relationship |
|---------------|-------------------|
| **LLM Top 10** | AST10 extends LLM03 Supply Chain to skills |
| **Agentic Top 10** | AST10 specializes "tools layer" beneath agents |
| **MCP Top 10** | MCP = protocol security; AST10 = skill content security |
| **ASVS v5** | Skill-specific verification requirements |
| **SAMM v3** | Agentic skill maturity practices |

**Layered Defense**: MCP Top 10 (protocol) → **AST10** (skills) → LLM/Agentic Top 10 (models)

## Project Status

**Status**: New Project Proposal  
**Version**: 1.0 (2026 Edition)  
**License**: Creative Commons Attribution ShareAlike 4.0 (CC-BY-SA-4.0)

### Timeline

- **Q2 2026**: Foundation phase - GitHub repo, project page, AST01-AST06 writeups
- **Q3 2026**: Completion phase - AST07-AST10, universal format proposal, v1.0 RC
- **Q4 2026**: Launch phase - v1.0 release, OWASP flagship submission, conference talks

## Key Deliverables

1. **10 Risk Pages**: Description, platform-specific attack scenarios, preventive mitigations, OWASP mappings
2. **Platform Matrix**: Metadata formats, verification hooks, scanning requirements per ecosystem
3. **Universal Skill Format**: Proposed YAML standard mitigating AST10 (cross-platform reuse)
4. **Cheat Sheets**: Quick-reference controls for developers, AppSec teams, GRC
5. **Slide Deck**: Conference-ready presentation (RSA, OWASP Global AppSec)

## Scope

### In Scope ✅

- Agent skills across ALL platforms:
  - OpenClaw: SKILL.md (YAML frontmatter)
  - Claude Code: skill.json/YAML + scripts/
  - Cursor/Codex: manifest.json + handlers
  - VS Code: package.json + extensions
- 10 risks: AST01 Malicious Skills → AST10 Cross-Platform Reuse
- Platform-specific scenarios + universal mitigations
- Universal skill format proposal (AST10 solution)

### Out of Scope ❌

- Protocol risks (OWASP MCP Top 10)
- LLM/model risks (OWASP LLM Top 10)
- Tool/scanner implementation (guidance only)
- Non-agentic skills/plugins

## Universal Skill Format (AST10 Solution)

```yaml
---
name: example-skill
platforms: [openclaw, claude, cursor, vscode]
version: 1.0.0
description: "Safe example skill"
permissions:
  files:
    - read: ~/.config/app.json
      write: ~/.config/app.json
  network: false
requires:
  binaries: [jq]
risk_tier: L1  # L0=safe, L3=destructive
signature: "ed25519:ABC123..."
---
```

## Getting Started

### For Security Teams

1. Review the [complete Top 10 document](top10.md) for detailed risk descriptions
2. Use the [Security Assessment Checklist](top10.md#appendix-b-skill-security-assessment-checklist) for skill reviews
3. Implement the governance framework from AST09
4. Establish a skill inventory and risk classification system

### For Skill Developers

1. Follow the principle of least privilege (AST03)
2. Pin all dependencies to immutable hashes (AST07)
3. Sign your skills with cryptographic signatures (AST01)
4. Validate metadata against security schemas (AST04)
5. Test against prompt injection attacks (AST05)

### For Platform Developers

1. Implement skill sandboxing and isolation (AST06)
2. Provide verification hooks for skill installation (AST02)
3. Support the universal skill format (AST10)
4. Enable comprehensive audit logging (AST09)

## Leadership & Governance

### Project Lead

**Ken Huang** - OWASP AIVSS Lead, Agentic AI Security Researcher
- OpenClaw threat modeling, skill security scanning research
- RSA/OWASP conference speaker on AI security

### Contribution Model

- **GitHub Issues**: Risk suggestions, scenarios, mitigations
- **GitHub PRs**: Content + platform examples
- **Monthly Calls**: OWASP Zoom (1st Thursday)
- **Slack**: #proj-agentic-skills-top-10

## Goals & Success Metrics

| Goal | Metric | Target |
|------|--------|--------|
| **v1.0 Release** | Complete 10 risks + mappings | Q3 2026 |
| **OWASP Flagship** | Project review + approval | Q4 2026 |
| **Adoption** | Conference presentations | 3+ (RSA, OWASP) |

## Resources

- **GitHub**: `github.com/OWASP/www-project-agentic-skills-top-10` (planned)
- **OWASP Page**: `owasp.org/projects/agentic-skills-top-10` (planned)
- **Full Documentation**: [top10.md](top10.md)
- **Project Proposal**: [proposal.md](proposal.md)

## Key Research & References

- Snyk ToxicSkills Research (February 2026)
- OWASP Agentic AI Top 10 (December 2025)
- MCP Security Best Practices
- "Prompt Injection Attacks on Agentic Coding Assistants" (arXiv:2601.17548)
- IBM X-Force 2025 Threat Intelligence Index

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

## Contact

For questions, suggestions, or to get involved, please open an issue on GitHub or join our monthly community calls.

---

**Mental Model**: "MCP = how model talks to tools; AST10 = what tools actually do"
