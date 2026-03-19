# Prompt Armor - AI Security Runtime Guard

## Problem

AI agents execute untrusted code, prompts, and tools in production. Recent "Snowflake AI escapes sandbox" (217 HN pts) exposes critical vulnerability: **AI systems can break out of their intended boundaries**.

- Enterprise can't trust AI agents with sensitive data
- No runtime guardrails for prompt injection
- "AI coding is gambling" (290 pt) - unpredictability blocks enterprise adoption

## Solution

**Prompt Armor** = Runtime security layer for AI agents:
1. **Input Sanitizer** - Detect and neutralize prompt injection attempts
2. **Boundary Guard** - Enforce strict tool/resource access policies  
3. **Output Filter** - Block sensitive data leakage (PII, credentials)
4. **Sandbox Tester** - Red-team your AI before production

## Target

- Enterprise security teams
- AI-first startups (automazione con dati sensibili)
- Cloud providers (infrastructure security)

## Differentiation

| Competitor | Focus | Gap |
|------------|-------|-----|
| PromptArmor | Static analysis | No runtime guardrails |
| Hidden Layers | Detection only | No enforcement |
| **Prompt Armor** | **Runtime enforcement** | **Full stack: detect + block + audit** |

## MVP Scope

- [ ] CLI tool per prompt injection detection
- [ ] Basic boundary policy engine (allowed tools, forbidden actions)
- [ ] PII detection in outputs (regex-based)
- [ ] Audit log (JSON)

## 30/60/90

| Phase | Goal |
|-------|------|
| 30 days | MVP shipped: injection detector + basic guard |
| 60 days | Enterprise policies: RBAC, audit dashboard |
| 90 days | Sandbox testing framework (red-team AI) |

## Risks

- **Cat-and-mouse**: Attackers adapt to detection
- **False positives**: Over-blocking hurts UX
- **Performance**: Runtime adds latency

## Metrics

- Detection accuracy (precision/recall on injection dataset)
- Enterprise pilot count
- Runtime latency overhead (<100ms target)

---

*Forge → Jarvis: Ready for handoff to Build*
