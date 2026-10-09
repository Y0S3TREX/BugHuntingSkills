# Vulnerability Pattern Card Template

Use this structured format for every finding.

---

## [VULN-ID] Vulnerability Title

**Category:** (e.g., Exported Component, WebView, Content Provider, Auth Bypass, etc.)
**Affected Component:** (e.g., `com.app.ui.DeepLinkActivity`)
**Severity:** Critical / High / Medium / Low / Informational
**CVSS (estimated):** X.X

### Root Cause

One-paragraph description of why this vulnerability exists.

### Attack Prerequisites

- What the attacker needs (installed app, network position, user interaction, etc.)
- Required permissions or conditions

### Exploitation Flow

1. Step-by-step attack procedure
2. Include exact intents, URIs, commands, or code
3. Each step should be reproducible

### Proof of Concept

```
# adb command, Frida script, or PoC app code
adb shell am start -n com.app/.InternalActivity --es "token" "stolen"
```

### Impact

- What an attacker gains (ATO, data leak, RCE, etc.)
- Affected user population
- Business impact

### Chain Potential

- What other issues can this combine with?
- Link to related findings: [VULN-ID]
- Full chain impact if combined

### Detection Strategy

- How a defender could detect exploitation
- Log indicators, anomalous behavior

### Fix Recommendation

- Specific code changes needed
- Android best practice reference

### Real-World References

- Links to similar bugs in public disclosures
- CVEs, blog posts, HackerOne reports

---

## Severity Rating Guide

| Severity | Criteria |
|---|---|
| Critical | RCE, full ATO, mass data breach, no user interaction |
| High | ATO with interaction, significant data leak, privilege escalation |
| Medium | Limited data exposure, requires chaining, partial bypass |
| Low | Information disclosure, minor privacy issue, limited impact |
| Informational | Best practice violation, no direct exploit path |
