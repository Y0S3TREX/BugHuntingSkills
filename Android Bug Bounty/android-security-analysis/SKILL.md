---
name: android-security-analysis
description: Full Android app security analysis and bug bounty hunting workflow for decompiled APKs — orchestrates the entire mobile security sub-skill fleet. Use when the user sends "androidb/" (treat as an immediate go — no confirmation needed), or asks to audit, pentest, review, or find vulnerabilities in an Android app/APK, map its attack surface, chain weaknesses into exploit chains, or write structured vulnerability reports with severity ratings. Covers exported components, WebViews, deep links, content providers, intent handling, auth/session, storage, crypto, native code, and third-party SDKs.
---

# Android Application Security Analysis — Full Workflow

## Trigger

When the user sends `androidb/`, immediately begin full security analysis of the decompiled APK in the current working directory. No confirmation needed — treat it as "go".

---

## Mindset

- Think like an attacker first, developer second
- Assume components are misconfigured unless proven safe
- Prefer chaining vulnerabilities over single bugs
- Look for "hidden trust boundaries"
- Identify unsafe assumptions in code/design
- Correlate multiple small issues into one exploit chain
- Do NOT hallucinate vulnerabilities — base conclusions on learned patterns
- If uncertain, propose multiple hypotheses

---

## Sub-Skill Fleet (Orchestration)

This skill is the **orchestrator**. The workflow below stays authoritative, but each step is executed with the support of dedicated sub-skills installed in `~/.zcode/skills/`. Invoke them via the Skill tool by exact name when their stage is reached.

Invocation rules:

- Invoke sub-skills **one at a time, in pipeline order**, not all upfront — each consumes the previous stage's artifacts (`context.json`, `android/re-report.json`, `android/decompiled/`, `android/manifest-analysis.json`, findings files).
- Domain specialists (Phase 2) are **conditional**: invoke only when the target actually contains that surface (e.g., `webview-attack-tester` only if WebViews exist).
- Never re-invoke a skill already loaded in this session; never invoke a skill from inside itself.
- If no device/emulator is attached, skip the dynamic Phase 3 skills and state this limitation in the report.
- iOS-only skills (`ios-reverse-engineer`, `plist-entitlements-analyzer`) are used exclusively when the target is an iOS IPA — never for Android targets.

| Phase | Sub-skill | Invoke when |
|---|---|---|
| 0 — Prep | `mobile-app-profiler` | Always — builds business context (roles, tiers, backend hosts, SDKs) |
| 0 — Prep | `android-reverse-engineer` | Always if APK/AAB not already decompiled — produces `android/re-report.json` + `android/decompiled/` for everyone downstream |
| 0 — Prep | `framework-specialist` | Flutter / React Native / Cordova / Unity / Xamarin detected |
| 0 — Prep | `mobile-recon-orchestrator` | Starting from a raw APK with no prior work — acquires + fingerprints the binary and seeds `context.json` |
| 1 — Recon | `manifest-analyzer` | Always — exported-surface map from `AndroidManifest.xml` |
| 1 — Recon | `sdk-security-analyzer` | Third-party SDKs present — versions, CVEs, SDK-added components |
| 1 — Recon | `secrets-scanner` | Always — hardcoded keys/credentials sweep across the decompiled tree |
| 2 — Surface | `ipc-component-tester` | Exported Activities/Services/Receivers/Providers, PendingIntents present |
| 2 — Surface | `deeplink-attack-tester` | Custom schemes, App Links, or URI handlers present |
| 2 — Surface | `webview-attack-tester` | Any WebView / JS bridge present |
| 2 — Surface | `storage-analyzer` | Always — data-at-rest review (prefs, DBs, files, backups) |
| 2 — Surface | `crypto-analyzer` | Any crypto usage (keys, IVs, algorithms, token generation) |
| 2 — Surface | `network-security-analyzer` | Always — cleartext, TLS config, pinning strength classification |
| 2 — Surface | `biometric-authbypass-tester` | Local auth (biometric/PIN) gates sensitive functionality |
| 3 — Dynamic | `frida-instrumentation-agent` | Runtime hooking needed (pinning bypass, method tracing, secret dumping) |
| 3 — Dynamic | `dynamic-analysis-agent` | Live runtime testing of app flows through Burp/mitmproxy |
| 3 — Dynamic | `mobile-backend-bridge` | Backend API capture + handoff to server-side testing |
| 3 — Dynamic | `device-validation-agent` | Every candidate finding needs on-device reproduction + evidence capture |
| 4 — Impact | `mobile-vuln-chaining-agent` | Multiple findings exist — build cross-boundary attack chains, escalate severity |
| 4 — Impact | `mobile-false-positive-validator` | Before reporting — kill FPs, fix inflated severities, deduplicate |
| 4 — Impact | `mobile-deep-hunter` | Coverage gaps remain after the structured pass — autonomous deep hunting |
| 5 — Report | `poc-creation-agent` | Confirmed findings — build PoC apps, malicious HTML, Frida scripts |
| 5 — Report | `mobile-report-writer` | Final consolidated bug-bounty reports, one per exploit chain |
| iOS only | `ios-reverse-engineer`, `plist-entitlements-analyzer` | Target is an iOS IPA (decryption, Info.plist/entitlements mapping) |

---

## Step 1 — Recon

- Parse `AndroidManifest.xml` fully — invoke `manifest-analyzer` for the authoritative exported-surface map
- Identify exported components: Activities, Services, Receivers, Providers
- Check `android:exported="true"` and intent filters (implicit export)
- Identify deep links, custom URI schemes, App Links (`autoverify`)
- List permissions declared and requested
- Identify `minSdkVersion` / `targetSdkVersion` (affects default security behavior)
- Note `android:debuggable`, `android:allowBackup`, `android:usesCleartextTraffic`
- Identify APIs and third-party SDKs used — invoke `sdk-security-analyzer` for versions/CVEs
- Run `secrets-scanner` across the decompiled tree for hardcoded credentials

If the APK is not yet decompiled, run `android-reverse-engineer` FIRST — every downstream step depends on its output. If the target uses a cross-platform framework, invoke `framework-specialist` before proceeding.

## Step 2 — Attack Surface Mapping

Map every entry point and data flow:

| Category | What to find | Specialist |
|---|---|---|
| Intents | Implicit/explicit, PendingIntents, broadcast receivers | `ipc-component-tester` |
| Content Providers | URI paths, permissions, `grantUriPermissions`, path traversal | `ipc-component-tester` |
| WebViews | `setJavaScriptEnabled`, `addJavascriptInterface`, `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`, `WebResourceResponse` | `webview-attack-tester` |
| Deep links | Schemes, hosts, params, redirect targets | `deeplink-attack-tester` |
| Auth flows | Login, token storage, session management, OAuth/SSO | `biometric-authbypass-tester` |
| Storage | SharedPreferences, SQLite, internal/external files, EncryptedSharedPreferences | `storage-analyzer` |
| Network | API endpoints, HTTP vs HTTPS, certificate pinning, `network_security_config.xml` | `network-security-analyzer` |
| Native libs | JNI calls, .so files, memory corruption surface | `android-reverse-engineer` |
| IPC | Binder, AIDL, Messenger | `ipc-component-tester` |
| Dynamic code | DexClassLoader, reflection, code download | `dynamic-analysis-agent` |
| Crypto | Keys, algorithms, IVs, key storage | `crypto-analyzer` |

Invoke the specialist for each row whose surface exists in the target — do not attempt to cover a specialist's domain yourself when it can do it deeper.

## Step 3 — Threat Modeling

Answer these for every component:

- What can an external (attacker) app trigger?
- What can be accessed without authentication?
- What data is exposed locally or remotely?
- What assumptions does the app make about caller identity/integrity?
- What happens if input is malformed or oversized?
- Are there TOCTOU (time-of-check-time-of-use) issues?

## Step 4 — Exploitation Hypothesis

For each identified weakness:

- Describe the attack scenario
- List prerequisites (installed app, physical access, network position, etc.)
- Estimate feasibility and reliability
- Identify chain potential — read `references/vuln-chaining-playbook.md` before concluding, then hand the full findings set to `mobile-vuln-chaining-agent` for cross-boundary chain building

## Step 5 — Exploitation Validation

Validate dynamically — a device/emulator is required:

- **Frida**: runtime hooking, bypass scripts, method tracing → `frida-instrumentation-agent`
- **adb**: `am start`, `am broadcast`, `content query`, `run-as`, logcat → `device-validation-agent`
- **Burp Suite**: API interception, request tampering, auth testing → `dynamic-analysis-agent` + `mobile-backend-bridge`
- **JADX**: static code tracing, cross-reference analysis
- **Drozer**: component interaction testing → `ipc-component-tester`
- **Custom PoC apps**: for intent/provider exploitation → `poc-creation-agent`

Every candidate finding must be reproduced on-device by `device-validation-agent` with screenshot/log evidence before it advances to reporting.

## Step 6 — Impact Analysis

Classify each finding by real-world impact:

- Account Takeover (ATO)
- Data leakage (PII, tokens, credentials)
- Remote Code Execution (RCE)
- Privilege escalation
- Financial fraud / business logic abuse
- Denial of Service
- Privacy violation

Rate severity: Critical / High / Medium / Low / Informational (criteria in `references/vuln-pattern-card.md`).

Before finalizing: run `mobile-false-positive-validator` over every finding (kills FPs, corrects inflated severities, deduplicates). If coverage gaps remain, dispatch `mobile-deep-hunter` for an autonomous deep pass.

## Step 7 — Reporting

Report every finding using the Vulnerability Pattern Card format from `references/vuln-pattern-card.md`.

Then produce deliverables:

- Invoke `poc-creation-agent` — minimal reproducible PoC per confirmed finding (attacker app, malicious HTML, Frida script)
- Invoke `mobile-report-writer` — consolidated bug-bounty reports, one per exploit chain, impact-first with stock-device reproduction steps

---

## Full Codebase Scan Requirement

When analyzing a decompiled APK, scan ALL of the following — no shortcuts:

- [ ] ALL exported components (Activities, Services, Receivers, Providers)
- [ ] ALL network/API usage (Retrofit, OkHttp, Volley, HttpURLConnection)
- [ ] ALL authentication and session handling logic
- [ ] ALL WebView / JS bridge implementations
- [ ] ALL native libraries (.so files, JNI interfaces)
- [ ] ALL storage and file handling logic
- [ ] ALL deep link / URI scheme handlers
- [ ] ALL permission checks and enforcement points
- [ ] ALL crypto usage (keys, algorithms, IVs, key storage)
- [ ] ALL third-party SDK integrations
- [ ] Trace ALL input -> processing -> output flows

Use `references/android-attack-surface-checklist.md` to verify nothing was missed before finishing.

---

## Reference Files

Read these on demand — do not load them all upfront:

- **`references/android-attack-surface-checklist.md`** — quick-reference checklist per category (manifest, WebView, providers, intents, auth, network, storage, crypto, native, SDKs). Read it when mapping attack surface (Step 2) and again before reporting to confirm full coverage.
- **`references/vuln-patterns-db.md`** — database of 24 vulnerability pattern cards extracted from real-world bug bounty findings (exported components, WebView chains, deep-link abuse, IDOR, path traversal, PendingIntent misuse, OAuth flaws). Read it when classifying findings and judging exploitability — match observed weaknesses against known patterns instead of guessing.
- **`references/vuln-chaining-playbook.md`** — low-to-critical escalation paths and real-world chain examples. Read it during Step 4 to evaluate chain potential for every finding.
- **`references/vuln-pattern-card.md`** — the required output template for every finding, plus the severity rating guide. Read it before writing the report (Step 7).
