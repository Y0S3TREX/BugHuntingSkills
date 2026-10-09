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

## Step 1 — Recon

- Parse `AndroidManifest.xml` fully
- Identify exported components: Activities, Services, Receivers, Providers
- Check `android:exported="true"` and intent filters (implicit export)
- Identify deep links, custom URI schemes, App Links (`autoverify`)
- List permissions declared and requested
- Identify `minSdkVersion` / `targetSdkVersion` (affects default security behavior)
- Note `android:debuggable`, `android:allowBackup`, `android:usesCleartextTraffic`
- Identify APIs and third-party SDKs used

## Step 2 — Attack Surface Mapping

Map every entry point and data flow:

| Category | What to find |
|---|---|
| Intents | Implicit/explicit, PendingIntents, broadcast receivers |
| Content Providers | URI paths, permissions, `grantUriPermissions`, path traversal |
| WebViews | `setJavaScriptEnabled`, `addJavascriptInterface`, `setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`, `WebResourceResponse` |
| Auth flows | Login, token storage, session management, OAuth/SSO |
| Storage | SharedPreferences, SQLite, internal/external files, EncryptedSharedPreferences |
| Network | API endpoints, HTTP vs HTTPS, certificate pinning, `network_security_config.xml` |
| Native libs | JNI calls, .so files, memory corruption surface |
| IPC | Binder, AIDL, Messenger |
| Dynamic code | DexClassLoader, reflection, code download |

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
- Identify chain potential (see Chaining Playbook)

## Step 5 — Exploitation Validation

Suggest concrete testing steps using:

- **Frida**: runtime hooking, bypass scripts, method tracing
- **adb**: `am start`, `am broadcast`, `content query`, `run-as`, logcat
- **Burp Suite**: API interception, request tampering, auth testing
- **JADX**: static code tracing, cross-reference analysis
- **Drozer**: component interaction testing
- **Custom PoC apps**: for intent/provider exploitation

## Step 6 — Impact Analysis

Classify each finding by real-world impact:

- Account Takeover (ATO)
- Data leakage (PII, tokens, credentials)
- Remote Code Execution (RCE)
- Privilege escalation
- Financial fraud / business logic abuse
- Denial of Service
- Privacy violation

Rate severity: Critical / High / Medium / Low / Informational

## Step 7 — Reporting

Use the Vulnerability Pattern Card format (see `vuln-pattern-card.md`).

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
