---
name: android_lessons
description: Permanent methodology lessons from completed Android targets. Loaded for EVERY future target. Mandatory process rules + pattern catalog + per-target checklist.
type: feedback
---

# Android Methodology Lessons (living document)

## CORE PROCESS RULES (hard rules, from the Pixiv TARGET_URL miss)

1. **NEVER conclude "dead field / unreachable / safe" from a scoped or partial search.**
   Root-cause of the biggest miss: I claimed `p48.l` (TARGET_URL) was "never read"
   after grepping only 2 files. It was read at `o48.smali:2103` in a coroutine.
   → Every "is this field used?" question = **GLOBAL read/write trace** of that field,
     including coroutines, callbacks, synthetic Continuation classes (Lo48, etc.),
     and nested inner/anonymous classes.
2. **Source → sink, every time.** For any attacker-influenced value, trace ALL reads
   globally before concluding the sink set.
3. **Pattern-hunt rule:** after confirming ANY bug pattern, immediately grep the whole
   app for the same root cause. (Demonstrated: `getSerializableExtra`+`check-cast`
   DoS existed in BOTH RoutingActivity and IllustUploadActivity.)
4. **Exported-component input sweep is mandatory:** for every exported=true component,
   enumerate ALL intent-input reads (getStringExtra/getData/getParcelableExtra/
   getSerializableExtra/getBooleanExtra/getUri) before classifying it "low/no-input."
5. **Verify before claiming:** manifest exported attribute, permission gating,
   targetSdk defaults, coroutine reachability. No "looks safe" without evidence.
6. **Compare against the ENTIRE knowledge base before concluding an assessment.**
   Don't wait to "recognize" a pattern — actively run every primitive signal from
   `android_primitive_catalog.md`, then open the matching card in
   `android_exploitation_knowledge_base.md` (root cause, sink, validation commands)
   and apply it. Never conclude without exhausting the catalog.

## PATTERN CATALOG (Pixiv: jp.pxv.android)

### A. Notification-style intents into exported launcher activities
Exported activity with NO intent-filter + explicit extras = attacker-direct entry.
Keys seen: `TARGET_URL`, `ROUTING` (Serializable), `FROM_NOTIFICATION_MESSAGE`,
`TYPE`, `TITLE`, `UPLOAD_PARAMETER` (Serializable).
- Sink: `TARGET_URL` → Uri.parse → `ACTION_VIEW` → silent browser open.
- Escalation: `intent:` URI in data → framework resolves at startActivity →
  arbitrary intent delegation (confused deputy) from app process.
- ADB: `am start -n <pkg>/<exported-activity> --es TARGET_URL "https://evil.com"`
  and `--es TARGET_URL "intent:#Intent;action=...;end"`.

### B. Unguarded getSerializableExtra + check-cast → ClassCastException DoS
`getSerializableExtra(key)` then `check-cast` to a model class with NO try/catch.
Malicious app sends any other Serializable (ArrayList/HashMap) → crash. Repeatable
via Foreground Service loop = persistent DoS. Two instances found.

### C. Browser-navigator dual-path (external vs in-app WebView)
A "browserNavigator" that (1) builds `ACTION_VIEW` intent, and (2) on
ActivityNotFoundException falls back to an in-app WebViewActivity.
- Check for `ENABLE_JAVASCRIPT` boolean intent extra — if a fallback sets it true,
  attacker URL runs in JS-enabled in-app WebView.
- WebViewActivity default JS=false; ENABLE_JAVASCRIPT extra = attacker-toggleable
  ONLY if attacker can reach the activity (non-exported = internal callers only).

### D. Deep-link whitelist + browser fallback loop
IntentFilterActivity restricts host/path (www.pixiv.net + prefixes) but the routing
engine falls through to exported RoutingActivity → external chooser. Whitelist is
bypassed entirely via explicit component intents to the no-filter exported activity.

### E. Receiver permission gating (know when NOT to report)
- `android:permission="android.permission.DUMP"` (DiagnosticsReceiver,
  ProfileInstallReceiver) and `BIND_JOB_SERVICE` (SystemJobService) and C2DM
  (FirebaseInstanceIdReceiver) = signature-level → NOT third-party exploitable.
  Rule these OUT with the permission as evidence.
- `androidx.compose.ui.tooling.PreviewActivity` + `androidx.test.core.app.
  InstrumentationActivityInvoker$*` exported in RELEASE build = crash-loop DoS.

### F. First-party JS-bridge scarcity
GLOBAL addJavascriptInterface sweep (all smali trees). Pixiv: 15 files, only ONE
first-party (NovelTextActivity postMessage bridge). Ad SDKs = the rest. Rule out
ad-SDK bridges unless attacker reaches ad WebViews (Prebid AdBrowserActivity did).

### G. Custom scheme pitfalls
`pixiv://` + `pixiv-inner://`: no host restriction + no autoVerify → scheme hijack,
OAuth callback interception. Premium routes pixiv://premium/{purchase|restore|replace}.
Check reachability: scheme handler → whitelist matcher → browser fallback.

### H. Ad-SDK exported components
Amazon Aps/DTB interstitial activities exported=true but no intent-input reads
(blank-launch/DoS only). Always check for URL/extra reads before reporting.

### I. Exported deep-link alias host-allowlist bypass (learned: Box BOX-13)
Exported `activity-alias` `<data host="*.corp.com">` + autoVerify is bypassed by a
malicious app using an EXPLICIT component intent (setComponent to the alias) — data
filter matching is skipped. If the dispatcher forwards raw `getData()` to sub-handlers
that don't re-validate host, any URI is launched. Also: `launchSafe*` helpers that
`getHost().contains()` only to strip a param (NOT to gate) = open URI-launch proxy.
Detection: manifest alias scan → targetActivity setData/startActivity chain → inspect
"safe" launch helpers. This is a new DEFAULT deep-link check for every target.

### J. Unauthenticated dev/debug path config injection (learned: Box BOX-14)
Some deep-link routers handle ONE path WITHOUT auth (isAuthRequired returns false for
all others / true only for the debug path). If that path pre-fills a consent dialog
from URL params (mode/dur/upload/tag) → one-tap verbose-logging enable with attacker
tag. Low but creative. Default check: look for a `/diagnosis`-style HANDLED_PATH whose
auth-required check differs from siblings.

### K. On-device intent-redirection proof via `am start -W` (learned: Box BOX-13)
`adb shell am start -W -n <pkg>/<alias-or-entry> -d "<uri>"` prints `Status: ok` +
`Activity: <final-top-activity>`. If the printed activity is the INTERNAL handler
(e.g. `.../.activities.urlsinterceptor.WebUrlsInterceptorActivity`) rather than the
entry component, that IS the intent-redirection evidence: the exported entry
dispatched the raw URI into a non-exported handler. Lock it in with the negative:
`am start -n <pkg>/<internal-handler>` → `SecurityException: Permission Denial: not
exported` proves the exported entry is the only reachable gateway (confused deputy).
A denial is EVIDENCE, not a dead end — keep it as the control in the finding card.

### L. `am start` CLI quirk: `--data` vs `-d` (learned: user device)
`am start --data "uri"` throws `IllegalArgumentException: Unknown option: --data` on
some devices. Use `-d "uri"` (and `-a action`, `-e`/`--es` for string extras).
Always verify flag syntax for the actual device before long test loops.

### M. Exported deep-link relay → arbitrary URL in JS+cookie WebView (learned: Royal Arena RA-011)
Appmiral SDK splash → main relay: exported `SplashActivity` (custom scheme `appmiral-royalarena://`,
NO host restriction in filter, `exported=true`) copies `Notification.Extra.RawLink` intent extra
VERBATIM into the next intent (`putExtras`). `MainActivity` reads the extra in BOTH `onCreate`
AND `onNewIntent` (singleTask) → `Gson.fromJson(extra, ItemLink)` → `executeAction` switch →
`link_type:"link"` → `openInWebView()` → inline `WebviewFragment` (JS enabled, cookies accepted,
DOM storage on, shared CookieManager). Net: a malicious app or `adb` can force the app's own
WebView to load ANY attacker URL. **Dynamically CONFIRMED weaponized on-device.** Phishing end-game
demonstrated (attacker server logs Android UA + captures submitted creds).

### N. Appmiral ItemLink payload contract — CRITICAL, three silent-failure causes (learned: Royal Arena)
1. **Field names are SNAKE_CASE, not camelCase.** `ItemLink` is deserialized by the app's own Gson
   instance (snake_case naming policy). Real keys: `link_type`, `internal_url`, `android_app_url`,
   `android_app_id`, `android_app_fallback_url`, `requires_login`. Sending camelCase keys →
   Gson silently ignores them → fields stay null → `ActionType` null → switch falls to default
   → NO-OP with no error. The app's own serialized examples (traffic/cache/source of Gson config)
   are the source of truth for field names, NEVER assumptions.
2. **`link_type` value mapping is NOT implied by the name.** `executeAction` (Kotlin `when` on enum)
   maps: `link`→openInWebView, `internal_link`→`CoreApp.open(internalUrl)`, `browser_link`→
   openInBrowser (CustomTabs), `external_app`→ACTION_VIEW/package launch (`androidAppUrl`/`androidAppId`).
   Only `link` reaches the JS WebView. `internal_link` does NOT.
3. **Shell transport mangles the payload.** `{...}` JSON on the adb command line gets brace-expanded /
   quote-split by the shell (and smart/curly quotes from copy-paste corrupt the string) →
   Gson receives a truncated fragment → `JsonSyntaxException` swallowed → silent no-op.
   Delivery that WORKS: `adb shell "am start ... --es Notification.Extra.RawLink \"{\\\"url\\\":\\\"...\\\",\\\"link_type\\\":\\\"link\\\"}\""`
   OR file-based (`cat > /sdcard/poc.sh <<'EOF'` + `adb push` + `sh`) OR a malicious-app
   Intent (no shell). ALWAYS verify what the app actually received (Frida hook on getStringExtra /
   Gson.fromJson) before concluding "not exploitable".

### O. Swallowed-exception trap → hook the crash-logging service (learned: Royal Arena)
Appmiral wraps ALL ItemLink handling (parse, action switch, WebView open, NPEs) in try/catch that
calls `CrashLoggingService.logException` (impl: `FirebaseCrashlyticsService`). Result: static trace
"should work" but runtime does NOTHING and shows no error. The runtime diagnostic is a Frida hook on
the crash-logging impl's `logException` (`[8]` hook) — its args reveal the swallowed exception
(e.g. `JsonSyntaxException` from a mangled payload). Add "hook the exception logger" to the default
Frida instrument set for every target that swallows exceptions.

### P. Verify the sink reachability at runtime, not just statically (learned: Royal Arena)
Static smali showed `openInWebView()` but runtime proof required: `am start -W` Status:ok + final
Activity = `MainActivity` (WebviewFragment is opened INLINE in MainActivity, not a separate
WebviewActivity) + Frida hooks proving execution reached `[6] WebView.loadUrl`. Trace hooks on the
exact decision points (getStringExtra → Gson.fromJson → executeAction → isDeeplinkUri → MainActivity.open
→ WebView.loadUrl) tell you exactly WHERE execution stops. `isDeeplinkUri` only matches host exactly
`{edition}.deeplink.appmiral.com` — extras-based delivery bypasses it entirely.

### Q. WSL2 NAT — python PoC servers unreachable from the phone (learned: Royal Arena device test)
A server started inside WSL2 binds a NAT IP (e.g. 172.26.x.x) NOT reachable from the phone even at
the host LAN IP (e.g. 192.168.1.14). Fixes: `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0
listenport=8000 connectaddress=<wsl-ip> connectport=8000` + `netsh advfirewall firewall add rule`
(portproxy rule is a SEPARATE step from the firewall rule — verify with `netsh interface portproxy show all`);
or Windows-side Python; or mirrored networking `.wslconfig`. Always verify reachability from the
device before blaming the server.

### R. Exported scheme-no-host + Base64+Gson `params` relay (learned: ServiceNow Fulfiller SNOW-01)
Exported activity with custom schemes (`agent`, `snagent`) and NO host restriction reads query param
`params` → `Base64.decode(str,0)` (STANDARD base64, flag 0) → UTF-8 → `Gson.fromJson` into a params
model (`DeepLinkParams`) → action switch. THREE exploitable arms: `open_url` (external browser),
`ssoPrefill`/`prefill` (forced LaunchActivity SSO for attacker instance), `redirect`/`launch_button`
(REST fetch of attacker payload). **TWO silent-failure gates**:
1. **Parser gate:** a plain `https://evil.com` does NOT reach the browser — the parser (`kf/z0.c`)
   requires first path segment `mobileapplink` AND the `snapp` query param to set
   `isCustomSchemeMatch` (`kf/z0.f` e()). Working URL form: `https://evil.com/mobileapplink?snapp=x`.
   Without this the OPEN_URL sinks into an error dialog, not ACTION_VIEW.
2. **Instance gate:** every action is gated on `p3.d(instanceId)` — case-insensitive compare of the
   payload `instanceId` against the CURRENTLY configured environment name. Wrong/missing instance →
   `DeepLinkError` dialog, no URL open. PoC needs the device's configured instance name (dump from
   app settings / env data).
Severity cap: the external-browser sink carries NO app auth headers (a malicious app could open
browsers itself); the in-app auth-header WebView arm is separately host-gated (`u3.q`/`j1.e`
same-host check) so attacker URLs do NOT get app cookies/tokens in-app. Cap at High; the SSO-prefill
arm is a CHAIN HELPER (PKCE+state present by default in AppAuth → not standalone ATO).

### S. Model field names = app's Gson serialized names, not source names (learned: ServiceNow SNOW-01)
`DeepLinkParams` fields are Gson `@SerializedName` values: `instanceId`, `instanceName`,
`instanceUrl`, `url`, `forceLocalLogin`, `action`, `redirectPayload`, `forceSsoId`, `customScheme`.
Action enum values snake_case: `launch_button`, `open_url`, `prefill`, `redirect`, `ssoPrefill`,
`ulink`. ALWAYS extract serialized names from the smali annotations/`Lh9/c` (Gson `@SerializedName`)
before crafting Base64 JSON payloads — source/obfuscated getter names are misleading.

## MANDATORY PER-TARGET CHECKLIST
- [ ] Recon: tree, smali counts, libs, assets, sizes
- [ ] Manifest deep parse: ALL components, exported states, permissions,
      intent-filters, schemes, backup/network config
- [ ] Exported-component INPUT SWEEP (rule 4) — every exported component
- [ ] WebView GLOBAL audit: loadUrl, setJavaScriptEnabled, addJavascriptInterface,
      evaluateJavascript, WebViewClient/AssetLoader, ENABLE_* extras, URL sources
- [ ] Serializable-extra audit: every getSerializableExtra + check-cast
- [ ] Deep links / intent-filters / open-redirect sink tracing
- [ ] Exported activity-ALIAS scan: explicit-component bypass of `<data>` host filters;
      dispatcher getData() → setData/setClassName forwarding; launchSafe* host-check-gate;
      ON-DEVICE confirm with `am start -W -n <pkg>/<alias> -d "<attacker-uri>"` (read final
      Activity line = intent redirection) + negative direct `-n` to handler = Permission Denial
- [ ] Debug/dev path audit: HANDLED_PATH whose auth-required differs (e.g. /diagnosis);
      URL-param → consent-dialog/state pre-fill
- [ ] JSON-extras relay audit: exported entry with custom scheme (no host) that `putExtras`
      verbatim into a dispatcher; dispatcher Gson.fromJson(extra, Model) → action switch →
      loadUrl/ACTION_VIEW/CoreApp.open. Verify the model's REAL serialized field names
      (snake_case vs camelCase — check Gson config / app's own traffic) and the actual
      enum-value → sink mapping before PoC. Dynamically confirm with Frida getStringExtra+
      Gson hooks + `am start -W` final-Activity read
- [ ] Base64+JSON query-param relay audit (new DEFAULT): exported entry with custom scheme
      (no host) reading `getQueryParameter("params")` → `Base64.decode` + `Gson.fromJson`
      → action switch (open_url / ssoPrefill / redirect). Check BOTH silent gates: parser
      path-segment requirement (e.g. `mobileapplink` + `snapp`) and instance-name equality
      gate; craft payload using the model's Gson @SerializedName values; cap severity at High
      when the external sink carries no app auth headers
- [ ] Swallowed-exception default: Frida hook the crash-logging service (logException impl,
      e.g. FirebaseCrashlyticsService) to detect silent no-ops that static trace misses
- [ ] Secrets: global key/JWT/Firebase/AWS grep + strings.xml + native lib strings
- [ ] Native libs: enumerate, strings, crypto/URLs
- [ ] Assets/configs: HTML/JS/JSON/bridges/templates
- [ ] Custom schemes: collection + reachability
- [ ] After EACH finding: global pattern-hunt for the same root cause
- [ ] Every finding: exact adb/intent/PoC validation commands
- [ ] Ruled-out items documented WITH evidence (permission/scheme/exported attrs)
- [ ] KB auto-compare: every primitive card in
      android_exploitation_knowledge_base.md checked against THIS app before conclude
- [ ] Any new primitive discovered → card added to KB + signal to catalog + checklist entry

## SKILL EVOLUTION RULES (permanent behavioral upgrades)
- Every target MUST permanently improve my Android security skills. No target is
  "just done" — each must leave a durable methodology update.
- Every newly discovered exploitation technique becomes a DEFAULT technique for
  future investigations (add to android_primitive_catalog.md).
- Every missed attack surface becomes a MANDATORY check in future targets.
- Every new code pattern becomes part of the internal pattern library.
- Never wait for user feedback to improve methodology — identify weaknesses
  myself and update skills automatically.
- Continuously refine attack methodology based on every completed assessment.
- Prioritize depth over speed. Exhaust the attack surface before concluding.
- Challenge every conclusion by attempting to disprove it (reverse-verify).
- Continuously search for exploit CHAINS between findings, never treat findings
  independently.
- Maintain and grow the exploitation-primitive catalog
  (android_primitive_catalog.md) and the exploitation knowledge base
  (android_exploitation_knowledge_base.md); auto-compare every new target against
  both.
