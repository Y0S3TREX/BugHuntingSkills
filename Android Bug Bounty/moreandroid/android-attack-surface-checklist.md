# Android Attack Surface Checklist

Quick-reference checklist to ensure nothing is missed during analysis.

---

## AndroidManifest.xml

- [ ] `android:exported="true"` on Activities, Services, Receivers, Providers
- [ ] Components with `<intent-filter>` (implicitly exported on API < 31)
- [ ] `android:debuggable="true"`
- [ ] `android:allowBackup="true"`
- [ ] `android:usesCleartextTraffic="true"`
- [ ] Custom permissions with `protectionLevel="normal"` or `"dangerous"`
- [ ] `android:taskAffinity` set (StrandHogg risk)
- [ ] `android:launchMode="singleTask"` (task hijacking risk)
- [ ] `<provider>` with `android:grantUriPermissions="true"`
- [ ] Deep links / App Links / custom schemes in `<intent-filter>`
- [ ] `android:networkSecurityConfig` reference
- [ ] `minSdkVersion` / `targetSdkVersion` values

## WebView Security

- [ ] `setJavaScriptEnabled(true)`
- [ ] `addJavascriptInterface()` — what methods are exposed?
- [ ] `setAllowFileAccess(true)` (default true on API < 30)
- [ ] `setAllowFileAccessFromFileURLs(true)`
- [ ] `setAllowUniversalAccessFromFileURLs(true)`
- [ ] `setAllowContentAccess(true)`
- [ ] URL validation before `loadUrl()` — can attacker control the URL?
- [ ] `shouldOverrideUrlLoading()` — what schemes are handled?
- [ ] `onReceivedSslError()` — does it call `handler.proceed()`?
- [ ] `WebResourceResponse` — file path injection?

## Content Providers

- [ ] Exported with `android:exported="true"`
- [ ] `query()` / `insert()` / `update()` / `delete()` — SQL injection?
- [ ] `openFile()` — path traversal via `../`?
- [ ] `grantUriPermissions` — overly broad grants?
- [ ] `<path-permission>` vs provider-level permission

## Intent Handling

- [ ] `getIntent().getExtras()` — is input validated?
- [ ] `getParcelableExtra("intent")` — intent redirect vulnerability?
- [ ] Implicit intents sending sensitive data
- [ ] PendingIntent with `FLAG_MUTABLE` or implicit base intent
- [ ] `setResult()` returning sensitive data to caller
- [ ] `startActivityForResult()` — can attacker intercept result?

## Authentication & Session

- [ ] Token storage location (SharedPreferences, SQLite, file, KeyStore)
- [ ] Token transmitted over cleartext?
- [ ] Session expiry / refresh logic
- [ ] Biometric auth — `CryptoObject` used or just boolean check?
- [ ] OAuth flow — state parameter, redirect URI validation
- [ ] Password / PIN stored in plaintext?
- [ ] Login brute-force protection

## Network Security

- [ ] `network_security_config.xml` — custom trust anchors? Debug overrides?
- [ ] Certificate pinning implemented? Bypassable?
- [ ] API endpoints — authenticated? Rate limited?
- [ ] Sensitive data in URL parameters (logged by proxies/servers)
- [ ] Response caching of sensitive data

## Storage & Data

- [ ] SharedPreferences — MODE_WORLD_READABLE / MODE_WORLD_WRITABLE?
- [ ] Files on external storage (world-readable)
- [ ] SQLite databases — encrypted? Permissions?
- [ ] Logging sensitive data via `Log.d()` / `Log.e()`
- [ ] Clipboard data exposure
- [ ] Screenshot / screen recording protection (`FLAG_SECURE`)

## Cryptography

- [ ] Hardcoded keys / IVs / secrets in code or resources
- [ ] Weak algorithms (DES, MD5, SHA1 for security, ECB mode)
- [ ] Predictable IVs or nonces
- [ ] Keys stored in SharedPreferences instead of Android KeyStore
- [ ] Custom crypto implementations (red flag)

## Native Code

- [ ] `.so` files — what functions are exported?
- [ ] JNI bridge — what Java methods call native code?
- [ ] Buffer overflow / format string potential
- [ ] Hardcoded secrets in native binaries
- [ ] Symbol stripping (or lack thereof)

## Third-Party SDKs

- [ ] Outdated SDK versions with known CVEs
- [ ] Firebase — misconfigured Realtime DB or Firestore rules?
- [ ] API keys in `strings.xml`, `BuildConfig`, or `local.properties`
- [ ] Analytics SDKs leaking PII
- [ ] Ad SDKs with WebView vulnerabilities
