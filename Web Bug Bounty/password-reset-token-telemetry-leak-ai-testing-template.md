# Bug Bounty Testing Template: Password Reset Token Leakage to Telemetry or RUM

## Universal Test Profile

- Report name: Password Reset Token Leakage to Telemetry or RUM
- Primary weakness: live account-recovery token appears in URL and is captured by third-party telemetry
- Bug class: sensitive token exposure / insecure reset flow / analytics data leakage
- Common sinks: Datadog RUM, Segment, Google Analytics, Mixpanel, Amplitude, FullStory, LogRocket, Sentry, Intercom, Hotjar, New Relic Browser, OpenTelemetry browser collectors, custom analytics, CDN logs, reverse proxy logs
- Common sources:
  - `/password-reset?<token>`
  - `/reset-password?token=<token>`
  - `/forgot-password/<token>`
  - `/invite?token=<token>`
  - `/verify-email?token=<token>`
  - `/magic-login?token=<token>`
  - `/oauth/callback?code=<code>`
- Required attacker capability: read access to telemetry, logs, analytics, RUM, replay tooling, browser session recordings, or leaked telemetry API credentials
- Highest-risk impact: account takeover or unauthorized account recovery if a live token and account identity are captured together

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for live password reset or account recovery token leakage into telemetry, RUM, analytics, logs, browser monitoring, or session replay tools.

Rules:
- Work only on assets and accounts explicitly authorized by the bug bounty program.
- Use only accounts controlled by the tester.
- Do not use or access third-party user reset links.
- Do not attempt to access the target company's telemetry account.
- Do not exfiltrate real secrets.
- Use dummy URL markers for global capture tests.
- Redact reset tokens in evidence.
- Do not complete an account takeover except against your own account.

Goal:
Determine whether a live reset, invite, verification, magic-login, or authorization token appears in a URL and is automatically captured by browser telemetry or logging before the token is consumed.

Workflow:
1. Identify account recovery, invite, email verification, magic-login, and OAuth callback flows.
2. Request a reset or invite link for a tester-controlled account.
3. Open the link but do not submit the reset form yet.
4. Inspect the URL shape and identify whether the secret is in query string, path, fragment, or referrer.
5. Enumerate loaded telemetry SDKs from script tags, bundles, globals, network requests, and browser devtools.
6. Check whether each SDK captures full URL, query string, referrer, route changes, page context, session ID, user ID, email, account handle, or anonymous ID.
7. Check each SDK configuration for redaction hooks, deny lists, before-send callbacks, source middleware, privacy settings, masking rules, and sample rate.
8. Observe outgoing telemetry requests while the live token remains in the URL.
9. Prove whether the SDK's internal state or outgoing payload contains the token.
10. Complete the reset on the tester account and check whether the same telemetry session later records account identity.
11. Test global capture safely by pushing a dummy marker into the URL on a non-sensitive route and confirming whether telemetry captures it.
12. Record what can and cannot be proven from the client side, and provide a server-side query the program can run to confirm stored events.

Stop condition:
- Stop when a live token is observed in telemetry SDK state or outbound telemetry payloads, or when all loaded telemetry sinks are proven to redact it.

Output:
- A concise vulnerability report with affected flow, token location, telemetry sink, redaction configuration, sample rate, timing, account correlation, impact, proof, limitations, and remediation.
```

## Vulnerability Summary

Password reset and account recovery tokens are bearer credentials. If a reset link places the token in the browser URL, any browser-side monitoring library that captures full URLs can record that live token before the user submits the reset form.

This is more severe when the same telemetry session also records the account identity, user ID, email, username, account handle, workspace path, or authenticated route after the reset completes. In that case, telemetry readers may have both:

- the live recovery token
- the account the token unlocks

The root issue may be the reset-flow design, telemetry configuration, or both.

## Security Impact

- Live reset tokens may be stored in third-party telemetry systems.
- Telemetry readers may reset accounts without knowing the old password.
- Tokens may remain valid if users open the link but abandon the reset flow.
- RUM/session replay/analytics platforms have separate access control, retention, export, API keys, and integrations outside the application's authorization model.
- If URL capture is global, other future secrets in URLs may be captured too.
- Similar risks apply to invite tokens, verification tokens, magic links, OAuth codes, SAML artifacts, one-time login links, file share tokens, and unsubscribe/admin tokens.

## Preconditions

- Testing is authorized.
- The tester controls the account receiving the reset/invite link.
- The token appears in a browser-visible URL before being consumed.
- A telemetry, RUM, analytics, logging, session replay, or monitoring library is active on the token-bearing page.
- The SDK captures current URL, referrer, route context, or browser history state without adequate redaction.

## Token Locations To Check

```text
https://<host>/password-reset?<token>
https://<host>/password-reset?token=<token>
https://<host>/reset-password/<token>
https://<host>/reset-password#token=<token>
https://<host>/invite?invite_token=<token>
https://<host>/verify-email?confirmation_token=<token>
https://<host>/magic-login?login_token=<token>
https://<host>/oauth/callback?code=<authorization-code>&state=<state>
```

Record whether the secret appears in:

- `location.href`
- `location.search`
- `location.pathname`
- `location.hash`
- document referrer
- SPA route state
- SDK view/page context
- outbound telemetry request body
- outbound telemetry request URL

## Telemetry Sink Discovery

Check for common browser globals:

```javascript
[
  "DD_RUM",
  "analytics",
  "dataLayer",
  "gtag",
  "mixpanel",
  "amplitude",
  "FS",
  "LogRocket",
  "Sentry",
  "Intercom",
  "newrelic",
  "hj",
  "heap"
].filter((name) => window[name])
```

Check script and network indicators:

```javascript
[...document.scripts].map((script) => script.src).filter(Boolean)
```

Look for requests to telemetry and monitoring hosts:

```text
datadoghq.com
segment.io
google-analytics.com
googletagmanager.com
mixpanel.com
amplitude.com
fullstory.com
logrocket.com
sentry.io
intercom.io
hotjar.com
nr-data.net
newrelic.com
heap.io
```

## Client-Side Verification Methodology

### Phase 1: Confirm The Token Is Live Before Submission

1. Request reset for tester-controlled account.
2. Open reset link.
3. Do not submit the form.
4. Confirm the reset form renders normally.
5. Optionally wait a short measured time and submit against the tester account to confirm the token was valid during observation.
6. Do not reuse or expose the token after completion.

### Phase 2: Inspect SDK State

For Datadog RUM:

```javascript
const token = "<redacted-token-or-unique-prefix>";
window.DD_RUM?.getInternalContext?.()?.view?.url?.includes(token);
window.DD_RUM?.getInitConfiguration?.();
typeof window.DD_RUM?.getInitConfiguration?.().beforeSend;
```

For Segment:

```javascript
window.analytics?.user?.();
window.analytics?.page;
```

For generic SDKs:

```javascript
location.href.includes("<token-or-marker>");
document.referrer.includes("<token-or-marker>");
```

Use SDK-specific APIs only where available. Avoid sending extra events containing real tokens.

### Phase 3: Observe Outbound Telemetry

Use browser devtools or an intercepting proxy to inspect outbound telemetry while the token is still in the URL.

Evidence to collect:

- telemetry host
- request path
- status code
- SDK version if available
- service/environment tags if visible
- redacted request body showing the token field location
- proof that the request occurred before form submission

Do not publish full tokens in the report.

### Phase 4: Account Correlation

After completing reset on the tester account:

1. Navigate to an authenticated route.
2. Check whether the same telemetry session ID persists.
3. Check whether the authenticated route contains account handle, user ID, workspace slug, email, org name, or other identity.
4. Check whether the SDK attaches user identity with `setUser`, user traits, anonymous ID, account ID, or route path.

Impact is stronger if the same session contains both:

- token-bearing reset view
- account-identifying authenticated view

### Phase 5: Global Capture Test With Dummy Marker

Use a harmless marker, not a real secret:

```javascript
const marker = "bb_dummy_marker_" + crypto.randomUUID();
history.pushState({}, "", location.pathname + "?demo_param=" + marker);
```

Then check whether telemetry captures the marker. Restore the original URL immediately:

```javascript
history.replaceState({}, "", location.pathname);
```

This proves whether the issue is route-specific or global URL capture.

## Server-Side Confirmation Query Ideas

The tester usually cannot access the organization's telemetry. Provide a query the program can run.

Examples:

```text
@view.url:*password-reset*
@view.url:*reset-password*
@view.url:*forgot-password*
@view.url:*token=*
@view.url:*invite*
@view.url:*verify*
```

For service-scoped systems:

```text
service:<service-name> @view.url:*password-reset*
```

Ask the program to confirm:

- number of stored events
- date range
- whether full tokens are present
- whether tokens were live at collection time
- whether session identity links tokens to accounts
- retention and export exposure

## Evidence Checklist

- Reset link shape with token redacted.
- Proof the form loads before token consumption.
- Telemetry SDKs loaded on the token-bearing page.
- SDK configuration showing missing or insufficient redaction.
- Sample rate or capture rate if available.
- SDK internal state containing token or dummy marker.
- Outbound telemetry request to sink with redacted token evidence.
- Timing proof: telemetry sent before reset form submission.
- Session correlation between reset view and account-identifying view.
- Global dummy-marker capture proof if applicable.
- Token single-use or validity behavior, tested only on the tester account.
- Clear statement of what was not accessed, such as no telemetry backend access and no third-party accounts.

## What To Avoid

- Do not disclose full reset tokens.
- Do not access other users' reset events.
- Do not attempt to query the company's telemetry backend unless explicitly authorized.
- Do not use leaked telemetry credentials.
- Do not test with real customer accounts.
- Do not trigger password resets for third parties.
- Do not submit sensitive real secrets as dummy markers.

## Root Cause Hypotheses

- Reset tokens are placed in URLs instead of exchanged server-side.
- Browser monitoring captures `location.href` or page context by default.
- Redaction callback is missing or only configured for one telemetry vendor.
- Prior fixes scrubbed one sink but not all sinks.
- Redaction is path-scoped and misses other secret-bearing routes.
- SPA route tracking captures query strings on every route.
- Account identity is attached to the same telemetry session as the reset link.

## Variant Testing Ideas

- Password reset links.
- Invite links.
- Email verification links.
- Magic login links.
- Organization join links.
- File share links.
- Billing portal links.
- OAuth authorization-code callbacks.
- SAML or OIDC callback URLs.
- Unsubscribe links.
- MFA recovery links.
- API key reveal links.
- Cross-host flows where one portal sends users into another portal's reset route.
- Mobile web and desktop web differences.
- SPA route changes after `history.pushState`.
- Query string, path segment, and fragment token placement.
- Referrer leakage from reset page to third-party resources.

## Remediation Recommendations

- Do not place account recovery tokens in long-lived browser URLs.
- Exchange the token server-side on first load and redirect to a clean URL.
- Store short-lived reset state in an HTTP-only, secure, same-site cookie.
- Strip query strings and fragments from telemetry URLs by default.
- Configure every telemetry SDK's redaction hook, not just one vendor.
- Prefer deny-by-default URL capture with explicit allowlisted parameters.
- Scrub `url`, `referrer`, `search`, `hash`, page context, custom properties, breadcrumbs, replay metadata, and user traits.
- Purge stored telemetry events containing live or recently live reset tokens.
- Treat unexpired captured tokens as compromised and invalidate them.
- Shorten token TTL where appropriate.
- Keep single-use invalidation.
- Add regression tests for every secret-bearing route and every telemetry sink.
- Set a strict `Referrer-Policy` on secret-bearing pages as defense in depth.

## Severity Guidance

Suggested severity: Medium when exploitation requires telemetry/RUM/log read access but yields live account recovery tokens.

Severity may be High if:

- Tokens are usable without email or other account identifiers.
- Telemetry also stores the account identifier.
- Tokens remain valid for a long time.
- Many employees, customers, admins, reviewers, or privileged users are affected.
- Telemetry access is broad, outsourced, integrated into many systems, or exposed through API keys.
- The affected accounts hold sensitive source code, production access, financial data, healthcare data, or admin privileges.

Severity may be Low if:

- Tokens expire very quickly.
- Tokens are already consumed before telemetry is sent.
- Telemetry redacts the token before storage.
- Account identity cannot be correlated.
- Telemetry access is extremely restricted and audited.

## Final Report Skeleton

````markdown
# Live Password Reset Token Leaks to Telemetry

## Summary
Opening a password reset link places a live account recovery token in the browser URL. A browser telemetry SDK captures the full URL before the reset form is submitted, causing the token to be stored in a third-party monitoring system.

## Affected Asset
- Host:
- Reset route:
- Reset endpoint:
- Telemetry sink:
- SDK/version:

## Preconditions
- Tester-controlled account:
- Token location:
- Telemetry access model:

## Steps To Reproduce
1. Request a reset link for a tester-controlled account.
2. Open the reset link but do not submit the form.
3. Confirm the token is present in the URL.
4. Confirm the telemetry SDK is loaded.
5. Confirm redaction is missing or insufficient.
6. Observe outbound telemetry before form submission.
7. Confirm the token appears in SDK state or telemetry payloads.
8. Complete reset on the tester account.
9. Confirm whether the same telemetry session links the token-bearing view to account identity.

## Observed Result

## Expected Result
Password reset tokens should not be sent to telemetry, analytics, RUM, logs, referrers, or third-party monitoring systems.

## Impact

## Evidence
- Reset link shape:
- SDK configuration:
- Telemetry request:
- Timing:
- Session correlation:
- Dummy marker global-capture test:

## Limitations
- No access to telemetry backend:
- No third-party accounts tested:

## Cleanup
- Token consumed or invalidated:
- Dummy marker removed:

## Remediation
Remove tokens from URLs, redirect to clean routes, configure global telemetry redaction, purge captured events, and invalidate any still-valid exposed tokens.
````
