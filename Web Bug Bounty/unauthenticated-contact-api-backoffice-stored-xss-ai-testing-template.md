# Bug Bounty Testing Template: Unauthenticated Contact API Stored XSS in Back Office

## Universal Test Profile

- Report name: Unauthenticated Contact API Stored XSS in Back-Office Ticket Review
- Primary weakness: public form/API stores attacker-controlled HTML or JavaScript that executes when staff review submissions
- Bug class: stored XSS / back-office XSS / support-ticket injection / missing server-side validation
- Common surfaces: contact forms, support forms, product inquiry forms, complaint forms, quote requests, warranty claims, feedback forms, CMS contact APIs, CRM lead APIs
- Common back offices: CMS admin, CRM, helpdesk, ticket queue, moderation panel, customer-service dashboard, marketing consent dashboard
- Common stacks: Umbraco, WordPress plugins, Drupal modules, Sitecore, custom ASP.NET MVC, Laravel, Rails, Node/Express, headless CMS integrations
- Required attacker capability: unauthenticated or low-privilege submission of a form that staff later review
- Highest-risk impact: script execution in authenticated staff/operator/admin session

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for stored XSS in public contact/support APIs that execute in internal back-office review tools.

Rules:
- Work only on assets and endpoints explicitly authorized by the bug bounty program.
- Use only tester-controlled email addresses, names, attachments, and test content.
- Do not target real support agents or submit payloads likely to execute in production staff queues unless the program explicitly allows it.
- Prefer staging, demo, local, or tester-owned environments for execution testing.
- Use harmless payloads such as DOM markers or document.title changes.
- Do not steal cookies, create users, install packages, upload malware, or modify production content.
- Keep request volume low and do not flood queues.
- Clean up test tickets/submissions and uploaded files where possible.

Goal:
Determine whether a public contact/support endpoint accepts unsafe HTML/JavaScript in submitted fields, stores it, and renders it unsafely in a staff back-office interface.

Workflow:
1. Identify public endpoints that create customer-service tickets, contact requests, product inquiries, complaints, or CRM leads.
2. Submit a baseline request using a tester-controlled email and benign content.
3. Identify all fields accepted by the endpoint, including hidden fields, locale fields, site/tenant IDs, referrer, user agent, consent flags, and attachment references.
4. Test whether server-side CAPTCHA validation is enforced by submitting with an empty or invalid CAPTCHA token.
5. Test whether authentication, CSRF, Origin/Referer checks, and rate limits exist using minimal safe requests.
6. Inject harmless HTML probes into text fields and observe whether the API accepts them.
7. If a safe review environment is available, open the created ticket as a staff/admin test account and check whether markup executes.
8. Test attachment upload behavior only with harmless files; do not upload malware.
9. Test whether tenant/site IDs can be changed to route submissions into other brands, locales, or workspaces.
10. Record accepted fields, sanitization behavior, back-office render context, and control failures.

Stop condition:
- Stop once a harmless payload is stored and confirmed to render or execute in a staff back-office context, or once server-side sanitization/encoding is confirmed.

Output:
- A concise vulnerability report with affected endpoint, fields, missing controls, payload, staff-side render proof, tenant impact, rate-limit/CAPTCHA status, cleanup, and remediation.
```

## Vulnerability Summary

This vulnerability occurs when a public form endpoint stores user submissions and internal staff later view those submissions in a back-office interface without proper output encoding or sanitization. The submitter may be unauthenticated, while the victim is an authenticated support operator, editor, moderator, or administrator.

The core chain is:

```text
unauthenticated public submission
-> unsafe fields accepted server-side
-> stored in ticket/CRM/CMS
-> staff opens ticket in authenticated back office
-> HTML/JavaScript executes with staff privileges
```

The risk increases when CAPTCHA, CSRF, Origin/Referer checks, rate limits, tenant authorization, attachment validation, and email validation are also missing.

## Security Impact

- Stored XSS in staff/operator/admin sessions.
- Access to support tickets, customer PII, CRM data, internal notes, and admin APIs.
- Content modification or administrative actions using staff privileges.
- Ticket queue flooding if no rate limits or bot protection exist.
- Cross-tenant or cross-brand injection if `siteId`, `tenantId`, `brandId`, or locale fields are not authorized.
- Malicious attachment delivery into staff workflows if uploads lack validation.
- Fake consent or subscription records if marketing consent fields are trusted without verification.

## Preconditions

- Testing is authorized.
- A public endpoint creates records later reviewed by staff.
- At least one submitted field is rendered in an HTML back-office context.
- The field is stored without sanitization or rendered without output encoding.
- Staff review interface is reachable in a safe test environment or evidence can be inferred from response/rendered preview.

## Candidate Endpoints

Look for paths like:

```text
/contact
/api/contact
/contacts/email
/support
/api/support
/complaint
/feedback
/lead
/crm
/ticket
/umbraco/api/*contact*
/wp-json/*contact*
/api/forms/*
/api/attachments
/upload
```

Common methods:

- `POST` form-urlencoded
- `POST` JSON
- `multipart/form-data` attachment upload

## Candidate Fields

Test all fields that may appear in staff tools:

- `firstName`, `lastName`, `name`, `email`, `compareEmail`
- `address`, `city`, `country`, `postalCode`, `phone`
- `subject`, `message`, `question`, `comment`, `description`
- `product`, `store`, `orderNumber`, `coreCode`, `category`
- `pageUrl`, `referrer`, `sourceTags`, `userAgent`
- `siteId`, `tenantId`, `brandId`, `cultureId`, `locale`
- `contactMethods`, `consents`, `newsletter`, `marketingOptIn`
- attachment filename/reference fields

## Safe Payload Set

Use harmless probes first.

### HTML Rendering Probe

```html
HTML_TEST_<b>bold</b>_END
```

### Attribute/Event Probe

```html
<img src=x onerror="document.body.setAttribute('data-bb-xss','1')">
```

### SVG Harmless Marker

```html
<svg onload="document.title='XSS-EXECUTED-'+document.domain"></svg>
```

### Dangerous URI Probe Without Exfiltration

```html
<a href="javascript:document.title='XSS-LINK-TEST'">XSS_LINK_TEST</a>
```

Do not use payloads that steal cookies, tokens, or data.

## Missing-Control Checks

### CAPTCHA Enforcement

Submit once with a missing or invalid CAPTCHA token.

Vulnerable behavior:

- API returns success.
- Ticket is created.

Safe behavior:

- server rejects with CAPTCHA validation error.

### CSRF and Origin/Referer

Submit without cookies and with no Origin/Referer, or from a harmless controlled Origin if allowed.

Record:

- whether cookies are required
- whether CSRF token is required
- whether Origin/Referer is validated
- whether CORS allows cross-origin POSTs

### Rate Limiting

Use very low-volume checks only.

Record:

- duplicate submission behavior
- per-IP limits
- per-recipient limits
- bot challenges
- cooldown messages

Do not stress the endpoint.

### Tenant/Site Authorization

If the request includes `siteId`, `tenantId`, `brandId`, `locale`, or `cultureId`, test whether changing it routes the ticket elsewhere.

Use safe values from the same authorized scope only.

Vulnerable behavior:

- arbitrary tenant/site ID accepted
- ticket appears in another brand/workspace/locale queue

Safe behavior:

- server derives tenant from host/session
- unauthorized tenant IDs are rejected

## Attachment Testing

Use harmless files only:

- small `.txt`
- small benign `.pdf`
- small image

Record:

- authentication required
- file type validation
- magic-byte validation
- extension validation
- size limits
- malware scanning indications
- whether uploaded file can be attached to a ticket without authorization
- whether attachment filenames are sanitized

Do not upload malware, macros, LNK files, EXEs, or weaponized PDFs.

## Back-Office Verification

Best evidence is staff-side rendering in a safe test environment.

Collect:

- ticket ID or submission ID
- staff/admin URL where the ticket is reviewed
- screenshot of rendered fields
- DOM showing injected HTML
- harmless execution marker
- role/session used for verification

If no back-office access is available:

- report accepted payloads and missing controls as preliminary
- request program confirmation from staff-side ticket rendering
- avoid claiming execution unless observed

## Evidence Checklist

- Baseline successful submission.
- Payload submission request and response.
- List of vulnerable fields.
- CAPTCHA bypass evidence.
- CSRF/Origin/Referer/CORS observations.
- Rate-limit observation with minimal requests.
- Tenant/site ID behavior if applicable.
- Attachment upload behavior if applicable.
- Staff-side rendered HTML or execution marker.
- Cleanup evidence.
- Clear statement of test accounts, test emails, and safe payloads used.

## What To Avoid

- Do not flood ticket queues.
- Do not submit payloads designed to steal sessions.
- Do not upload malicious documents.
- Do not target real support staff unless explicitly authorized.
- Do not manipulate real customer consent or subscriptions.
- Do not submit cross-tenant tests outside scope.
- Do not overclaim RCE or account takeover without safe, direct evidence.

## Root Cause Hypotheses

- CAPTCHA is enforced only client-side.
- Public API endpoints skip CSRF because they are assumed anonymous-safe.
- Staff UI renders ticket fields as trusted HTML.
- Server stores all fields verbatim.
- Email validation permits HTML-like local parts and staff UI renders them unsafely.
- Tenant or site routing is trusted from client-controlled parameters.
- Attachment upload endpoint is unauthenticated or unbound to a verified ticket/session.

## Variant Testing Ideas

- Test every locale/brand route that shares the same API.
- Test personal contact vs product contact vs complaint forms.
- Test JSON and form-urlencoded content types.
- Test hidden fields from the frontend bundle.
- Test internal notification emails generated from the ticket.
- Test back-office list view and detail view separately.
- Test exported CSV/PDF views for formula injection or HTML injection.
- Test attachment names and descriptions.
- Test staff reply templates and CRM sync fields.
- Test cross-tenant `siteId`, `brandId`, and `cultureId`.

## Remediation Recommendations

- Encode all user-supplied values on output in staff/admin UI.
- Sanitize rich-text fields with a strict allowlist only if rich text is required.
- Treat all contact-form fields as untrusted, including hidden fields, referrer, URL, and user agent.
- Validate CAPTCHA server-side.
- Add CSRF protections where browser-authenticated flows exist.
- Enforce Origin/Referer checks or robust CORS restrictions for public APIs.
- Add per-IP and per-identity rate limits.
- Derive tenant/site/brand from server-side context, not client-controlled IDs.
- Validate email addresses with standard libraries and never render them as HTML.
- Bind attachments to a submission/session and validate content type, extension, magic bytes, and size.
- Add regression tests that render malicious submissions in staff UI and assert escaping.

## Severity Guidance

Suggested severity: High when unauthenticated attackers can store payloads that execute in staff back-office sessions.

Severity may be Critical if:

- Payload executes in administrator or CMS superuser sessions.
- Back office allows code/package/plugin installation.
- Cross-tenant injection is possible.
- The endpoint is unauthenticated, lacks CAPTCHA, and lacks rate limits.
- Attachments can deliver unsafe files into staff workflows.
- Customer PII or regulated data is accessible from the staff session.

Severity may be Medium if:

- Payload renders only as harmless HTML without script execution.
- Staff UI has strong CSP that prevents execution.
- The endpoint requires authentication and rate limits.
- Only low-sensitivity staff views are affected.

## Final Report Skeleton

````markdown
# Unauthenticated Contact API Stored XSS in Back Office

## Summary
A public contact/support API accepts attacker-controlled HTML/JavaScript in submitted fields and stores it in a ticket or CRM record. When staff review the submission in the back office, the payload renders or executes in their authenticated session.

## Affected Asset
- Host:
- Endpoint:
- Back-office product:
- Affected fields:
- Affected tenant/site:

## Preconditions
- Authentication required:
- CAPTCHA status:
- CSRF/Origin status:
- Rate-limit status:
- Staff review path:

## Steps To Reproduce
1. Submit a benign baseline contact request.
2. Submit a request with a harmless XSS marker in the affected field.
3. Confirm the API accepts and stores the request.
4. Open the ticket in a safe staff/admin test session.
5. Confirm the payload renders or executes.
6. Test minimal missing-control checks: CAPTCHA, CSRF, rate limiting, tenant ID, and attachment handling where applicable.
7. Clean up the test ticket and uploaded files.

## Proof Payload
```html
<svg onload="document.title='XSS-EXECUTED-'+document.domain"></svg>
```

## Observed Result

## Expected Result
Public submissions should be validated server-side and encoded before rendering in staff/admin tools.

## Impact

## Evidence
- Request:
- Response:
- Staff-side render:
- Missing controls:
- Tenant behavior:
- Attachment behavior:

## Cleanup

## Remediation
Encode output in back-office views, validate CAPTCHA server-side, add rate limits, validate tenant IDs server-side, and sanitize/validate attachments.
````
