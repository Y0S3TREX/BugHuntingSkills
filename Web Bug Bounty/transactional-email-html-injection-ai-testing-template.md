# Bug Bounty Testing Template: Transactional Email HTML Injection

## Universal Test Profile

- Report name: Transactional Email HTML Injection in User-Controlled Template Fields
- Primary weakness: user input is inserted into an HTML email template without proper output encoding
- Bug class: HTML injection / email content injection / trusted-email abuse
- Common surfaces: contact forms, support forms, quote requests, newsletter signup, referral flows, invite flows, account notifications, order confirmations, appointment confirmations, lead forms, demo requests
- Common fields: `firstName`, `lastName`, `name`, `fullName`, `company`, `subject`, `message`, `comment`, `title`, `recipientName`, `displayName`
- Common email providers: SendGrid, Mailgun, SES, Postmark, Mandrill, SparkPost, Customer.io, Braze, Iterable, HubSpot, Salesforce Marketing Cloud
- Required attacker capability: submit a public or low-privilege form that triggers an email to an attacker-chosen or tester-controlled recipient
- Highest-risk impact: trusted branded email can contain attacker-controlled links or HTML that misleads recipients

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for HTML injection in transactional emails.

Rules:
- Work only on assets and endpoints explicitly authorized by the bug bounty program.
- Send emails only to tester-controlled addresses.
- Do not send emails to real users, employees, customers, or third parties.
- Do not perform credential harvesting, malware delivery, bulk sending, spam, or social engineering.
- Use harmless proof links such as https://example.com or a tester-controlled benign landing page.
- Keep volume low: one or two messages per payload variant.
- Stop immediately if the endpoint appears to send at scale or lacks rate limits.
- Redact recipient addresses and provider tracking URLs in evidence.

Goal:
Determine whether user-controlled fields submitted to a form are rendered as raw HTML inside a transactional email body, allowing attacker-controlled links, styling, or markup inside a trusted branded email.

Workflow:
1. Identify forms or endpoints that trigger outbound emails: contact, support, invite, referral, quote, demo, order, appointment, account, or notification flows.
2. Submit the form using a tester-controlled recipient email address.
3. Confirm the baseline email template, sender, subject, branding, and which fields appear in the email.
4. Inject harmless HTML into likely reflected fields, especially names, company, subject, and message fields.
5. Check the received email in at least one webmail or desktop client.
6. Record which tags survive, which attributes survive, and whether inline styles are preserved.
7. Check whether links are rewritten by the email provider and whether they still redirect to the original harmless test URL.
8. Confirm whether the email passes SPF, DKIM, and DMARC as a legitimate platform-sent message.
9. Check whether the endpoint requires authentication, CAPTCHA, CSRF protection, recipient validation, and rate limiting.
10. Collect screenshots and raw MIME/source evidence with all sensitive values redacted.

Stop condition:
- Stop once a benign HTML tag or styled link is rendered in the delivered email, or once all user-controlled fields are proven encoded/stripped.

Output:
- A concise vulnerability report with affected endpoint, field, payload, rendered email proof, provider behavior, abuse constraints, impact, and remediation.
```

## Vulnerability Summary

This bug occurs when a server accepts user-controlled input and inserts it directly into an HTML email template without HTML entity encoding or strict sanitization. If the email pipeline preserves HTML tags or attributes, the recipient receives a legitimate branded email containing attacker-controlled markup.

The most important proof is not script execution. Most email clients block scripts. The practical risk is that links, styling, layout, or misleading content can be injected into a trusted transactional email sent from the organization's legitimate infrastructure.

## Security Impact

- Trusted branded emails can contain attacker-controlled links or calls to action.
- Emails may pass SPF, DKIM, and DMARC because they are sent by the legitimate provider.
- Attackers may target arbitrary recipient addresses if the endpoint accepts arbitrary `email` values.
- Lack of CAPTCHA or rate limiting can enable automated abuse.
- Provider link tracking may wrap attacker-controlled links while still redirecting to the attacker-controlled destination.
- Sender reputation may be harmed if the endpoint is abused for phishing-like content or spam.

## Preconditions

- Testing is authorized.
- The tester controls the recipient mailbox.
- The endpoint sends a transactional email after submission.
- At least one submitted field appears in the email body or subject.
- The field is inserted into an HTML email context.

## Discovery Methodology

Look for endpoints and forms that send mail:

```text
/contact
/contacts/email
/support
/api/contact
/api/support
/api/invite
/newsletter
/demo-request
/quote
/referral
/forgot-password
/order-confirmation
/appointment
```

Common request shape:

```http
POST <email-trigger-endpoint> HTTP/1.1
Host: <target-host>
Content-Type: application/json

{
  "email": "<tester-controlled-recipient>",
  "firstName": "Test",
  "lastName": "User",
  "message": "Benign test message"
}
```

Record:

- whether authentication is required
- whether CAPTCHA is required
- whether CSRF protection is required
- whether the recipient can be arbitrary
- whether rate limiting exists
- whether the email provider is visible in headers
- which submitted fields appear in the delivered email

## Safe Payload Set

Use harmless payloads that demonstrate rendering without social engineering or harmful content.

### Encoding Probe

```html
HTML_TEST_<b>bold</b>_END
```

Vulnerable result:

- `bold` appears bold in the delivered email.

Safe result:

- The literal text `<b>bold</b>` appears, or tags are stripped.

### Styled Link Probe

```html
<a href="https://example.com" style="font-weight:bold;color:red">HTML_INJECTION_TEST_LINK</a>
```

Vulnerable result:

- The link renders as clickable styled text.
- The email provider may rewrite the URL through a tracking domain, but the final destination remains the harmless URL.

Safe result:

- The anchor is escaped, stripped, or converted to plain text.

### Layout Probe

```html
<span style="display:block;border:1px solid red;padding:4px">HTML_INJECTION_TEST_BOX</span>
```

Vulnerable result:

- The styled box renders inside the branded email.

Safe result:

- HTML is escaped or styles are removed.

## Payload Behavior Matrix

Track each field and payload:

| Field | Payload | API status | Email received | Rendered HTML | Notes |
| --- | --- | --- | --- | --- | --- |
| `firstName` | `<b>...</b>` | | | | |
| `firstName` | `<a href=...>` | | | | |
| `message` | `<span style=...>` | | | | |
| `subject` | `<b>...</b>` | | | | |

Also record whether these elements survive:

- `b`, `strong`, `i`, `em`
- `a href`
- inline `style`
- `div`, `span`, `p`
- `img`
- table/layout tags
- comments
- malformed tags

Do not use real credential-harvesting content or deceptive wording in payloads.

## Email Client Checks

Check rendering in tester-controlled inboxes:

- Gmail web
- Outlook web
- Apple Mail
- Thunderbird
- mobile mail client if relevant

Record:

- rendered body screenshot
- raw email source or MIME snippet
- sender/from/reply-to
- subject
- SPF/DKIM/DMARC results
- provider tracking link behavior
- whether the injected HTML appears in preview text
- whether the injected HTML appears in plain-text alternative

## Provider Tracking Behavior

If the provider rewrites links:

```text
Original href: https://example.com
Rendered href: https://<provider-tracking-domain>/...
Final redirect: https://example.com
```

Evidence should show:

- provider tracking domain
- final harmless destination
- that attacker-controlled link text and styling are preserved

Do not use real phishing domains.

## Abuse Controls To Check

Safely test or infer:

- authentication required
- CAPTCHA required
- CSRF token required
- per-IP rate limits
- per-recipient rate limits
- per-domain rate limits
- disposable email restrictions
- duplicate submission throttling
- content moderation
- HTML validation
- recipient verification before sending

Keep request volume minimal and do not stress the endpoint.

## Evidence Checklist

- Endpoint and request body with recipient redacted.
- Baseline email without injection.
- Injection request with harmless payload.
- HTTP response showing email accepted.
- Delivered email screenshot showing rendered injected HTML.
- Raw MIME/source snippet showing HTML context.
- Email headers showing legitimate sending infrastructure.
- SPF/DKIM/DMARC pass result if available.
- Provider link rewrite and harmless final redirect proof.
- Sanitization matrix for tested tags.
- Rate limit/CAPTCHA/authentication observations.
- Statement that only tester-controlled recipients were used.

## What To Avoid

- Do not send to victims or third parties.
- Do not run bulk tests.
- Do not use credential-harvesting pages.
- Do not use malware links.
- Do not impersonate company staff in test content.
- Do not attempt to bypass provider anti-abuse systems.
- Do not include real deceptive calls to action in screenshots.

## Root Cause Hypotheses

- User input is interpolated directly into an HTML email template.
- Template engine disables auto-escaping or uses raw/unsafe output.
- Sanitization happens for some tags but allows anchors and styles.
- Input validation treats name fields as free-form HTML-capable strings.
- Email provider link tracking rewrites links but does not remove unsafe injected anchors.
- Public form lacks anti-automation controls.

## Variant Testing Ideas

- Test all reflected fields, not just name fields.
- Test subject and preview-text injection.
- Test HTML body and plain-text alternative separately.
- Test multiple languages or locale-specific templates.
- Test contact, support, quote, demo, invite, referral, and confirmation emails.
- Test recipient-controlled vs fixed recipient flows.
- Test authenticated and unauthenticated submissions.
- Test whether the injected content appears in internal notification emails to staff.
- Test whether provider click tracking preserves final destination.
- Test whether the endpoint can send to arbitrary external domains.

## Remediation Recommendations

- HTML-encode all user-controlled values before insertion into HTML email templates.
- Do not allow HTML in name, company, subject, or other identity fields.
- Use template-engine auto-escaping by default.
- Sanitize rich-text fields with a strict email-safe allowlist only where rich text is truly required.
- Strip or disallow anchors, inline styles, images, scripts, forms, and layout-changing HTML in untrusted fields.
- Add CAPTCHA or equivalent bot protection to unauthenticated email-triggering forms.
- Add per-IP, per-recipient, and per-domain rate limiting.
- Validate recipient behavior and consider sending only to verified or expected recipients.
- Disable or constrain click tracking for user-supplied links if links are allowed.
- Add regression tests that render email templates with malicious-looking input and assert output encoding.

## Severity Guidance

Suggested severity: Medium when unauthenticated users can send branded emails with attacker-controlled links to arbitrary recipients.

Severity may be High if:

- The endpoint allows high-volume arbitrary recipient sending.
- The email passes SPF/DKIM/DMARC from a highly trusted domain.
- The injected link appears as a first-class call to action.
- The target audience includes customers, employees, healthcare users, financial users, or administrators.
- There is no CAPTCHA, authentication, or rate limiting.
- The injected content also reaches internal staff workflows.

Severity may be Low if:

- Emails can only be sent to the submitting user's verified address.
- HTML is limited to harmless formatting with no links.
- Strong rate limits and abuse detection are present.
- Branding is minimal and the sender is clearly no-reply/untrusted.

## Final Report Skeleton

````markdown
# HTML Injection in Transactional Email Template

## Summary
A user-controlled field submitted to an email-triggering endpoint is rendered as raw HTML in a transactional email. This allows a tester to inject a harmless styled link into a legitimate branded email sent by the platform's email provider.

## Affected Asset
- Host:
- Endpoint:
- Email provider:
- Email template:
- Affected field:

## Preconditions
- Recipient account controlled by tester:
- Authentication required:
- CAPTCHA/rate limit status:

## Steps To Reproduce
1. Submit the email form with a normal value and confirm the baseline email.
2. Submit the same form with a harmless HTML payload in the affected field.
3. Open the received email in a tester-controlled inbox.
4. Confirm the injected HTML renders inside the branded template.
5. Confirm any injected link points only to a harmless test URL.
6. Record headers and provider tracking behavior.

## Proof Payload
```html
<a href="https://example.com" style="font-weight:bold;color:red">HTML_INJECTION_TEST_LINK</a>
```

## Observed Result

## Expected Result
User-controlled values should be HTML-encoded or sanitized before insertion into email HTML.

## Impact

## Evidence
- Request:
- Response:
- Rendered email:
- Raw MIME/source:
- Email authentication:
- Rate limiting/CAPTCHA observations:

## Cleanup

## Remediation
HTML-encode user input in email templates, validate fields, add anti-abuse controls, and add regression tests.
````
