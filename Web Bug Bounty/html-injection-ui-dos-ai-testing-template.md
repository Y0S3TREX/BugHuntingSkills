# Bug Bounty Testing Template: Stored HTML Injection Chained to UI DoS

## Universal Test Profile

- Report name: Stored HTML Injection to UI Denial of Service
- Primary weakness: Stored HTML injection in rich-text note rendering
- Chain: Stored HTML injection -> external resource beacon -> full-page CSS overlay -> UI denial of service
- Target: any authorized in-scope web application with stored rich-text or HTML-rendered user content
- Candidate endpoints: create/update endpoints for notes, comments, descriptions, messages, tickets, tasks, posts, CRM objects, support objects, profile fields, templates, signatures, and imported content
- Candidate fields: `html`, `body`, `content`, `description`, `note`, `note_html`, `comment`, `message`, `summary`, `bio`, `signature`, `template`, `rich_text`, `text`
- Required attacker capability: authenticated user who can create or edit content visible to another account or role
- Victim interaction required: victim opens the affected object, feed, notification, preview, export, or shared view

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for stored HTML injection that can chain into UI denial of service.

Rules:
- Work only on assets, accounts, and data explicitly authorized by the bug bounty program.
- Use attacker and victim test accounts controlled by the tester.
- Do not target real users.
- Do not steal cookies, tokens, private data, or perform destructive actions.
- Clean up every stored payload after collecting evidence.

Goal:
Find any stored user-controlled rich-text or HTML-rendered field where injected markup is saved and later rendered to another user. Confirm whether external image beaconing works and whether inline CSS can create a full-screen overlay that blocks the UI.

Workflow:
1. Map features where one user can store content another user can view: notes, comments, posts, messages, tickets, descriptions, profiles, tasks, templates, signatures, imports, and CRM/support records.
2. Capture create and update requests for those fields.
3. Identify parameters that may render as HTML, especially names like html, body, content, description, note, note_html, comment, message, rich_text, template, or signature.
4. First submit harmless HTML such as <b>html-injection-test</b> and check whether formatting survives.
5. Submit an external image beacon using a tester-controlled collaborator URL.
6. Open the affected object as the victim test account and check whether the collaborator receives a request.
7. Submit a harmless full-screen overlay payload using inline CSS fixed positioning.
8. Open the affected object as the victim test account and check whether the UI becomes blocked.
9. Test related render surfaces: detail page, activity feed, notifications, previews, exports, mobile web, and admin views.
10. Record request, response, screenshots, collaborator logs, DOM evidence, affected roles, and cleanup proof.

Stop condition:
- Stop once there is clear evidence of stored cross-user HTML injection, external resource loading, UI overlay impact, or a sanitizer bypass.

Output:
- A concise vulnerability report with affected endpoint, affected field, payload, reproduction steps, impact, evidence, cleanup, and remediation.
```

## Vulnerability Summary

The application stores attacker-controlled HTML submitted in a rich-text or HTML-rendered field and later renders it in other users' browsers without sufficient sanitization, isolation, or output encoding. Because arbitrary HTML and inline CSS can be preserved, an attacker can inject markup that affects the parent application UI.

The demonstrated chain has two parts:

1. External resource beaconing with an injected `img` tag to prove that another user loaded the stored note.
2. UI denial of service with a fixed-position full-screen overlay that blocks the victim from using the affected page.

This should be treated as stored HTML injection with possible stored XSS escalation if scripts, event handlers, dangerous URLs, or browser-executable contexts are also allowed.

## Security Impact

- Stored client-side content injection affects other users who view the note.
- Fullscreen injected CSS can make the affected page unusable.
- External image loads can confirm victim interaction and expose request metadata to an attacker-controlled server, such as public source IP, user agent, approximate time of view, and request headers normally sent for image loading.
- If the sanitizer also permits event handlers, script-capable tags, dangerous URL schemes, SVG script contexts, or DOM clobbering primitives, impact may escalate to stored XSS.

## Preconditions

- Testing must be performed only against an authorized bug bounty target and in-scope assets.
- Use accounts you control, such as attacker and victim test accounts.
- The attacker account must be allowed to create or edit content visible to another account.
- The victim account must be able to open the same object, record, post, ticket, note, message, profile, or shared workspace view.
- Use a harmless collaborator endpoint under your control for beacon verification.
- Do not use payloads that damage data, exfiltrate secrets, or affect real users.

## Baseline Request Shape

```http
PUT <candidate-create-or-update-path> HTTP/1.1
Host: <target-host>
Content-Type: application/json
Authorization: Bearer <attacker_token>

{
  "<candidate_html_field>": "<p>test</p>",
  "attachments": [],
  "title": "Note"
}
```

## Proof Payload: External Image Beacon

Purpose: confirm stored HTML is rendered in another user's browser and can trigger a request to an attacker-controlled endpoint.

```json
{
  "<candidate_html_field>": "<body><p><img src=\"https://YOUR-COLLABORATOR.example/html-injection-beacon\" alt=\"html-injection-test\"></p></body>",
  "attachments": [],
  "title": "Note"
}
```

Expected vulnerable behavior:

- The API stores the payload without removing the external `img`.
- When the victim opens the affected object or content view, the victim browser requests the collaborator URL.
- The collaborator log shows a request with user agent, timestamp, and public source IP or upstream proxy IP.

Expected safe behavior:

- The application strips external images, proxies them safely, blocks untrusted hosts, or renders the content as escaped text.
- The victim browser does not directly request the attacker-controlled host.

## Proof Payload: UI Denial of Service Overlay

Purpose: prove attacker-controlled inline CSS can interfere with the parent application UI.

Use a visible but reversible overlay during testing. Avoid destructive behavior and test only with your own victim account.

```json
{
  "<candidate_html_field>": "<body><p><span style=\"position:fixed;top:0;right:0;bottom:0;left:0;background:rgba(0,0,0,1);z-index:5000;display:block;\"></span></p></body>",
  "attachments": [],
  "title": "Note"
}
```

Expected vulnerable behavior:

- The note renders the injected `span` into the live page DOM.
- The fixed-position element covers the whole viewport.
- The victim cannot interact with the affected page, edit the content, or use normal page controls while the overlay is present.

Expected safe behavior:

- The sanitizer removes `style`, `position:fixed`, dangerous layout CSS, or the entire injected element.
- Rich text is rendered inside an isolated sandbox that cannot affect the parent UI.
- The note display is constrained so injected content cannot escape its container.

## Test Methodology

1. Confirm the target is in scope and that stored-note testing is allowed.
2. Create two test users or use two authorized roles in the same workspace.
3. As the attacker, create or edit a note using a normal benign payload.
4. Replay the create or update request and replace the candidate rich-text field with the external image beacon payload.
5. As the victim, open the affected object or render surface.
6. Check the collaborator endpoint for a request caused by victim page rendering.
7. Replace the note with the UI overlay payload.
8. As the victim, reload or revisit the affected object or render surface.
9. Record whether the overlay blocks interaction with the page.
10. Clean up the payload by deleting the content or replacing the affected field with benign text.

## Variants To Test

- Note creation endpoint as well as note update endpoint.
- Other rich-text fields: comments, descriptions, email signatures, tasks, notes, object descriptions, contact fields, custom fields, imports, templates, and integrations.
- Other render surfaces: activity feed, detail page, search results, notifications, email previews, mobile web, desktop web, exported PDFs, and embedded widgets.
- Other roles: admin, owner, member, restricted user, shared collaborator, and read-only viewer.
- Other tenants or shared objects where content crosses workspace boundaries.
- Other HTML tags: `img`, `a`, `svg`, `math`, `iframe`, `object`, `embed`, `video`, `audio`, `source`, `link`, `meta`, and table/layout tags.
- Other attributes: `style`, `class`, `src`, `srcset`, `href`, `target`, `rel`, `id`, `name`, `form`, and all event-handler attributes.
- Dangerous URL schemes: `javascript:`, `data:`, `vbscript:`, `file:`, protocol-relative URLs, encoded schemes, mixed-case schemes, and whitespace-obfuscated schemes.
- CSS abuse: `position:fixed`, `position:absolute`, large `z-index`, `pointer-events`, `opacity`, `transform`, negative margins, viewport units, sticky positioning, and overlaying navigation controls.
- Sanitizer bypasses: malformed tags, nested tags, double encoding, entity encoding, mixed case attributes, null bytes, comments, broken HTML, SVG namespace tricks, and copy-paste editor normalization.

## XSS Escalation Checks

Only run harmless verification payloads in authorized test accounts.

- Check whether event handlers survive, such as `onerror`, `onclick`, `onload`, or `onmouseover`.
- Check whether `javascript:` URLs survive in links.
- Check whether SVG or MathML script-capable contexts survive.
- Check whether the rendered content is inserted with unsafe DOM APIs such as `innerHTML`.
- Check whether CSP blocks inline script execution and external script loading.
- Check whether the payload executes in the main app origin or in a sandboxed origin.

Harmless example idea:

```html
<img src=x onerror="document.body.setAttribute('data-html-injection-test','1')">
```

Do not use cookie theft, token theft, account takeover actions, or real-user targeting.

## Evidence Checklist

- Raw HTTP request that stores the payload.
- Raw HTTP response showing the payload was accepted.
- Screenshot of the stored note as attacker.
- Screenshot or video of the victim loading the affected page.
- Collaborator log showing victim-triggered image request.
- Screenshot or video of the UI overlay blocking interaction.
- Browser devtools evidence showing the injected element in the DOM.
- Cleanup proof showing the malicious note was removed or neutralized.
- Scope proof showing the tested asset and accounts were authorized.

## Severity Guidance

Suggested severity: High when stored content affects other users and can make a business-critical page unusable or enables meaningful cross-user interaction tracking.

Severity may increase if:

- JavaScript execution is possible.
- Payload executes in the main application origin.
- Sensitive data can be read or actions can be performed as the victim.
- The payload affects many users, shared workspaces, admins, or external customers.
- The malicious content is difficult for victims or admins to remove.

Severity may decrease if:

- The payload only affects the submitting user.
- The content is rendered in a strongly sandboxed iframe.
- External resources are proxied and inline CSS is stripped.
- The UI impact is limited to a small content container and does not block the parent application.

## Root Cause Hypotheses

- The backend accepts rich HTML in a user-controlled field without strict sanitization.
- The frontend renders stored note content as HTML instead of escaped text.
- Inline CSS is allowed in user-controlled content.
- Rendered note content is not isolated from the parent application layout.
- CSP and image-source restrictions do not prevent direct external resource loads.

## Remediation Recommendations

- Prefer rendering notes as escaped plain text unless rich text is required.
- If rich text is required, use a strict server-side sanitizer with a minimal allowlist.
- Strip `style`, `class`, event handlers, scripts, iframes, objects, embeds, external links, and dangerous URL schemes unless there is a strong product need.
- For images, allow only same-origin or trusted hosts, or proxy images through the application backend.
- Render untrusted rich text in a sandboxed iframe without script execution and without top-level navigation privileges.
- Add CSP defense in depth, including restrictive `default-src`, `script-src`, `style-src`, `img-src`, and `frame-src`.
- Constrain rendered note content with container boundaries so it cannot cover the full viewport.
- Add server-side detection and logging for suspicious HTML/CSS patterns.
- Add regression tests for stored rich-text sanitization and cross-user rendering.

## AI Agent Testing Prompt

Use this prompt with an AI testing agent during authorized bug bounty work:

```text
You are testing an authorized bug bounty target for stored HTML injection in any rich-text or HTML-rendered user-controlled field. Stay within program scope and use only accounts controlled by the tester.

Target behavior to investigate:
- User-controlled HTML submitted to a stored content field may be rendered for other users.
- Risky fields are commonly named `html`, `body`, `content`, `description`, `note`, `note_html`, `comment`, `message`, `rich_text`, `template`, or `signature`.
- Risky endpoints commonly create or update notes, comments, posts, messages, tickets, tasks, profiles, templates, signatures, CRM records, or support records.
- A vulnerable implementation may preserve HTML tags, inline CSS, and external image URLs.

Primary test chain:
1. Authenticate as an attacker test user.
2. Create or edit stored content visible to a victim test user.
3. Submit a harmless external image beacon in the candidate rich-text field.
4. Open the affected object as the victim test user.
5. Confirm whether the victim browser requests the tester-controlled beacon URL.
6. Submit a harmless full-screen CSS overlay payload using fixed positioning.
7. Open the affected object as the victim test user.
8. Confirm whether the injected element escapes the content container and blocks the parent UI.
9. Clean up the payload immediately after evidence is collected.

Important payload concepts:
- External image beacon: <img src="https://COLLABORATOR/unique-id" alt="test">
- UI overlay: <span style="position:fixed;top:0;right:0;bottom:0;left:0;background:rgba(0,0,0,1);z-index:5000;display:block;"></span>

What to collect:
- Request and response for storing the payload.
- Victim-side screenshot or video.
- Collaborator request logs.
- DOM evidence showing injected markup.
- Notes about whether scripts, event handlers, style attributes, external images, and dangerous URL schemes are stripped or preserved.

Do not:
- Target real users.
- Steal cookies, tokens, or private data.
- Run destructive actions.
- Persist payloads after testing.
- Test out-of-scope assets.

Report conclusion format:
- Vulnerability type: stored HTML injection.
- Chain: stored injection to external request beacon and UI denial of service.
- Affected endpoint and field.
- Preconditions and roles.
- Step-by-step reproduction.
- Impact.
- Evidence.
- Cleanup performed.
- Recommended remediation.
```

## Final Report Skeleton

````markdown
# Stored HTML Injection Allows Cross-User UI Denial of Service

## Summary
An HTML-rendered user-controlled field stores attacker-controlled markup and renders it to other users without sufficient sanitization. An attacker can inject external resources to confirm victim interaction and inject fixed-position CSS that blocks the affected UI.

## Affected Asset
- Host:
- Endpoint:
- Field:
- Feature or object:
- Affected roles:

## Preconditions
- Attacker account:
- Victim account:
- Shared object or render surface:

## Steps To Reproduce
1.
2.
3.

## Proof Of Concept
```json
{
  "<candidate_html_field>": "",
  "<other_required_field>": ""
}
```

## Observed Result

## Expected Result

## Impact

## Evidence

## Remediation
````
