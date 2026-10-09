# Bug Bounty Testing Template: Stored Admin XSS via Unsanitized Media Metadata

## Universal Test Profile

- Report name: Stored Admin XSS via Unsanitized Media Metadata
- Primary weakness: attacker-controlled media metadata is stored unsanitized and later rendered unescaped in an administrative UI
- Bug class: stored XSS / cross-privilege XSS / metadata injection / output-encoding failure
- Common surfaces: CMS media libraries, attachment metadata APIs, image thumbnail APIs, file processing endpoints, asset managers, plugin media endpoints, REST finalize/processing endpoints
- Common attacker roles: author, contributor with upload rights, editor, vendor, tenant member, project member, low-privilege staff user
- Common victim roles: administrator, site owner, media manager, moderator, support agent, reviewer
- Required attacker capability: upload or edit a media object and influence stored metadata such as filename, thumbnail filename, variant path, alt text, caption, MIME metadata, preview URL, or derived image sizes
- Highest-risk impact: low-privilege user stores script that executes in a higher-privilege admin origin

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope CMS, plugin, or web application for stored admin-panel XSS through media metadata.

Rules:
- Work only on assets explicitly authorized by the bug bounty program.
- Prefer local lab, staging, or tester-owned instances when testing CMS/plugin vulnerabilities.
- Use only tester-controlled accounts and media files.
- Do not test payloads on production admins or real users.
- Use harmless execution proof such as changing document.title or setting a DOM marker.
- Do not create admin users, install plugins, edit themes, steal cookies, read secrets, or persist access.
- Clean up poisoned media objects and metadata after testing.

Goal:
Find whether a low-privilege user can store unsafe media metadata that later breaks out of an HTML attribute or element in an admin/media-library page and executes JavaScript in a higher-privilege session.

Workflow:
1. Identify media upload, edit, finalize, resize, crop, thumbnail, or metadata update endpoints.
2. Determine which roles can upload media or edit their own media metadata.
3. Upload a benign image or file as the low-privilege attacker.
4. Locate metadata fields that influence rendered URLs, file paths, thumbnail names, alt text, captions, titles, MIME fields, or variant names.
5. Try safe breakout probes in metadata fields using quotes and benign markers.
6. Check whether the server stores the raw value or sanitizes it to a basename/safe filename.
7. Identify admin or media-library screens that render the metadata.
8. Open those screens as a higher-privilege test account.
9. Inspect HTML source for unescaped attribute or element insertion.
10. Confirm execution only with a harmless proof payload such as document.title = "XSS-EXECUTED".
11. Test negative controls: lower role without upload permission, attacker editing another user's media, and unaffected screens.
12. Clean up the media object and any modified metadata.

Stop condition:
- Stop once stored metadata from a lower-privilege account executes script in a higher-privilege admin UI, or once all candidate sinks encode safely.

Output:
- A concise vulnerability report with write primitive, propagation path, render sink, required role, affected admin page, negative controls, impact, limitations, cleanup, and remediation.
```

## Vulnerability Summary

This bug occurs when an application stores attacker-controlled media metadata without validating that it is a safe filename/path/value, then later concatenates that metadata into a URL or HTML context and renders it without escaping.

The dangerous pattern is:

```text
low-privilege media metadata write
-> raw value stored in attachment/file metadata
-> raw value concatenated into URL/path/render data
-> admin UI echoes value into HTML attribute or element
-> attribute breakout or element injection
-> script execution in higher-privilege admin session
```

This is especially impactful when the attacker lacks permission to post arbitrary HTML/JavaScript through normal content features, but can still trigger script execution in an administrator's browser.

## Security Impact

- Low-privilege user can execute JavaScript in admin origin.
- Payload may fire whenever admins open affected media-library or admin pages.
- A single poisoned attachment may affect every admin who loads a listing page.
- Admin-origin XSS can often read nonces, perform privileged actions, create users, install plugins, change settings, or edit site content.
- The bug can bypass role restrictions such as lack of `unfiltered_html`, lack of admin rights, or inability to edit other users' content.

## Preconditions

- Testing is authorized.
- The attacker role can upload media or edit metadata for its own media.
- A metadata field accepts attacker-controlled strings.
- The application stores the value without strict validation or sanitization.
- A privileged user can load an admin/media UI that renders the stored value.
- The render context is HTML, especially single-quoted or double-quoted attributes.

## Candidate Fields

Test media metadata fields such as:

- original filename
- thumbnail filename
- resized variant filename
- image size `file`
- preview URL
- source URL
- `src`
- path
- title
- caption
- alt text
- description
- MIME type
- generated derivative names
- `srcset` values
- metadata JSON fields
- custom plugin media fields

## Safe Payloads

Use harmless proof payloads. Avoid destructive actions.

### Attribute Breakout Probe

For single-quoted attributes:

```text
a.jpg' data-bb-xss='1
```

For double-quoted attributes:

```text
a.jpg" data-bb-xss="1
```

Expected vulnerable source:

```html
<img src='.../a.jpg' data-bb-xss='1' alt=''>
```

### Harmless Execution Proof

For single-quoted `src` contexts:

```text
a.jpg' /><svg onload='document.title="XSS-EXECUTED-"+document.domain'></svg><b x='
```

For double-quoted `src` contexts:

```text
a.jpg" /><svg onload="document.title='XSS-EXECUTED-'+document.domain"></svg><b x="
```

Use only on tester-owned lab/staging instances or authorized test environments.

## Generic Write Request Shape

```http
POST <media-metadata-or-finalize-endpoint> HTTP/1.1
Host: <target-host>
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "media_id": "<attacker-owned-media-id>",
  "sizes": [
    {
      "name": "thumbnail",
      "file": "a.jpg' /><svg onload='document.title=\"XSS-EXECUTED\"'></svg><b x='",
      "width": 150,
      "height": 150,
      "mime_type": "image/jpeg"
    }
  ]
}
```

Adapt field names to the target. The important property is storing unsafe metadata for a media object the attacker owns.

## Validation Methodology

### Phase 1: Upload Baseline Media

1. Log in as low-privilege user.
2. Upload a small benign image.
3. Record media ID, owner, URL, and generated thumbnails.
4. Confirm the user can edit only their own media.

### Phase 2: Poison Metadata

1. Identify update/finalize/crop/resize metadata endpoint.
2. Submit a quote-containing filename or path marker.
3. Fetch stored metadata through API, admin UI, database, or response if allowed.
4. Confirm whether the raw quote and markup are stored verbatim.

Safe result:

- value is rejected
- value is converted with `sanitize_file_name`
- path separators are removed
- quotes and angle brackets are encoded or stripped
- only basenames are allowed

Vulnerable result:

- raw quotes, angle brackets, event handlers, or HTML survive in stored metadata.

### Phase 3: Trace Propagation

Check whether stored metadata flows into:

- image URL
- thumbnail URL
- `src`
- `srcset`
- link `href`
- preview HTML
- media picker
- admin listing
- gallery popup
- legacy iframe/modal
- attachment edit page
- file details sidebar

Record source/sink path clearly:

```text
metadata field -> URL builder -> image helper -> admin render function -> HTML attribute
```

### Phase 4: Privileged Render Sink

Open affected admin/media pages as a higher-privilege tester account.

Check:

- raw HTTP response body
- browser DOM
- script execution marker
- whether every media item is rendered in a listing page
- whether the page requires a nonce or is simple GET
- whether user interaction is required

### Phase 5: Negative Controls

Verify limits:

- low-privilege user without upload permission cannot write metadata
- attacker cannot edit another user's media
- modern media grid/list may be escaped
- individual edit page may be escaped
- only specific legacy popup or admin path may be affected
- payload does not execute in attacker's own context only

## Evidence Checklist

- Attacker role and capability proof.
- Victim role proof.
- Media upload request and response.
- Metadata poisoning request and response.
- Stored metadata showing raw unsafe value.
- Propagated URL or render data showing raw unsafe value.
- Admin HTML response showing attribute breakout.
- Browser execution proof with harmless marker.
- Affected admin route.
- Non-affected routes tested.
- Negative controls for permissions.
- Cleanup proof.

## What To Avoid

- Do not run post-exploitation actions such as creating admins or installing plugins.
- Do not steal cookies, nonces, or data.
- Do not target real administrators.
- Do not poison shared production media libraries unless explicitly authorized.
- Do not leave persistent poisoned media in place.
- Do not overclaim screens or versions not tested.

## Root Cause Hypotheses

- Metadata schema accepts arbitrary strings for filename/path fields.
- Write endpoint lacks `sanitize_file_name`, basename validation, path validation, or schema `pattern`.
- Stored metadata is later concatenated into URLs without canonicalization.
- Admin UI echoes URLs into HTML attributes without `esc_url`, `esc_attr`, or equivalent.
- Legacy render paths lack escaping even if modern UI paths are safe.
- Sanitization exists on upload path but not on later metadata/finalize path.

## Variant Testing Ideas

- Test thumbnail, medium, large, custom sizes, and original image fields.
- Test filenames with single quotes, double quotes, spaces, angle brackets, path separators, URL encodings, entities, and Unicode lookalikes.
- Test `src`, `srcset`, `href`, `alt`, `title`, caption, and description contexts.
- Test image crop/finalize/rotate/regenerate-thumbnail endpoints.
- Test plugin-specific media controllers.
- Test legacy and modern admin UIs separately.
- Test list views, grid views, modal pickers, iframe popups, gallery pickers, and editor integrations.
- Test same-origin admin execution with a harmless DOM marker.
- Test stale poisoned metadata after a partial fix.

## Remediation Recommendations

- Validate media metadata filename fields at write time.
- Require filename fields to be safe basenames only.
- Reject path separators, quotes, angle brackets, control characters, and URL schemes in filename fields.
- Use `sanitize_file_name` or framework-equivalent validation.
- Add schema `pattern`, enum, or `validate_callback` for metadata fields.
- Escape output at every HTML sink using context-aware functions:
  - URL context: `esc_url` or equivalent
  - attribute context: `esc_attr` or equivalent
  - HTML text context: HTML entity encoding
- Canonicalize metadata to basename before joining into URLs.
- Add migration or cleanup for stale poisoned metadata.
- Add regression tests for low-privilege metadata writes and admin render sinks.

## Severity Guidance

Suggested severity: High when a low-privilege user can execute JavaScript in an administrator's authenticated admin origin.

Severity may be Critical if:

- The payload fires automatically on common admin pages.
- The victim page has powerful CSRF tokens/nonces accessible to JavaScript.
- The attacker can trigger the admin to visit a nonce-less GET page.
- The application allows plugin/module installation, admin creation, or code editing from the admin UI.
- The poisoned object appears in global listings viewed by many admins.

Severity may be Medium if:

- The affected page is obscure.
- The victim must take unusual steps.
- The payload only affects users with similar privilege.
- Output is escaped in common admin paths and only one legacy path remains.

## Final Report Skeleton

````markdown
# Stored Admin XSS via Unsanitized Media Metadata

## Summary
A low-privilege user can store unsafe media metadata for an uploaded file. The value is later concatenated into an image URL and rendered unescaped in an administrative media UI, allowing HTML attribute breakout and JavaScript execution in a higher-privilege session.

## Affected Asset
- Product/application:
- Endpoint:
- Metadata field:
- Admin render path:
- Affected versions:

## Roles
- Attacker role:
- Victim role:
- Required permissions:

## Steps To Reproduce
1. Log in as a low-privilege user with media upload permission.
2. Upload a benign image.
3. Update or finalize the image metadata with a harmless XSS proof payload in a filename/path field.
4. Confirm the unsafe value is stored.
5. Log in as an administrator in a separate session.
6. Open the affected media/admin page.
7. Confirm the stored value breaks out of the HTML attribute.
8. Confirm harmless script execution with a DOM marker.

## Proof Payload
```text
a.jpg' /><svg onload='document.title="XSS-EXECUTED-"+document.domain'></svg><b x='
```

## Observed Result

## Expected Result
Media metadata should be validated at write time and escaped at every render sink.

## Impact

## Negative Controls
- User without upload permission:
- Attacker editing another user's media:
- Non-affected admin pages:

## Evidence
- Upload request:
- Metadata write request:
- Stored metadata:
- Rendered HTML:
- Browser execution proof:

## Cleanup

## Remediation
Validate metadata filenames as safe basenames, escape admin output with context-aware functions, and clean stale poisoned metadata.
````
