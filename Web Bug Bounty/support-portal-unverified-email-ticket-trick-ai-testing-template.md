# Bug Bounty Testing Template: Support Portal Unverified Email Ticket Trick

## Universal Test Profile

- Report name: Support Portal Unverified Email Ticket Trick
- Primary weakness: support portal allows account creation or login with an unverified email address
- Bug class: broken authentication / email ownership bypass / ticket trick / account takeover via support inbox access
- Common surfaces: Zendesk, Freshdesk, Help Scout, Intercom, Salesforce Service Cloud, custom support portals, community portals, customer dashboards, help centers
- Required attacker capability: create or access a support-portal account using an email address not owned by the attacker
- Targeted external dependency: another site sends login links, password reset links, verification links, invoices, support replies, or secrets by email to the impersonated address
- Highest-risk impact: attacker reads inbound support tickets created from emails sent to the impersonated address and uses magic links or reset links to access third-party accounts

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for support portal email ownership bypass that enables ticket-trick attacks.

Rules:
- Work only on assets explicitly authorized by the bug bounty program.
- Use only tester-controlled domains, email addresses, and external test accounts.
- Do not impersonate real companies, employees, customers, vendors, or third parties.
- Do not request login links or password resets for real accounts.
- Do not access real support tickets, private emails, or third-party data.
- Use a harmless tester-owned external service or a self-controlled demo app to send test emails.
- Stop immediately if the portal exposes real existing tickets for an address you do not own.
- Do not exploit beyond proving that unverified email ownership can expose inbound email content.

Goal:
Determine whether a support portal lets a user register, log in, or view tickets for an email address they have not verified, and whether inbound emails to that address become visible as support tickets.

Workflow:
1. Identify the support portal and its signup/login model.
2. Check whether an account can be created using an arbitrary email address without clicking a verification link sent to that address.
3. Check whether login is possible before email verification.
4. Check whether the portal shows tickets, dashboard entries, email threads, attachments, or inbound messages for the unverified address.
5. Use a tester-controlled external sender to send a benign email into the support system that appears as a ticket for the unverified address.
6. Confirm whether the attacker session can read the ticket content.
7. Demonstrate the ticket-trick pattern using only a tester-controlled external service that sends a harmless magic link or unique token to the unverified address.
8. Confirm whether the magic link or token appears in the support portal.
9. Clean up the test account and tickets where possible.

Stop condition:
- Stop once an unverified support-portal account can read inbound email content for an email address the tester does not control, using only test addresses and benign content.

Output:
- A concise vulnerability report with affected support portal, email verification failure, ticket visibility proof, safe ticket-trick demonstration, impact, restrictions, and remediation.
```

## Vulnerability Summary

This bug occurs when a support portal treats possession of an email address as proven merely because a user typed that address during signup or login. If email ownership is not verified before ticket access, an attacker can register as a victim address and view support tickets associated with that address.

The attack becomes more serious when third-party services send magic login links, password reset links, verification links, invoices, secrets, or sensitive replies to that email address. If those inbound emails are converted into support tickets visible to the attacker, the attacker may use the contents to access external accounts or sensitive information.

## Attack Pattern

```text
1. Attacker creates support-portal account as victim@example.com without proving ownership.
2. External service sends an email to victim@example.com.
3. The support system ingests that email and creates a ticket for victim@example.com.
4. Attacker views the ticket while logged in as victim@example.com.
5. If the ticket contains a magic link or reset link, attacker can use it.
```

The core vulnerability is not the external service. The core vulnerability is the support portal allowing unverified email identities to read email-derived ticket content.

## Security Impact

- Unauthorized access to support tickets for an email address the attacker does not own.
- Exposure of inbound email content, attachments, ticket history, metadata, and support replies.
- Account takeover on third-party services that send magic links or reset links by email.
- Access to invoices, order details, internal support communications, customer data, or secrets sent through email.
- Impersonation of organizations or users inside the support portal.
- Potential cross-service compromise if many services use email-based login or recovery.

## Preconditions

- Testing is authorized.
- The support portal permits signup or login by email address.
- The attacker can enter an email address they do not control.
- Email verification is missing, optional, delayed, bypassable, or not required before ticket access.
- The portal displays tickets based on the claimed email address.
- Inbound emails to that address become tickets or dashboard messages.

## Safe Test Setup

Use only controlled identities:

- Attacker support account: created with a test address or controlled alias.
- Claimed victim address: use a tester-owned domain alias when possible, such as `claimed-victim@tester-domain.example`.
- External sender: a tester-owned app, mailbox, or demo service that sends a benign unique link or token.
- Magic-link simulation: use a harmless URL like `https://example.com/ticket-trick-test/<unique-id>`.

Do not use real brand addresses, employee addresses, customer addresses, or third-party accounts.

## Discovery Methodology

### Phase 1: Email Verification Check

Test whether the support portal allows account access before verification:

```text
1. Start signup with <claimed-email>.
2. Do not click any verification email.
3. Try to log in or continue session.
4. Open dashboard/tickets/profile.
5. Check whether the email is marked verified.
6. Check whether ticket access is enabled.
```

Vulnerable behavior:

- The dashboard is accessible.
- Tickets for the claimed email are visible.
- Email status is unverified but access is still granted.
- Verification email can be skipped.

Safe behavior:

- Ticket access is blocked until email ownership is verified.
- The account cannot log in before verification.
- The dashboard shows no tickets for unverified addresses.

### Phase 2: Ticket Creation From Inbound Email

Send a benign test email into the support system from a controlled sender.

Example subject:

```text
BB_TEST_TICKET_TRICK_<unique-id>
```

Example body:

```text
This is a benign bug bounty authorization test.
Unique marker: BB_TEST_TICKET_TRICK_<unique-id>
Harmless link: https://example.com/ticket-trick-test/<unique-id>
```

Vulnerable behavior:

- The support portal creates or displays a ticket containing the marker.
- The unverified account can read the ticket.

Safe behavior:

- The ticket is hidden until email verification.
- The ticket is associated only after verified ownership.
- Inbound emails from unverified identities are quarantined or not linked to accounts.

### Phase 3: Ticket-Trick Simulation

Use a tester-controlled external service or script to send a harmless "login link" style email to the claimed address.

The email should not authenticate to any real service. It should contain only a dummy link:

```text
https://example.com/magic-link-simulation/<unique-id>
```

Vulnerable behavior:

- The dummy link appears inside the support portal ticket.
- The attacker-controlled session can read and click it.

This demonstrates how a real magic login or password reset email could be exposed without targeting real accounts.

## Evidence Checklist

- Support portal signup request or screenshots.
- Proof that the claimed email was not verified.
- Proof that login/dashboard access was allowed anyway.
- Ticket list visible to the unverified account.
- Inbound test email with unique marker.
- Ticket content showing the unique marker.
- Dummy magic-link simulation visible inside the ticket.
- Timestamps linking sent email to created ticket.
- Cleanup proof, if available.
- Statement that no real third-party accounts or users were targeted.

## What To Avoid

- Do not use a real organization's email address.
- Do not request real magic links or password resets for third-party accounts.
- Do not access existing tickets for an address you do not own.
- Do not read customer support data.
- Do not send repeated or bulk emails.
- Do not impersonate a real company in test content.
- Do not continue if real data appears unexpectedly.

## Root Cause Hypotheses

- Support account creation does not require email verification.
- Ticket visibility is keyed only by claimed email address.
- Email verification is required for some features but not ticket reads.
- Inbound email ingestion trusts the `From` or recipient identity without linking to a verified account.
- Portal login uses weak magic-link or session logic that does not prove mailbox ownership.
- Existing tickets are automatically attached to newly created accounts with matching email.

## Variant Testing Ideas

- Signup with unverified email.
- Login with unverified email.
- Magic-link login flow for support portal itself.
- Existing tickets linked after account creation.
- New inbound tickets linked after account creation.
- Attachments visible in tickets.
- Internal agent replies visible.
- CC/BCC participants visible.
- Organization-level tickets visible through claimed domain email.
- Plus-addressing and case-normalization edge cases.
- Domain aliases, shared mailboxes, and role addresses.
- Email change flow where new email is unverified but ticket access changes.
- SSO or customer portal accounts linked to support identities.

## Remediation Recommendations

- Require email verification before any ticket, dashboard, or profile access.
- Do not show existing or new tickets to unverified email identities.
- Do not attach historical tickets to newly registered accounts until email ownership is verified.
- Use signed, single-use verification links for support portal signup.
- Re-check verification before each sensitive ticket read.
- Quarantine inbound messages for unverified identities.
- Add alerts when a new account claims an email address with existing ticket history.
- Prevent arbitrary users from claiming protected organization, role, or vendor email addresses.
- Log and audit account creation, email verification, and ticket-linking events.
- Add regression tests for unverified account ticket visibility.

## Severity Guidance

Suggested severity: High when an attacker can read inbound emails or magic links for an address they do not own.

Severity may be Critical if:

- The portal exposes password reset or magic login links for high-value external services.
- Existing ticket history contains sensitive data, secrets, invoices, attachments, or internal replies.
- Attackers can claim organization/vendor addresses at scale.
- The vulnerability allows account takeover of production systems.

Severity may be Medium if:

- Only newly generated benign tickets are visible.
- Email verification is required before historical tickets are shown.
- The portal exposes low-sensitivity content only.
- Rate limits and monitoring substantially reduce abuse.

## Final Report Skeleton

````markdown
# Support Portal Allows Unverified Email Account to Read Tickets

## Summary
The support portal allows a user to create or access an account using an email address before proving ownership. Tickets generated for that email address become visible in the portal, enabling a ticket-trick attack where login links or reset links sent by external services can be read by the attacker.

## Affected Asset
- Support portal:
- Signup/login endpoint:
- Ticket dashboard:
- Email verification status:

## Preconditions
- Claimed email:
- Verification state:
- Tester-controlled external sender:

## Steps To Reproduce
1. Create or log into a support account using a claimed email address.
2. Do not verify ownership of that email address.
3. Confirm the dashboard or ticket list is accessible.
4. Send a benign test email containing a unique marker to the support system.
5. Confirm a ticket is created for the claimed email.
6. Confirm the unverified account can read the ticket content.
7. Send a harmless dummy magic-link simulation and confirm it appears in the ticket.

## Observed Result

## Expected Result
The portal should require verified email ownership before showing any tickets or inbound email content for that address.

## Impact

## Evidence
- Unverified email state:
- Dashboard access:
- Test email marker:
- Ticket content:
- Dummy magic link:
- Cleanup:

## Remediation
Require email verification before ticket access, prevent historical ticket linking to unverified accounts, and quarantine inbound email until ownership is proven.
````
