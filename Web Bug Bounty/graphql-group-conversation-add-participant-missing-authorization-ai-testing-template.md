# Bug Bounty Testing Template: Missing Authorization in Group Conversation Participant Addition

## Universal Test Profile

- Report name: Missing Authorization in Group Conversation Participant Addition
- Primary weakness: participant-management mutation or endpoint checks membership but misses permission/entitlement checks
- Bug class: broken access control / IDOR / function-level authorization bypass
- Common surfaces: GraphQL mutations, REST endpoints, chat APIs, inbox APIs, support tickets, clinical messaging, team workspaces, project discussions, private channels, group DMs
- Candidate operations:
  - `addParticipantsToGroupConversation`
  - `addParticipant`
  - `inviteUser`
  - `addMember`
  - `conversationAddParticipants`
  - `channelInvite`
  - `threadAddUsers`
  - `shareConversation`
  - `grantConversationAccess`
- Required attacker capability: authenticated user who is a participant/member of a private conversation or group object but lacks read, write, invite, admin, or entitlement permissions
- Highest-risk impact: unauthorized third-party access to private historical messages, files, attachments, patient/customer data, internal communications, or privileged workspace content

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for missing authorization in group conversation participant-add operations.

Rules:
- Work only on assets, accounts, data, and environments explicitly authorized by the bug bounty program.
- Use only tester-controlled accounts.
- Do not target real users or expose real private data.
- Use benign test messages and synthetic content.
- Do not spam invites or add unrelated real users.
- Clean up added participants and test conversations after evidence is collected.

Goal:
Find whether a low-privilege participant who cannot read, send, invite, administer, or otherwise act on a private conversation can still add another user to that conversation, causing the added user to gain access to historical content.

Testing model:
- Owner account: creates or controls the private conversation.
- Attacker account: is a participant/member but lacks one or more required permissions.
- Target/injected account: starts outside the conversation and should have no access.
- Optional observer account: legitimate participant used to prove baseline message history.

Workflow:
1. Create a private group conversation, channel, thread, ticket, workspace discussion, or shared object using tester-controlled accounts.
2. Add benign test messages before any injection attempt.
3. Add the attacker account in the lowest-privilege state available: unverified, read-blocked, send-blocked, restricted, external guest, suspended, removed-and-restored, pending, expired, or no-entitlement user.
4. Prove attacker limitations with negative controls:
   - Attacker cannot read the conversation.
   - Attacker cannot send a message.
   - Attacker cannot view message history.
   - Attacker cannot manage members through the UI.
5. Ensure the target/injected account is not currently a participant and cannot read the conversation.
6. Capture the participant-add request from a legitimate user or infer the mutation/endpoint from client traffic.
7. Replay the participant-add operation using the attacker account token/session.
8. Check whether the server returns success and adds the target account.
9. Log in as the target account and test whether historical messages, files, attachments, metadata, or participant lists are now visible.
10. Test whether the newly added account can further add other users, proving transitive privilege propagation.
11. Clean up by removing injected accounts and deleting test messages/conversations where possible.

Stop condition:
- Stop once an underprivileged participant can add another account, or once an injected account can access private historical content.

Output:
- A concise vulnerability report with affected operation, missing authorization boundary, account roles, negative controls, exploit request, post-injection access proof, impact, cleanup, and remediation.
```

## Vulnerability Summary

Private group conversation systems often separate multiple permissions:

- Read conversation history.
- Send messages.
- Invite or add participants.
- Remove participants.
- Manage conversation settings.
- Access sensitive content or regulated data.

This bug occurs when the participant-add operation only checks whether the caller is authenticated and currently listed as a participant, but does not verify that the caller has the required entitlement or permission to invite others.

Membership alone is not sufficient authorization. A restricted, unverified, guest, blocked, read-denied, send-denied, or no-entitlement participant may still satisfy a naive `participant_in_conversation` check while lacking the real authority to expand access.

## Security Impact

- Unauthorized users can grant third parties access to private conversations.
- Added third parties may receive full historical message access, including messages sent before they were added.
- Sensitive content may be exposed across teams, tenants, organizations, roles, or regulated contexts.
- The injected user may further add additional users, creating transitive unauthorized access propagation.
- Audit, notification, approval, or owner-consent gaps can make the access expansion difficult to detect.
- Impact is higher when conversations contain patient data, customer data, legal data, security incidents, credentials, financial records, HR content, or internal company communications.

## Authorization Boundary To Test

Expected secure authorization:

```text
authenticated
AND participant/member of the conversation
AND has read access to the conversation
AND has invite/add-member permission
AND has required product entitlement
AND target user is allowed by tenant/org/policy rules
```

Common vulnerable authorization:

```text
authenticated
AND participant/member of the conversation
```

The key bug pattern is treating participant status as the complete permission check rather than as only one precondition.

## Preconditions

- Testing is authorized.
- The application has private group conversations, channels, shared objects, tickets, inboxes, or threads.
- The tester controls at least three accounts:
  - Owner or authorized participant.
  - Restricted attacker participant.
  - Target/injected account.
- The tester can create benign private test content.
- The tester can capture API traffic through browser devtools, proxy logs, or client network traces.

## Generic GraphQL Request Shape

```http
POST <graphql-path> HTTP/1.1
Host: <target-host>
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "query": "mutation AddParticipants($input: AddParticipantsInput!){ addParticipantsToGroupConversation(input:$input){ success errors { attribute messages } } }",
  "variables": {
    "input": {
      "conversationId": "<conversation-id>",
      "userIds": ["<target-user-id>"]
    }
  }
}
```

## Generic REST Request Shape

```http
POST /api/conversations/<conversation-id>/participants HTTP/1.1
Host: <target-host>
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "user_ids": ["<target-user-id>"]
}
```

## Negative Control Checks

Before exploiting the participant-add operation, prove the attacker is not authorized for normal conversation actions.

### Control A: Attacker Cannot Read Conversation

```http
POST <graphql-path> HTTP/1.1
Host: <target-host>
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "query": "query ReadConversation($id: ID!){ conversation(id:$id){ id subject messages { edges { node { id body createdAt } } } } }",
  "variables": {
    "id": "<conversation-id>"
  }
}
```

Expected secure denial:

- `Unauthorized`
- `Forbidden`
- `null` conversation
- policy failure
- missing permission or entitlement error

### Control B: Attacker Cannot Send Message

```http
POST <graphql-path> HTTP/1.1
Host: <target-host>
Authorization: Bearer <attacker-token>
Content-Type: application/json

{
  "query": "mutation SendMessage($input: SendMessageInput!){ sendMessage(input:$input){ success errors { attribute messages } } }",
  "variables": {
    "input": {
      "conversationId": "<conversation-id>",
      "body": "benign authorization test"
    }
  }
}
```

Expected secure denial:

- missing write permission
- missing entitlement
- restricted user
- cannot send messages

### Control C: Target Cannot Read Before Injection

```http
POST <graphql-path> HTTP/1.1
Host: <target-host>
Authorization: Bearer <target-token>
Content-Type: application/json

{
  "query": "query ReadConversation($id: ID!){ conversation(id:$id){ id subject messages { edges { node { id body createdAt } } } } }",
  "variables": {
    "id": "<conversation-id>"
  }
}
```

Expected secure denial:

- target account is not a participant
- no messages returned
- no conversation returned

## Exploit Check

Replay the add-participant operation with the restricted attacker token.

Vulnerable behavior:

- The response returns `success: true`.
- The target account appears in the participant list.
- The operation succeeds even though the attacker cannot read or send messages.
- No approval gate is required.
- No owner/admin consent is required.

Safe behavior:

- The server denies the request due to missing invite permission, write permission, read permission, entitlement, role, or organization boundary.

## Post-Injection Impact Proof

After a successful add operation, log in as the target/injected account and request the conversation.

Evidence to collect:

- Same target account was denied before injection.
- Same target account can read after injection.
- Historical messages created before injection are visible.
- Attachments, files, participant metadata, or sensitive fields are visible if authorized to test.
- The injected user can or cannot add more users.

Use benign synthetic content:

```text
PRE-INJECTION TEST MESSAGE: created before unauthorized add.
POST-INJECTION TEST MESSAGE: created after unauthorized add.
```

Impact is stronger if the injected user can read the pre-injection message.

## Transitive Abuse Check

Test whether the newly injected account can add another tester-controlled account.

Vulnerable behavior:

- Attacker adds target.
- Target adds second target.
- Access propagates without owner/admin approval.

Do not add real users. Use only tester-controlled accounts.

## Variant Testing Ideas

- Add single participant vs multiple participants in one request.
- Add internal user, external guest, same-org user, cross-org user, inactive user, unverified user, pending user, restricted user, and removed user.
- Test direct messages upgraded to groups.
- Test channels, tickets, shared inboxes, projects, cases, workspaces, and private records.
- Test remove participant, rename conversation, archive conversation, mark read, pin, mute, share, export, and attachment-access operations.
- Test UI-blocked actions by replaying API requests directly.
- Test stale participant state: removed users, pending invites, expired memberships, suspended users, or users without product entitlement.
- Test whether historical content is visible or only future content is visible.
- Test whether notifications, audit logs, or owner approval occur.
- Test whether role checks differ between GraphQL and REST APIs.

## Evidence Checklist

- Account role matrix for owner, attacker, target, and optional observer.
- Conversation creation proof with benign pre-injection content.
- Attacker read-denial response.
- Attacker send-denial response.
- Target pre-injection read-denial response.
- Restricted attacker add-participant request.
- Successful add-participant response.
- Target post-injection read-success response.
- Proof that historical pre-injection messages are visible to target.
- Optional transitive add proof using only tester-controlled accounts.
- Cleanup proof showing injected participants removed or test conversation deleted.

## Root Cause Hypothesis

The vulnerable operation likely checks only:

```text
authenticated? && participant_in?(conversation)
```

The operation should also require an explicit permission or entitlement:

```text
authenticated?
&& participant_in?(conversation)
&& can_read_conversation?
&& can_write_or_manage_conversation?
&& can_invite_participants?
&& target_user_allowed_by_policy?
```

## Remediation Recommendations

- Add a server-side authorization check specifically for participant addition.
- Require invite/manage permission, not only participant membership.
- Require product entitlement or write permission where applicable.
- Enforce tenant, organization, role, verification, and external-user constraints for both caller and target users.
- Do not grant historical message access to newly added participants unless explicitly intended and approved.
- Consider owner/admin approval for adding sensitive external participants.
- Add audit events and notifications for participant additions.
- Add regression tests for restricted participants, read-denied participants, send-denied participants, removed participants, and unverified users.
- Review related operations: remove participant, rename group, archive/trash conversation, mark read, export, attach files, share links, and participant listing.

## Severity Guidance

Suggested severity: High when an underprivileged participant can add arbitrary users who gain access to private historical content.

Severity may be Critical if:

- Conversations contain regulated data such as medical, financial, legal, government, or child data.
- The bug crosses tenant or organization boundaries.
- Arbitrary external users can be added.
- Historical attachments and files are exposed.
- The injected user can propagate access transitively.
- There is no audit log, notification, approval, or easy revocation.

Severity may be Medium if:

- Only future messages are visible.
- Only same-organization users can be added.
- The caller already has full read/write access.
- Owners receive strong notifications and can immediately revoke access.
- The data is low sensitivity.

## Final Report Skeleton

````markdown
# Missing Authorization Allows Restricted Participant to Add Users to Private Conversation

## Summary
A restricted participant can call the participant-add operation and add another user to a private conversation despite lacking the required read, write, invite, or entitlement permissions. The injected user gains access to conversation content, including historical messages if confirmed.

## Affected Asset
- Host:
- API path:
- Operation/mutation:
- Object type:

## Account Roles
- Owner:
- Restricted attacker:
- Target/injected user:
- Optional observer:

## Preconditions
- Conversation type:
- Attacker restriction:
- Target pre-injection state:

## Steps To Reproduce
1. Create a private test conversation with benign pre-injection messages.
2. Add or configure the attacker as a restricted participant.
3. Confirm the attacker cannot read the conversation.
4. Confirm the attacker cannot send messages.
5. Confirm the target account cannot read the conversation.
6. Replay the add-participant operation using the attacker token.
7. Confirm the target was added.
8. Confirm the target can read historical conversation content.
9. Clean up all test participants and content.

## Observed Result

## Expected Result
The server should deny participant-add requests from users lacking explicit invite/manage permission and required entitlements.

## Impact

## Evidence
- Attacker read denial:
- Attacker send denial:
- Target pre-injection denial:
- Add-participant success:
- Target post-injection access:
- Historical message access:

## Cleanup

## Remediation
Add explicit server-side authorization for participant addition and review all related conversation management operations.
````
