# Bug Bounty Testing Template: JFrog Artifactory Blank Join Key Authentication Bypass

## Universal Test Profile

- Report name: JFrog Artifactory Blank Join Key Authentication Bypass
- Primary weakness: unauthenticated trusted-service registration through a weak or default join key
- Bug class: authentication bypass leading to service token issuance and possible administrative access
- Common product: JFrog Artifactory / JFrog Access
- Candidate CVE family: blank, default, empty, weak, exposed, or reused Artifactory join key vulnerabilities
- Target: any authorized in-scope Artifactory or JFrog Platform instance
- Candidate endpoints:
  - `/access/api/v1/registry/join`
  - `/access/api/v1/tokens`
  - `/artifactory/api/system/version`
  - `/artifactory/api/repositories`
  - `/artifactory/api/security/users`
- Required attacker capability: unauthenticated network access to the JFrog Access join endpoint, or authorized internal testing access if the endpoint is network-restricted
- Highest-risk impact: service trust forgery, admin token issuance, repository read/write, token exposure, user management, secret exposure, and software supply chain compromise

## Start-Now AI Testing Prompt

```text
You are an authorized bug bounty testing agent. Start testing the current in-scope target for a JFrog Artifactory / JFrog Access blank or weak join-key authentication bypass.

Rules:
- Work only on assets explicitly authorized by the bug bounty program.
- Do not test random internet hosts.
- Do not persist access, implant users, create long-lived tokens, modify production artifacts, delete data, or disrupt service.
- Do not extract secrets unless the program explicitly allows secret access proof; prefer proving that an endpoint is reachable and redacting sensitive values.
- Use the minimum proof needed to demonstrate impact.
- Clean up all test artifacts immediately.
- If network controls block the endpoint, report that the public path is mitigated and recommend internal validation rather than bypassing controls.

Goal:
Determine whether an Artifactory/JFrog Access instance accepts a forged trusted-service join token created with a blank/default/weak join key, and whether the returned service token can request elevated permissions.

Workflow:
1. Confirm the target is an in-scope JFrog Artifactory or JFrog Platform instance.
2. Identify externally reachable JFrog endpoints and version indicators without brute force or disruptive scanning.
3. Check whether `/access/api/v1/registry/join` is reachable from the authorized testing network.
4. Generate a fresh join JWT immediately before sending it; the `iat` value may have a strict freshness window.
5. Submit the forged join JWT to the join endpoint.
6. If the server returns a service token, treat authentication bypass as confirmed.
7. Test whether the service token can request an admin-scoped or high-privilege access token.
8. Verify impact using read-only or reversible actions first, such as listing a limited number of repositories or checking token scope.
9. Avoid dumping full user lists, full token lists, private keys, passwords, or repository contents unless explicitly authorized.
10. Record exact requests, responses, timestamps, version evidence, token scopes, and cleanup actions.

Stop condition:
- Stop as soon as service-token issuance or elevated-token issuance is confirmed.
- Stop if the endpoint is blocked by WAF, IP allowlist, VPN requirement, or patched-version behavior.

Output:
- A concise vulnerability report with affected endpoint, version if known, join-token behavior, privilege escalation result, impact, evidence, network restrictions, cleanup, and remediation.
```

## Vulnerability Summary

Some Artifactory/JFrog Access deployments rely on a shared join key to allow internal services or cluster nodes to register as trusted services. If the join key is blank, default, weak, exposed, or predictable, an unauthenticated attacker who can reach the join endpoint may forge a trusted-service JWT.

If accepted, the join endpoint may return a valid service token. Depending on configuration, that service token may be usable to request an admin-scoped access token or perform privileged API actions. This can lead to full takeover of artifact repositories and severe supply chain risk.

## Security Impact

- Authentication bypass into JFrog Access trusted-service registration.
- Service token issuance without valid administrative credentials.
- Possible admin-scoped access token issuance.
- Read access to private repositories, build artifacts, package metadata, and deployment assets.
- Write access to package repositories, enabling artifact poisoning.
- Exposure of users, groups, permissions, access tokens, configuration, signing keys, credentials, and integrations if admin access is reached.
- Supply chain compromise if attackers can alter packages, container images, release bundles, Maven artifacts, npm packages, PyPI packages, Helm charts, OCI images, or signing material.

## Preconditions

- Testing is authorized by the bug bounty program.
- The target is confirmed to be a JFrog Artifactory or JFrog Platform instance.
- The testing network can reach the JFrog Access API.
- The join endpoint is exposed to the tester, or the program allows internal validation.
- The tester uses only short-lived tokens and avoids persistent changes.

## Discovery Methodology

Use low-noise checks:

```http
GET /artifactory/api/system/version HTTP/1.1
Host: <target-host>
```

```http
GET /access/api/v1/system/ping HTTP/1.1
Host: <target-host>
```

```http
POST /access/api/v1/registry/join HTTP/1.1
Host: <target-host>
Content-Type: text/plain

<fresh-forged-join-jwt>
```

Indicators worth recording:

- Product/version response.
- HTTP status for the join endpoint.
- Whether unauthenticated requests reach JFrog Access or are blocked by WAF/network controls.
- Whether the response indicates key mismatch, invalid token, stale `iat`, missing `kid`, unknown service, or successful token issuance.
- Whether Cloudflare, Akamai, reverse proxy, VPN, allowlist, or internal-only routing changes public exploitability.

## Generic Join JWT Construction Concepts

Important concepts for AI testing agents:

- The join JWT must be generated fresh and sent immediately.
- `iat` may need to be in seconds, not milliseconds, depending on the vulnerable implementation.
- Some vulnerable versions require a `kid` identifying the blank key.
- The blank key pattern may derive from an empty join key padded into a fixed-length HMAC key.
- Use a unique `jti`, `service_id`, and `node_id` per attempt.
- Do not reuse stale tokens.
- Do not create persistent service identities beyond what the join endpoint automatically does.

Generic pseudocode:

```text
1. Build JWT header with HS256 and any required key identifier for the tested vulnerability family.
2. Build JWT payload with fresh iat, unique jti, service_id, node_id, and skip_node_registration if applicable.
3. Sign header.payload with the candidate blank/default/weak join key.
4. Immediately POST the JWT as text/plain to /access/api/v1/registry/join.
5. If a service token is returned, request the minimum privilege token needed to prove impact.
6. Verify privileges with read-only calls first.
```

## Safe Validation Sequence

### Phase 1: Reachability

Goal: determine whether the join endpoint is reachable.

Expected vulnerable or testable behavior:

- The endpoint accepts unauthenticated POST requests and returns token-validation errors or service-token responses.

Expected mitigated behavior:

- The endpoint is blocked from the public internet.
- The endpoint requires VPN, allowlist, or internal routing.
- The endpoint rejects forged JWTs because the join key is strong or the version is patched.

### Phase 2: Authentication Bypass

Goal: determine whether a forged join JWT is accepted.

Vulnerable behavior:

- HTTP success response from `/access/api/v1/registry/join`.
- JSON response contains a service token or token-like value.

Safe evidence:

- Capture status code.
- Capture redacted response shape.
- Capture token metadata only, not full reusable token values.

### Phase 3: Privilege Escalation

Goal: determine whether the service token can obtain elevated permissions.

Candidate endpoint:

```http
POST /access/api/v1/tokens HTTP/1.1
Host: <target-host>
Authorization: Bearer <service-token>
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "scope": "applied-permissions/admin",
  "audience": "*@*"
}
```

Vulnerable behavior:

- The server returns an admin-scoped or broadly privileged token.

Safer alternatives:

- Request the least-privileged scope that proves improper trust.
- If admin scope is tested, do not use it for destructive actions.
- Redact the token and report only token scope, expiry, and token ID if safe.

### Phase 4: Read-Only Impact Proof

Prefer read-only verification:

```http
GET /artifactory/api/repositories HTTP/1.1
Host: <target-host>
Authorization: Bearer <admin-or-service-token>
```

```http
GET /artifactory/api/system/version HTTP/1.1
Host: <target-host>
Authorization: Bearer <admin-or-service-token>
```

Optional, only if explicitly authorized:

- List a small sample of users.
- List a small sample of repositories.
- Confirm token scope.
- Confirm whether admin-only endpoints are reachable.

Avoid unless explicitly authorized:

- Dumping all users.
- Dumping all tokens.
- Reading secrets.
- Decrypting configuration.
- Extracting signing keys.
- Modifying repositories.
- Creating users.
- Creating persistent tokens.
- Uploading, replacing, or deleting artifacts.

## Evidence Checklist

- In-scope authorization proof.
- Target product/version evidence if available.
- Join endpoint reachability evidence.
- Forged JWT generation timestamp and freshness note.
- Join endpoint request and redacted response.
- Service-token issuance evidence with token redacted.
- Token-escalation request and redacted response, if tested.
- Minimal read-only proof of privilege.
- Network-control notes, such as WAF, Cloudflare challenge, IP allowlist, VPN requirement, or internal-only access.
- Cleanup proof and statement that no persistent access was maintained.

## Variant Testing Ideas

- Test HTTP hostnames and internal hostnames provided by the program.
- Test Artifactory base path variants with and without `/artifactory`.
- Test whether JFrog Access is served under the same host, different port, or internal hostname.
- Test whether the endpoint behaves differently through CDN, reverse proxy, origin IP, VPN, and internal network.
- Test whether `iat` format must be seconds or milliseconds.
- Test whether the JWT requires `kid`.
- Test whether unique `jti`, `service_id`, or `node_id` values affect acceptance.
- Test whether patched versions reject the blank-key signature.
- Test whether join endpoint exposure remains after WAF/CDN mitigation.

## Remediation Recommendations

- Upgrade JFrog Artifactory/JFrog Access to a version that fixes the affected blank/default join-key behavior.
- Rotate the Artifactory join key to a strong random value.
- Revoke tokens issued during the vulnerable period.
- Audit all access tokens, admin tokens, service tokens, users, groups, repositories, permissions, and recent administrative actions.
- Rotate secrets that may have been exposed through Artifactory configuration.
- Rotate signing keys if admin access could expose or misuse signing material.
- Restrict `/access/api/v1/registry/join` to trusted internal networks only.
- Place JFrog Access administrative APIs behind VPN, private networking, or strict allowlists.
- Monitor for unexpected service registration, token creation, repository changes, user creation, and configuration decryption.
- Review published artifacts for unauthorized modifications.

## Severity Guidance

Suggested severity: Critical when an unauthenticated attacker can obtain service or admin tokens and access repository administration.

Severity may increase if:

- The instance hosts production releases, package registries, containers, signing keys, customer artifacts, or deployment dependencies.
- Admin-scoped token issuance is possible.
- Repository write access is possible.
- Tokens or secrets are accessible.
- The instance serves regulated, financial, government, healthcare, or critical infrastructure software.

Severity may decrease if:

- The join endpoint is only reachable from a tightly controlled internal network.
- The join key is strong and forged tokens are rejected.
- The instance is patched.
- The returned service token has no meaningful privileges.
- Only non-production test repositories are affected.

## Final Report Skeleton

````markdown
# JFrog Artifactory Authentication Bypass via Blank or Weak Join Key

## Summary
The JFrog Access join endpoint accepted a forged trusted-service JWT, allowing unauthenticated service registration and token issuance. This may allow escalation to administrative access depending on token scope and instance configuration.

## Affected Asset
- Host:
- Product:
- Version:
- Endpoint:
- Network path tested:

## Preconditions
- Tester network position:
- Authentication required:
- Program authorization:

## Steps To Reproduce
1. Confirm the target is a JFrog Artifactory/JFrog Platform instance.
2. Generate a fresh forged join JWT using the tested blank/default/weak join-key method.
3. Immediately submit it to `/access/api/v1/registry/join`.
4. Observe whether a service token is returned.
5. Use the service token to request a minimally sufficient privileged token.
6. Verify impact using read-only API calls.

## Observed Result

## Expected Result
The join endpoint should reject forged JWTs and should not issue service tokens to unauthenticated attackers.

## Impact

## Evidence
- Request/response:
- Token metadata:
- Read-only verification:
- Screenshots/logs:

## Cleanup
- Tokens revoked or expired:
- Test artifacts removed:
- No persistent access maintained:

## Remediation
- Patch version:
- Rotate join key:
- Revoke tokens:
- Audit repositories and administrative actions:
- Restrict join endpoint:
````
