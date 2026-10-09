# Vulnerability Chaining Playbook

## Mandatory Chaining Check

For EVERY finding, answer:

1. Is this exploitable alone?
2. Can this be combined with another issue?
3. What is the full attack chain from entry to impact?

---

## Chain Patterns

### Low -> Critical Escalation Paths

| Start With | Chain With | End Result |
|---|---|---|
| Exported Activity | Intent redirect / deeplink hijack | Arbitrary component access |
| Content Provider leak | Path traversal | Arbitrary file read |
| Arbitrary file read | Token/cookie theft | Account Takeover |
| WebView with JS enabled | JS bridge exploitation | RCE / data theft |
| WebView file access | `file://` scheme + universal access | Cross-origin data theft |
| Implicit Intent | Intent interception | Credential theft / MITM |
| Insecure deep link | Auto-verify bypass | Phishing / session hijack |
| Exported Service | Binder exploitation | Privilege escalation |
| Debuggable app | Runtime attachment | Full app compromise |
| Backup enabled | adb backup extraction | Credential / token theft |
| Cleartext traffic | Network MITM | Session hijack / injection |
| Weak crypto / hardcoded keys | Decrypt stored data | Data breach |
| PendingIntent misuse | Intent hijack | Privilege escalation |
| Task affinity misconfiguration | StrandHogg / task hijack | UI spoofing / credential theft |

### Chain Evaluation Questions

Ask these for every finding:

- Can one issue expose another hidden endpoint?
- Can a low-impact leak lead to authentication bypass?
- Can a file read lead to token theft?
- Can a WebView issue escalate into account takeover?
- Can exported components be combined into privilege escalation?
- Can API misuse + client-side trust issues create full compromise?
- Can a race condition widen a narrow vulnerability?
- Can a permission bypass chain with a data leak?

---

## Real-World Chain Examples

### Chain 1: Exported Activity -> Intent Redirect -> Arbitrary Component Access
1. Attacker sends crafted intent to exported activity
2. Activity reads an extra (`intent`, `url`, `next`) and forwards it
3. Attacker-controlled intent reaches internal (non-exported) component
4. Internal component performs privileged action

### Chain 2: Content Provider + Path Traversal -> File Theft -> ATO
1. Content provider exports a file-serving URI
2. Path traversal via `../` in URI reaches app private directory
3. Attacker reads `shared_prefs/auth_token.xml`
4. Token reused for account takeover

### Chain 3: Deep Link -> WebView -> JS Bridge -> RCE
1. Attacker crafts deep link that opens a WebView
2. WebView loads attacker-controlled URL (no URL validation)
3. JavaScript bridge exposes sensitive methods
4. Attacker calls bridge method to execute code or exfiltrate data

### Chain 4: Implicit Broadcast + PendingIntent -> Privilege Escalation
1. App sends implicit broadcast containing a PendingIntent
2. Attacker app registers receiver for that broadcast
3. Attacker modifies PendingIntent extras/action
4. Modified intent executes with the victim app's permissions
