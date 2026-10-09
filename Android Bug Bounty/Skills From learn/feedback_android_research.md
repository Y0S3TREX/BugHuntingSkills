---
name: feedback_android_research
description: Karim's Android vulnerability research approach and reporting style
type: feedback
---

**Android Vulnerability Research Style:**

Karim Mohamed focuses on Android security research, particularly:
- Exported activity/component vulnerabilities
- Denial of Service (DoS) via repeated activity triggering
- Real-world exploitability PoCs (malicious app simulations)

**Reporting Approach:**
- Submits DoS reports via exported activity crashes
- Some programs accept these (e.g., Expedia report #3653257 - Triaged, Low severity)
- Uses ADB loop testing + PoC app demonstrations
- Frames reports around "real-world attack scenarios" where malicious apps trigger crashes without ADB

**What works for him:**
- Building PoC apps that demonstrate persistent triggering (Foreground Services, Handler loops)
- Reports that show attacker can replicate ADB loop behavior via malicious app
- Human-toned, concise report writing (no AI-sounding language)
- Including reproduction steps: manual ADB test → loop test → PoC app simulation

**Key insight:**
Programs vary on DoS acceptance. When accepted, framing matters: emphasize "malicious app can do this without ADB" and "persistent disruption for users."
