# Bug Bounty Report Templates

A reusable collection of bug bounty vulnerability report templates designed for AI-assisted reporting across different tools and models.

## Purpose

This repository provides structured, reusable templates for writing accurate, concise, professional security vulnerability reports.

It can be used with Claude, ChatGPT, Claude Code, coding agents, and other AI assistants that can access repository files.

## Instructions for AI Assistants

When asked to write or improve a bug bounty report:

1. Identify the vulnerability class and the demonstrated attack scenario.
2. Search `templates/` for the closest matching template.
3. Read the complete template before drafting the report.
4. Preserve the template's structure and wording wherever possible.
5. Replace placeholders only with information supported by the supplied evidence.
6. Request missing critical information when it is necessary to establish exploitability or impact.
7. Never invent endpoints, parameters, responses, screenshots, reproduction steps, affected assets, or security impact.
8. Distinguish confirmed impact from potential impact and unverified assumptions.
9. Recommend severity based on demonstrated exploitability, affected assets, privileges required, and actual security consequences.
10. Follow the target program's submission requirements when they are provided.

## Template Selection

- Prefer an exact vulnerability-specific template when available.
- If no exact match exists, use the closest relevant template and adapt it carefully.
- Do not combine unrelated templates unless the attack scenario requires it.
- Do not silently discard important sections from an existing template.
- If no suitable template exists, use the general report structure and identify the need for a new template.

## Reporting Standards

A report should clearly explain:

- Title
- Summary
- Affected asset or component
- Preconditions and required privileges
- Steps to reproduce
- Proof of concept and observed results
- Security impact
- Remediation recommendations
- References, where relevant

Use only sections that are appropriate to the selected template and the target program's requirements.

## Evidence and Impact

A vulnerability classification alone does not establish its severity.

For example, the presence of an exported Android activity or a custom deep link scheme does not, by itself, prove account takeover. Demonstrate the actual security consequence before claiming sensitive data exposure, token theft, authentication bypass, or account compromise.

If the impact is not demonstrated, describe the limitation honestly rather than overstating the finding.

## Writing Style

- Be concise, technical, and professional.
- Prefer direct language and reproducible instructions.
- Avoid marketing language, exaggerated claims, and unnecessary filler.
- Do not use emojis in security reports.
- Preserve technical accuracy and the researcher's intended meaning.

## Output Requirements

Return a complete report ready for review and submission.

Do not include unsupported claims or silently fabricate missing details. Clearly flag any placeholders or missing evidence that still require the researcher's input.

## Source of Truth

The vulnerability-specific template is the primary reference for its report structure. These instructions provide general rules for selecting and using templates.

If instructions conflict, follow the target program's requirements, preserve factual accuracy, and avoid unsupported claims.
