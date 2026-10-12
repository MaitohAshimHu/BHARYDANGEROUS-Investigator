# Security Policy for BHARYDANGEROUS-Investigator

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability or potential parser exploit in **BHARYDANGEROUS-Investigator**, please report it responsibly:

- **Email:** `security@bharydangerous.org`
- Do **not** open a public GitHub issue for undisclosed vulnerabilities.
- Provide full reproduction steps, proof-of-concept evidence artifacts, and affected platform details.
- We will acknowledge receipt within 48 hours and coordinate a coordinated disclosure timeline.

## Threat Model & Security Posture

BHARYDANGEROUS-Investigator is designed defensively against adversarial forensic evidence:

- **Decompression Bombs:** Strict quotas on file expansion ratios (100:1 max), archive entry counts (10,000 max), and extracted bytes (2 GB max).
- **Path Traversal:** Strict path sanitization on archives and carved files to prevent escaping the case workspace.
- **Subprocess Security:** Absolute prohibition of `shell=True`. Arguments are passed as explicit arrays with controlled working directories and strict timeouts.
- **AI Prompt Injection:** All evidence text is wrapped in `<untrusted_evidence_data>` delimiters with system instructions to disregard embedded directives.
- **Data Leakage Safeguards:** Automatic regex redactor for passwords, API tokens, and private keys before any optional AI transmission, backed by an interactive consent gate.
