# BHARYDANGEROUS-Investigator

> **A modular, production-grade, AI-assisted digital forensics and incident response (DFIR) CLI created by Ashim for the cybersecurity community.**

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Forensics Ready](https://img.shields.io/badge/evidence-immutable%20read--only-red.svg)]()

---

## Overview

**BHARYDANGEROUS-Investigator** automates digital forensic intake, triage, timeline construction, cross-artifact incident correlation, and reporting. Built with high-performance Python 3.11+, Typer, Rich, and SQLite (WAL mode), it operates **100% offline and air-gapped** by default while offering optional hosted AI reasoning via Google Gemini Developer API (`gemini-2.5-flash`) or local Ollama instances.

### Key Capabilities

1. **Case Management & Evidence Vault:** Multi-case workspace isolation, cryptographic chain-of-custody logging, and read-only unbuffered streaming SHA-256 and MD5 intake.
2. **File & Archive Triage:** MIME detection, PE/ELF/Mach-O header sniffing, Shannon entropy calculation, string/IOC extraction, and bomb-protected archive inspection (ratio, entry, and size quotas).
3. **Multi-Source Log Analysis:** Windows Event Logs (EVTX / XML), Linux syslog / auth.log / sudo execution, and web server access logs (Apache / Nginx / IIS) with automated SQLi and webshell detection.
4. **Network Forensics:** Deep packet dissection for PCAP/PCAPNG, conversation metrics, DNS queries, HTTP sessions, and unencrypted credential sniffing.
5. **Disk & Memory Adapters:** The Sleuth Kit (`fls`, `fsstat`, `mmls`) and Volatility 3 (`vol`) integration with pure-Python partition and memory triage fallbacks.
6. **Timeline & Incident Correlation:** Normalized ISO-8601 UTC timelines with automated multi-stage correlation (e.g. brute-force logons, webshell upload -> command execution).
7. **AI Reasoning with Guardrails:** Finding explanations, technical hypotheses, and executive summaries with strict PII/secret redaction, mandatory consent preview, prompt injection isolation, and grounded citation verification.
8. **Multi-Format Reporting:** Publication-ready JSON, Markdown, and standalone, zero-CDN, responsive HTML reports.

---

## Installation

### Linux & macOS
```bash
git clone https://github.com/MaitohAshimHu/BHARYDANGEROUS-Investigator.git
cd BHARYDANGEROUS-Investigator
bash scripts/install_linux_macos.sh
source .venv/bin/activate
```

### Windows (PowerShell)
```powershell
git clone https://github.com/MaitohAshimHu/BHARYDANGEROUS-Investigator.git
cd BHARYDANGEROUS-Investigator
.\scripts\install_windows.ps1
.\.venv\Scripts\Activate.ps1
```

### Verification & Diagnostics
Run the system doctor to inspect your Python runtime and forensic utilities:
```bash
bdinvestigator doctor
```

---

## Quickstart Investigation Walkthrough

### 1. Initialize a Forensic Case
```bash
bdinvestigator case create --name "Incident-Alpha" --investigator "Ashim" --description "Suspected web server breach"
```

### 2. Ingest Evidence (Read-Only)
```bash
bdinvestigator evidence add /path/to/evidence.pcap --label "EgressTraffic" --type PCAP
bdinvestigator evidence add /path/to/security.evtx --label "DC01_SecurityLogs" --type LOG_FILE
bdinvestigator evidence verify
```

### 3. Execute Specialized Analyzers
```bash
# File triage & string extraction
bdinvestigator analyze triage /path/to/suspicious_sample.bin --strings

# Windows and Linux logs (EVTX, Syslog, Web logs)
bdinvestigator analyze logs /path/to/security.evtx

# Partition inspection (The Sleuth Kit or pure-Python MBR parser)
bdinvestigator analyze disk /path/to/disk_image.raw

# Memory forensics (Volatility 3 or native heuristic memory scanning)
bdinvestigator analyze memory /path/to/memory_dump.raw

# Network PCAP dissection & credential sniffing
bdinvestigator analyze pcap /path/to/evidence.pcap

# YARA signature pattern scanning
bdinvestigator analyze yara /path/to/target_directory/
```

### 4. Build Unified Timeline & Cross-Artifact Correlations
```bash
bdinvestigator timeline build
bdinvestigator timeline query --limit 20
```

### 5. AI-Assisted Reasoning (Optional & Consent-Gated)
Configure your Gemini API key (optional, stored with restricted permissions):
```bash
# Via CLI config command:
bdinvestigator config set-api-key "your-api-key"

# Or via environment variable:
export GEMINI_API_KEY="your-api-key"
```

Inspect active configuration & environment:
```bash
bdinvestigator config show
```

Explain a specific finding or summarize the entire case:
```bash
bdinvestigator ai explain --finding FND-001 --consent-ai-upload
bdinvestigator ai summarize --consent-ai-upload
```
*(Deterministic offline Mock and Local Ollama providers are available via `--provider mock` or `--provider ollama`)*

### 6. Generate Forensic Reports
```bash
bdinvestigator report generate --format all --output-dir ./exports
```
Generates `./exports/incident-alpha_report.json`, `./exports/incident-alpha_report.md`, and `./exports/incident-alpha_report.html` (100% self-contained for air-gapped viewing).

---

## Forensic Integrity & Epistemic Separation

BHARYDANGEROUS-Investigator enforces strict separation of:
- **Facts:** Cryptographic hashes, byte offsets, file sizes, and raw log records.
- **Heuristic Detections:** YARA rule matches, entropy flags (>7.2), anomaly thresholds.
- **Hypotheses:** Cross-artifact correlation patterns.
- **AI Interpretations:** LLM-generated summaries, strictly citing verified `[FND-XXXX]` finding IDs.

---

## License

Created by **Ashim**. Distributed under the [MIT License](LICENSE).
