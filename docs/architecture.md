# BHARYDANGEROUS-Investigator — System Architecture

**Creator:** Ashim  
**Version:** 1.0.0  
**License:** MIT  

---

## 1. Architectural Layers

BHARYDANGEROUS-Investigator is built as a layered, modular forensic engine:

1. **Presentation & CLI Layer (`src/bharydangerous/cli/`):**
   - Built with **Typer** and **Rich**.
   - Structured sub-commands (`doctor`, `case`, `evidence`, `analyze`, `timeline`, `ai`, `report`).
   - Clean tabular and tree output with color-coded severity badges.

2. **Core Domain & Models (`src/bharydangerous/core/`):**
   - Strict Pydantic models enforcing schema validation for Cases, Evidence, Chain of Custody, Artifacts, Findings, Timeline Events, Correlations, and AI Annotations.
   - Streaming, unbuffered cryptographic hashing (SHA-256 and MD5).
   - Safe path resolvers preventing path traversal and directory escapes.

3. **Storage & Persistence Layer (`src/bharydangerous/db/`):**
   - Built-in zero-dependency **SQLite** database configured with **Write-Ahead Logging (`WAL`)** mode and foreign key enforcement.
   - Specialized repositories for atomic transactions, batch insertions, and filtered timeline queries.

4. **Forensic Analyzers & Adapters (`src/bharydangerous/analyzers/` & `src/bharydangerous/adapters/`):**
   - Decoupled adapters wrapping external forensic binaries (The Sleuth Kit, Volatility 3, TShark, YARA) via safe subprocess arrays (no `shell=True`, timeouts, memory-bounded output).
   - Pure-Python fallback engines for partition parsing (MBR/GPT), memory triage, PCAP dissection, and YARA signature matching.

5. **Timeline & Correlation Engine (`src/bharydangerous/correlation/`):**
   - Heterogeneous timestamp normalization to ISO-8601 UTC.
   - Multi-stage cross-artifact correlation rules (brute-force attacks, webshell deployment to execution, rapid privilege escalation, repetitive DNS beaconing).

6. **AI Reasoning Layer (`src/bharydangerous/ai/`):**
   - Provider interface supporting hosted Google Gemini API (`gemini-2.5-flash`), local Ollama instances, and deterministic offline mock engines.
   - Mandatory interactive consent gate and PII/secret redactor.
   - Finding ID grounding validator ensuring LLM answers strictly reference verified evidence.

7. **Reporting Engine (`src/bharydangerous/reporting/`):**
   - Multi-format generation: strict JSON, structured Markdown, and standalone zero-CDN HTML.
