# BHARYDANGEROUS-Investigator — CLI Command Reference

All commands are accessed via the `bdinvestigator` (or `bharydangerous`) executable.

---

## 1. Global & Diagnostic Commands

### `bdinvestigator --help`
Displays top-level command groups and global options.

### `bdinvestigator version`
Outputs tool version, creator (Ashim), and branding.

### `bdinvestigator doctor`
Inspects system health, Python environment, standard libraries, and external forensic tool availability.

### `bdinvestigator plugins`
Lists all loaded community and third-party forensic plugins.

---

## 2. Case Management (`bdinvestigator case`)

### `bdinvestigator case create`
Initialize a new forensic case and create the SQLite database.
- `--name, -n`: Case name (Required).
- `--investigator, -i`: Lead investigator name (Default: `Ashim`).
- `--workspace, -w`: Workspace directory (Default: `.`).
- `--description, -d`: Case description.

### `bdinvestigator case list`
Lists all cases recorded in the workspace database.

### `bdinvestigator case info`
Displays detailed case parameters, paths, and creation timestamps.

---

## 3. Evidence Management (`bdinvestigator evidence`)

### `bdinvestigator evidence add <PATH>`
Ingests evidence in read-only mode, streams SHA-256 and MD5 hashes, and records chain of custody.
- `--label, -l`: Descriptive label (Required).
- `--type, -t`: Evidence type (`FILE`, `DISK_IMAGE`, `MEMORY_DUMP`, `PCAP`, `LOG_FILE`).
- `--case, -c`: Specific Case ID (defaults to latest).
- `--investigator, -i`: Analyst performing intake.

### `bdinvestigator evidence verify`
Re-calculates cryptographic hashes for all evidence files and checks for tampering.

### `bdinvestigator evidence list`
Tabulates evidence inventory, sizes, and verification statuses.

---

## 4. Forensic Analyzers (`bdinvestigator analyze`)

### `bdinvestigator analyze triage <PATH>`
Calculates Shannon entropy, detects MIME/file types, and checks binary headers.
- `--strings, -s`: Extract printable strings and regex IOCs (IP, URL, email, GUID, Base64).

### `bdinvestigator analyze logs <PATH>`
Parses log files into normalized timeline events.
- `--format, -f`: `auto`, `evtx`, `syslog`, `web`.

### `bdinvestigator analyze disk <PATH>`
Inspects partition tables (MBR/GPT) and filesystems.

### `bdinvestigator analyze memory <PATH>`
Analyzes memory dumps using Volatility 3 or native string/header anomaly scanning.

### `bdinvestigator analyze pcap <PATH>`
Dissects network captures for conversations, DNS queries, HTTP requests, and cleartext credentials.

### `bdinvestigator analyze yara <PATH>`
Scans files or directories against default or custom forensic YARA rules.
- `--rules, -r`: Path to custom `.yar` rule file.

---

## 5. Timeline & Correlation (`bdinvestigator timeline`)

### `bdinvestigator timeline build`
Compiles chronological timeline and executes cross-artifact correlation rules.

### `bdinvestigator timeline query`
Queries timeline events.
- `--limit, -n`: Number of events to display (Default: `50`).
- `--source, -s`: Filter by source type (`EVTX`, `SYSLOG`, `PCAP`, `WEBLOG`).

---

## 6. AI Reasoning (`bdinvestigator ai`)

### `bdinvestigator ai explain`
Generates structured technical analysis for a specific finding.
- `--finding, -f`: Target Finding ID (e.g. `FND-001`) (Required).
- `--provider, -p`: `gemini` (default), `ollama`, or `mock`.
- `--consent-ai-upload`: Non-interactive consent flag.

### `bdinvestigator ai summarize`
Synthesizes comprehensive executive and technical summary of all case findings.
- `--provider, -p`: `gemini`, `ollama`, or `mock`.
- `--consent-ai-upload`: Non-interactive consent flag.

---

## 7. Report Generation (`bdinvestigator report`)

### `bdinvestigator report generate`
Exports complete forensic investigation report.
- `--format, -f`: `json`, `md`, `html`, or `all` (Default: `all`).
- `--output-dir, -o`: Directory to save report files (Default: `./exports`).
