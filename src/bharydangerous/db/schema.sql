-- BHARYDANGEROUS-Investigator Master Database Schema
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- Cases Table
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    investigator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('OPEN', 'ACTIVE', 'LOCKED', 'CLOSED')),
    description TEXT,
    workspace_path TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}'
);

-- Evidence Table
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    evidence_type TEXT NOT NULL CHECK(evidence_type IN ('FILE', 'DISK_IMAGE', 'MEMORY_DUMP', 'PCAP', 'LOG_FILE', 'DIRECTORY')),
    source_path TEXT NOT NULL,
    stored_path TEXT,
    file_size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL,
    intake_timestamp TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    verification_status TEXT NOT NULL CHECK(verification_status IN ('VERIFIED', 'MISMATCH', 'UNCHECKED')),
    metadata_json TEXT DEFAULT '{}'
);

-- Cryptographic Chain of Custody
CREATE TABLE IF NOT EXISTS chain_of_custody (
    log_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    recorded_hash TEXT NOT NULL,
    details_json TEXT DEFAULT '{}'
);

-- Extracted Forensic Artifacts
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    artifact_type TEXT NOT NULL,
    name TEXT NOT NULL,
    location_path TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT,
    metadata_json TEXT DEFAULT '{}',
    extracted_at TEXT NOT NULL
);

-- Normalized Forensic Findings
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    artifact_id TEXT REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('MALWARE', 'PERSISTENCE', 'PRIV_ESC', 'LATERAL_MOVEMENT', 'CREDENTIAL_ACCESS', 'DATA_EXFIL', 'SUSPICIOUS_EXEC', 'ANOMALY', 'INFO')),
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    confidence TEXT NOT NULL CHECK(confidence IN ('CONFIRMED_FACT', 'HEURISTIC_DETECTION', 'HYPOTHESIS')),
    facts_json TEXT NOT NULL,
    analyst_notes TEXT,
    source_artifact TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Unified Timeline Events
CREATE TABLE IF NOT EXISTS timeline_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    timestamp_desc TEXT NOT NULL,
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    actor TEXT,
    target TEXT,
    raw_record_json TEXT NOT NULL,
    normalized_json TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline_case ON timeline_events(case_id);

-- Correlated Incident Incidents
CREATE TABLE IF NOT EXISTS correlations (
    correlation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    score REAL NOT NULL,
    event_ids_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL
);

-- AI Explanations and Audits
CREATE TABLE IF NOT EXISTS ai_annotations (
    annotation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK(target_type IN ('CASE_SUMMARY', 'FINDING_EXPLANATION', 'TIMELINE_ANALYSIS', 'NEXT_STEPS')),
    target_id TEXT,
    model_identifier TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    sanitized_prompt_preview TEXT NOT NULL,
    response_text TEXT NOT NULL,
    cited_finding_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
