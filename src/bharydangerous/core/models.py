"""Data models for BHARYDANGEROUS-Investigator."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

def current_utc_iso() -> str:
    """Return current timestamp in ISO-8601 UTC."""
    return datetime.now(timezone.utc).isoformat()

class CaseRecord(BaseModel):
    case_id: str
    name: str
    investigator: str
    created_at: str = Field(default_factory=current_utc_iso)
    status: str = "OPEN"
    description: Optional[str] = None
    workspace_path: str
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

class EvidenceRecord(BaseModel):
    evidence_id: str
    case_id: str
    label: str
    evidence_type: str  # FILE, DISK_IMAGE, MEMORY_DUMP, PCAP, LOG_FILE, DIRECTORY
    source_path: str
    stored_path: Optional[str] = None
    file_size_bytes: int
    sha256: str
    md5: str
    intake_timestamp: str = Field(default_factory=current_utc_iso)
    verified_at: str = Field(default_factory=current_utc_iso)
    verification_status: str = "VERIFIED"  # VERIFIED, MISMATCH, UNCHECKED
    metadata_json: Dict[str, Any] = Field(default_factory=dict)

class ChainOfCustodyRecord(BaseModel):
    log_id: str
    evidence_id: str
    action: str
    performed_by: str
    timestamp: str = Field(default_factory=current_utc_iso)
    recorded_hash: str
    details_json: Dict[str, Any] = Field(default_factory=dict)

class ArtifactRecord(BaseModel):
    artifact_id: str
    evidence_id: str
    artifact_type: str
    name: str
    location_path: str
    mime_type: Optional[str] = None
    size_bytes: int
    sha256: Optional[str] = None
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    extracted_at: str = Field(default_factory=current_utc_iso)

class FindingRecord(BaseModel):
    finding_id: str
    evidence_id: str
    artifact_id: Optional[str] = None
    title: str
    category: str  # MALWARE, PERSISTENCE, PRIV_ESC, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence: str  # CONFIRMED_FACT, HEURISTIC_DETECTION, HYPOTHESIS
    facts_json: Dict[str, Any] = Field(default_factory=dict)
    analyst_notes: Optional[str] = None
    source_artifact: str
    created_at: str = Field(default_factory=current_utc_iso)

class TimelineEventRecord(BaseModel):
    event_id: str
    case_id: str
    evidence_id: str
    timestamp: str
    timestamp_desc: str  # e.g., 'mtime', 'logon_time', 'packet_time'
    source_type: str  # EVTX, SYSLOG, PCAP, FILESYSTEM, etc.
    event_type: str
    summary: str
    actor: Optional[str] = None
    target: Optional[str] = None
    raw_record_json: Dict[str, Any] = Field(default_factory=dict)
    normalized_json: Dict[str, Any] = Field(default_factory=dict)

class CorrelationRecord(BaseModel):
    correlation_id: str
    case_id: str
    rule_name: str
    score: float
    event_ids: List[str] = Field(default_factory=list)
    summary: str
    details_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=current_utc_iso)

class AIAnnotationRecord(BaseModel):
    annotation_id: str
    case_id: str
    target_type: str  # CASE_SUMMARY, FINDING_EXPLANATION, TIMELINE_ANALYSIS, NEXT_STEPS
    target_id: Optional[str] = None
    model_identifier: str
    prompt_hash: str
    sanitized_prompt_preview: str
    response_text: str
    cited_finding_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=current_utc_iso)

class DoctorCheckResult(BaseModel):
    category: str
    name: str
    status: str  # OK, MISSING, WARNING, OPTIONAL
    details: str
    remediation: Optional[str] = None

class ReportModel(BaseModel):
    product_name: str
    version: str
    generated_at: str = Field(default_factory=current_utc_iso)
    case: CaseRecord
    evidence_list: List[EvidenceRecord] = Field(default_factory=list)
    findings_list: List[FindingRecord] = Field(default_factory=list)
    timeline_summary: Dict[str, Any] = Field(default_factory=dict)
    correlations: List[CorrelationRecord] = Field(default_factory=list)
    ai_annotations: List[AIAnnotationRecord] = Field(default_factory=list)
    tool_diagnostics: List[DoctorCheckResult] = Field(default_factory=list)
