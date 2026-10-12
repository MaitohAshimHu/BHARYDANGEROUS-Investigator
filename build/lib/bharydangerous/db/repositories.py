"""Data access repositories for forensic entities."""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import sqlite3

from bharydangerous.core.models import (
    CaseRecord,
    EvidenceRecord,
    ChainOfCustodyRecord,
    ArtifactRecord,
    FindingRecord,
    TimelineEventRecord,
    CorrelationRecord,
    AIAnnotationRecord,
)

class BaseRepository:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)

    def _get_conn(self) -> sqlite3.Connection:
        from bharydangerous.db.connection import get_db_connection
        return get_db_connection(self.db_path)

class CaseRepository(BaseRepository):
    def create(self, case: CaseRecord) -> CaseRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO cases (case_id, name, investigator, created_at, status, description, workspace_path, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    case.case_id,
                    case.name,
                    case.investigator,
                    case.created_at,
                    case.status,
                    case.description,
                    case.workspace_path,
                    json.dumps(case.metadata_json),
                ),
            )
            conn.commit()
        return case

    def get_by_id(self, case_id: str) -> Optional[CaseRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM cases WHERE case_id = ?;", (case_id,))
            row = cur.fetchone()
            if not row:
                return None
            return CaseRecord(
                case_id=row["case_id"],
                name=row["name"],
                investigator=row["investigator"],
                created_at=row["created_at"],
                status=row["status"],
                description=row["description"],
                workspace_path=row["workspace_path"],
                metadata_json=json.loads(row["metadata_json"] or "{}"),
            )
        finally:
            conn.close()

    def list_all(self) -> List[CaseRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM cases ORDER BY created_at DESC;")
            results = []
            for row in cur.fetchall():
                results.append(
                    CaseRecord(
                        case_id=row["case_id"],
                        name=row["name"],
                        investigator=row["investigator"],
                        created_at=row["created_at"],
                        status=row["status"],
                        description=row["description"],
                        workspace_path=row["workspace_path"],
                        metadata_json=json.loads(row["metadata_json"] or "{}"),
                    )
                )
            return results
        finally:
            conn.close()

    def update_status(self, case_id: str, new_status: str) -> None:
        with self._get_conn() as conn:
            conn.execute("UPDATE cases SET status = ? WHERE case_id = ?;", (new_status, case_id))
            conn.commit()

class EvidenceRepository(BaseRepository):
    def add(self, ev: EvidenceRecord) -> EvidenceRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO evidence (
                    evidence_id, case_id, label, evidence_type, source_path, stored_path,
                    file_size_bytes, sha256, md5, intake_timestamp, verified_at,
                    verification_status, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    ev.evidence_id,
                    ev.case_id,
                    ev.label,
                    ev.evidence_type,
                    ev.source_path,
                    ev.stored_path,
                    ev.file_size_bytes,
                    ev.sha256,
                    ev.md5,
                    ev.intake_timestamp,
                    ev.verified_at,
                    ev.verification_status,
                    json.dumps(ev.metadata_json),
                ),
            )
            conn.commit()
        return ev

    def get_by_id(self, evidence_id: str) -> Optional[EvidenceRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM evidence WHERE evidence_id = ?;", (evidence_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_record(row)
        finally:
            conn.close()

    def list_by_case(self, case_id: str) -> List[EvidenceRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY intake_timestamp ASC;", (case_id,))
            return [self._row_to_record(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def update_verification(self, evidence_id: str, status: str, verified_at: str) -> None:
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE evidence SET verification_status = ?, verified_at = ? WHERE evidence_id = ?;",
                (status, verified_at, evidence_id),
            )
            conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=row["evidence_id"],
            case_id=row["case_id"],
            label=row["label"],
            evidence_type=row["evidence_type"],
            source_path=row["source_path"],
            stored_path=row["stored_path"],
            file_size_bytes=row["file_size_bytes"],
            sha256=row["sha256"],
            md5=row["md5"],
            intake_timestamp=row["intake_timestamp"],
            verified_at=row["verified_at"],
            verification_status=row["verification_status"],
            metadata_json=json.loads(row["metadata_json"] or "{}"),
        )

class ChainOfCustodyRepository(BaseRepository):
    def record(self, coc: ChainOfCustodyRecord) -> ChainOfCustodyRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO chain_of_custody (log_id, evidence_id, action, performed_by, timestamp, recorded_hash, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    coc.log_id,
                    coc.evidence_id,
                    coc.action,
                    coc.performed_by,
                    coc.timestamp,
                    coc.recorded_hash,
                    json.dumps(coc.details_json),
                ),
            )
            conn.commit()
        return coc

    def list_by_evidence(self, evidence_id: str) -> List[ChainOfCustodyRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM chain_of_custody WHERE evidence_id = ? ORDER BY timestamp ASC;", (evidence_id,))
            records = []
            for row in cur.fetchall():
                records.append(
                    ChainOfCustodyRecord(
                        log_id=row["log_id"],
                        evidence_id=row["evidence_id"],
                        action=row["action"],
                        performed_by=row["performed_by"],
                        timestamp=row["timestamp"],
                        recorded_hash=row["recorded_hash"],
                        details_json=json.loads(row["details_json"] or "{}"),
                    )
                )
            return records
        finally:
            conn.close()

class ArtifactRepository(BaseRepository):
    def add(self, art: ArtifactRecord) -> ArtifactRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (artifact_id, evidence_id, artifact_type, name, location_path, mime_type, size_bytes, sha256, metadata_json, extracted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    art.artifact_id,
                    art.evidence_id,
                    art.artifact_type,
                    art.name,
                    art.location_path,
                    art.mime_type,
                    art.size_bytes,
                    art.sha256,
                    json.dumps(art.metadata_json),
                    art.extracted_at,
                ),
            )
            conn.commit()
        return art

    def list_by_evidence(self, evidence_id: str) -> List[ArtifactRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM artifacts WHERE evidence_id = ? ORDER BY extracted_at ASC;", (evidence_id,))
            return [
                ArtifactRecord(
                    artifact_id=row["artifact_id"],
                    evidence_id=row["evidence_id"],
                    artifact_type=row["artifact_type"],
                    name=row["name"],
                    location_path=row["location_path"],
                    mime_type=row["mime_type"],
                    size_bytes=row["size_bytes"],
                    sha256=row["sha256"],
                    metadata_json=json.loads(row["metadata_json"] or "{}"),
                    extracted_at=row["extracted_at"],
                )
                for row in cur.fetchall()
            ]
        finally:
            conn.close()

class FindingRepository(BaseRepository):
    def add(self, finding: FindingRecord) -> FindingRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO findings (finding_id, evidence_id, artifact_id, title, category, severity, confidence, facts_json, analyst_notes, source_artifact, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    finding.finding_id,
                    finding.evidence_id,
                    finding.artifact_id,
                    finding.title,
                    finding.category,
                    finding.severity,
                    finding.confidence,
                    json.dumps(finding.facts_json),
                    finding.analyst_notes,
                    finding.source_artifact,
                    finding.created_at,
                ),
            )
            conn.commit()
        return finding

    def get_by_id(self, finding_id: str) -> Optional[FindingRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM findings WHERE finding_id = ?;", (finding_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_finding(row)
        finally:
            conn.close()

    def list_by_case(self, case_id: str) -> List[FindingRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT f.* FROM findings f
                JOIN evidence e ON f.evidence_id = e.evidence_id
                WHERE e.case_id = ?
                ORDER BY f.created_at ASC;
                """,
                (case_id,),
            )
            return [self._row_to_finding(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def list_by_evidence(self, evidence_id: str) -> List[FindingRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM findings WHERE evidence_id = ? ORDER BY created_at ASC;", (evidence_id,))
            return [self._row_to_finding(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def _row_to_finding(self, row: sqlite3.Row) -> FindingRecord:
        return FindingRecord(
            finding_id=row["finding_id"],
            evidence_id=row["evidence_id"],
            artifact_id=row["artifact_id"],
            title=row["title"],
            category=row["category"],
            severity=row["severity"],
            confidence=row["confidence"],
            facts_json=json.loads(row["facts_json"] or "{}"),
            analyst_notes=row["analyst_notes"],
            source_artifact=row["source_artifact"],
            created_at=row["created_at"],
        )

class TimelineRepository(BaseRepository):
    def add(self, event: TimelineEventRecord) -> TimelineEventRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO timeline_events (event_id, case_id, evidence_id, timestamp, timestamp_desc, source_type, event_type, summary, actor, target, raw_record_json, normalized_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.event_id,
                    event.case_id,
                    event.evidence_id,
                    event.timestamp,
                    event.timestamp_desc,
                    event.source_type,
                    event.event_type,
                    event.summary,
                    event.actor,
                    event.target,
                    json.dumps(event.raw_record_json),
                    json.dumps(event.normalized_json),
                ),
            )
            conn.commit()
        return event

    def add_batch(self, events: List[TimelineEventRecord]) -> None:
        if not events:
            return
        with self._get_conn() as conn:
            conn.executemany(
                """
                INSERT INTO timeline_events (event_id, case_id, evidence_id, timestamp, timestamp_desc, source_type, event_type, summary, actor, target, raw_record_json, normalized_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                [
                    (
                        e.event_id,
                        e.case_id,
                        e.evidence_id,
                        e.timestamp,
                        e.timestamp_desc,
                        e.source_type,
                        e.event_type,
                        e.summary,
                        e.actor,
                        e.target,
                        json.dumps(e.raw_record_json),
                        json.dumps(e.normalized_json),
                    )
                    for e in events
                ],
            )
            conn.commit()

    def list_by_case(
        self,
        case_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        source_type: Optional[str] = None,
        limit: int = 1000,
    ) -> List[TimelineEventRecord]:
        conn = self._get_conn()
        try:
            query = "SELECT * FROM timeline_events WHERE case_id = ?"
            params: List[Any] = [case_id]
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            if source_type:
                query += " AND source_type = ?"
                params.append(source_type)
            query += " ORDER BY timestamp ASC LIMIT ?"
            params.append(limit)

            cur = conn.cursor()
            cur.execute(query, params)
            return [
                TimelineEventRecord(
                    event_id=r["event_id"],
                    case_id=r["case_id"],
                    evidence_id=r["evidence_id"],
                    timestamp=r["timestamp"],
                    timestamp_desc=r["timestamp_desc"],
                    source_type=r["source_type"],
                    event_type=r["event_type"],
                    summary=r["summary"],
                    actor=r["actor"],
                    target=r["target"],
                    raw_record_json=json.loads(r["raw_record_json"] or "{}"),
                    normalized_json=json.loads(r["normalized_json"] or "{}"),
                )
                for r in cur.fetchall()
            ]
        finally:
            conn.close()

    def count_by_case(self, case_id: str) -> int:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM timeline_events WHERE case_id = ?;", (case_id,))
            return cur.fetchone()[0]
        finally:
            conn.close()

class CorrelationRepository(BaseRepository):
    def add(self, corr: CorrelationRecord) -> CorrelationRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO correlations (correlation_id, case_id, rule_name, score, event_ids_json, summary, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    corr.correlation_id,
                    corr.case_id,
                    corr.rule_name,
                    corr.score,
                    json.dumps(corr.event_ids),
                    corr.summary,
                    json.dumps(corr.details_json),
                    corr.created_at,
                ),
            )
            conn.commit()
        return corr

    def list_by_case(self, case_id: str) -> List[CorrelationRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM correlations WHERE case_id = ? ORDER BY score DESC, created_at ASC;", (case_id,))
            return [
                CorrelationRecord(
                    correlation_id=r["correlation_id"],
                    case_id=r["case_id"],
                    rule_name=r["rule_name"],
                    score=r["score"],
                    event_ids=json.loads(r["event_ids_json"] or "[]"),
                    summary=r["summary"],
                    details_json=json.loads(r["details_json"] or "{}"),
                    created_at=r["created_at"],
                )
                for r in cur.fetchall()
            ]
        finally:
            conn.close()

class AIAnnotationRepository(BaseRepository):
    def add(self, annot: AIAnnotationRecord) -> AIAnnotationRecord:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO ai_annotations (annotation_id, case_id, target_type, target_id, model_identifier, prompt_hash, sanitized_prompt_preview, response_text, cited_finding_ids_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    annot.annotation_id,
                    annot.case_id,
                    annot.target_type,
                    annot.target_id,
                    annot.model_identifier,
                    annot.prompt_hash,
                    annot.sanitized_prompt_preview,
                    annot.response_text,
                    json.dumps(annot.cited_finding_ids),
                    annot.created_at,
                ),
            )
            conn.commit()
        return annot

    def list_by_case(self, case_id: str) -> List[AIAnnotationRecord]:
        conn = self._get_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM ai_annotations WHERE case_id = ? ORDER BY created_at ASC;", (case_id,))
            return [
                AIAnnotationRecord(
                    annotation_id=r["annotation_id"],
                    case_id=r["case_id"],
                    target_type=r["target_type"],
                    target_id=r["target_id"],
                    model_identifier=r["model_identifier"],
                    prompt_hash=r["prompt_hash"],
                    sanitized_prompt_preview=r["sanitized_prompt_preview"],
                    response_text=r["response_text"],
                    cited_finding_ids=json.loads(r["cited_finding_ids_json"] or "[]"),
                    created_at=r["created_at"],
                )
                for r in cur.fetchall()
            ]
        finally:
            conn.close()
