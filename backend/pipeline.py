import time
import uuid
from datetime import datetime
from typing import List, Dict, Any, Tuple
from pathlib import Path

from .database import get_connection, clear_events_and_iocs, bulk_insert_events
from .parsers import (
    parse_windows_csv,
    parse_firewall_csv,
    parse_syslog_text,
    parse_app_text,
    parse_canonical_csv,
    parse_json_data
)
from .engine import (
    normalize_record,
    clean_and_validate_record,
    deduplicate_events,
    classify_record,
    correlate_events,
    extract_and_sync_iocs
)

class PipelineRunner:
    def __init__(self, run_id: str = None):
        self.run_id = run_id or f"RUN-{uuid.uuid4().hex[:8].upper()}"
        self.stage_logs = []
        self.all_errors = []

    def log_stage(self, stage: str, status: str, duration_ms: float, in_count: int, out_count: int, details: str):
        self.stage_logs.append({
            "run_id": self.run_id,
            "stage": stage,
            "status": status,
            "duration_ms": round(duration_ms, 2),
            "input_count": in_count,
            "output_count": out_count,
            "details": details,
            "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        })

    def process_files(self, file_inputs: List[Tuple[str, str]], clear_existing: bool = True) -> Dict[str, Any]:
        """
        file_inputs: List of (filename, file_content_str)
        """
        overall_start = time.time()
        
        if clear_existing:
            clear_events_and_iocs()

        # Step 1 & 2: Parsing & Ingestion
        t0 = time.time()
        raw_events = []
        parsing_errors = []

        for filename, content in file_inputs:
            fname_lower = filename.lower()
            if "windows" in fname_lower:
                evts, errs = parse_windows_csv(content, filename)
            elif "firewall" in fname_lower:
                evts, errs = parse_firewall_csv(content, filename)
            elif "syslog" in fname_lower or fname_lower.endswith(".log") and "app" not in fname_lower:
                evts, errs = parse_syslog_text(content, filename)
            elif "app" in fname_lower:
                evts, errs = parse_app_text(content, filename)
            elif fname_lower.endswith(".json"):
                evts, errs = parse_json_data(content, filename)
            else:
                # Default to canonical CSV parser
                evts, errs = parse_canonical_csv(content, filename)

            raw_events.extend(evts)
            parsing_errors.extend(errs)

        t_parse = (time.time() - t0) * 1000
        self.log_stage(
            stage="1. Log Parsing & Source Mapping",
            status="Completed" if raw_events else ("Warning" if parsing_errors else "Empty"),
            duration_ms=t_parse,
            in_count=len(file_inputs),
            out_count=len(raw_events),
            details=f"Parsed {len(raw_events)} events across {len(file_inputs)} source files. {len(parsing_errors)} errors flagged."
        )

        # Step 3: Timestamp & Format Normalization
        t0 = time.time()
        normalized_events = []
        for evt in raw_events:
            norm_evt = normalize_record(evt)
            if norm_evt.get("timestamp"):
                normalized_events.append(norm_evt)
            else:
                parsing_errors.append({
                    "source_file": evt.get("source_file") or "unknown",
                    "row_index": evt.get("source_row_index") or 0,
                    "error_reason": "Timestamp could not be parsed to standard UTC",
                    "raw_data": str(evt.get("raw_record") or evt)
                })

        t_norm = (time.time() - t0) * 1000
        self.log_stage(
            stage="2. Timestamp Normalization (UTC)",
            status="Completed",
            duration_ms=t_norm,
            in_count=len(raw_events),
            out_count=len(normalized_events),
            details=f"Converted dates to UTC ISO-8601 strings. {len(raw_events) - len(normalized_events)} rows dropped due to unparseable timestamps."
        )

        # Step 4: Data Validation & Evidence Cleaning
        t0 = time.time()
        cleaned_events = []
        validation_warnings = 0
        for evt in normalized_events:
            cleaned_evt, warning = clean_and_validate_record(evt)
            if warning:
                validation_warnings += 1
            cleaned_events.append(cleaned_evt)

        t_clean = (time.time() - t0) * 1000
        self.log_stage(
            stage="3. Validation & Evidence Cleaning",
            status="Completed",
            duration_ms=t_clean,
            in_count=len(normalized_events),
            out_count=len(cleaned_events),
            details=f"Cleaned formatting without mutating raw evidence. {validation_warnings} field syntax warnings handled."
        )

        # Step 5: Duplicate Detection
        t0 = time.time()
        deduped_events, dedup_stats = deduplicate_events(cleaned_events, window_seconds=5)
        t_dedup = (time.time() - t0) * 1000
        self.log_stage(
            stage="4. Duplicate Detection & Pruning",
            status="Completed",
            duration_ms=t_dedup,
            in_count=dedup_stats["total_before"],
            out_count=dedup_stats["total_after"],
            details=f"Removed {dedup_stats['exact_duplicates_removed']} exact duplicates and {dedup_stats['similar_duplicates_removed']} rapid burst duplicates. Retention rate: {dedup_stats['retention_rate']}%."
        )

        # Step 6: Transparent Event Classification
        t0 = time.time()
        classified_events = [classify_record(evt) for evt in deduped_events]
        t_class = (time.time() - t0) * 1000
        self.log_stage(
            stage="5. Rule-Based Event Classification",
            status="Completed",
            duration_ms=t_class,
            in_count=len(deduped_events),
            out_count=len(classified_events),
            details=f"Classified {len(classified_events)} events using transparent security rule dictionary."
        )

        # Step 7: Incident Correlation
        t0 = time.time()
        correlated_events = correlate_events(classified_events)
        t_corr = (time.time() - t0) * 1000
        corr_count = sum(1 for e in correlated_events if e.get("correlation_id"))
        self.log_stage(
            stage="6. Multi-Source Incident Correlation",
            status="Completed",
            duration_ms=t_corr,
            in_count=len(classified_events),
            out_count=len(correlated_events),
            details=f"Grouped events by Correlation IDs, Session IDs, and interacting IP addresses. {corr_count} events linked to incidents."
        )

        # Step 8: IOC Extraction & Sync
        t0 = time.time()
        extract_and_sync_iocs(correlated_events)
        t_ioc = (time.time() - t0) * 1000
        self.log_stage(
            stage="7. IOC Detection & Threat Discovery",
            status="Completed",
            duration_ms=t_ioc,
            in_count=len(correlated_events),
            out_count=len(correlated_events),
            details="Extracted public suspicious IPs, high-risk ports, domains, and file hashes into IOC database."
        )

        # Step 9: Database Persistence
        t0 = time.time()
        bulk_insert_events(correlated_events)
        t_persist = (time.time() - t0) * 1000
        self.log_stage(
            stage="8. Indexed SQLite Storage",
            status="Completed",
            duration_ms=t_persist,
            in_count=len(correlated_events),
            out_count=len(correlated_events),
            details=f"Stored {len(correlated_events)} records with B-tree indexes on timestamp, source, severity, and IP."
        )

        # Record stage logs & errors to DB
        conn = get_connection()
        cursor = conn.cursor()
        for sl in self.stage_logs:
            cursor.execute("""
                INSERT INTO pipeline_logs (run_id, stage, status, duration_ms, input_count, output_count, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (sl["run_id"], sl["stage"], sl["status"], sl["duration_ms"], sl["input_count"], sl["output_count"], sl["details"], sl["created_at"]))

        for pe in parsing_errors:
            cursor.execute("""
                INSERT INTO parsing_errors (source_file, row_index, error_reason, raw_data, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (pe["source_file"], pe["row_index"], pe["error_reason"], pe.get("raw_data", "")[:500], datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        conn.close()

        total_duration_sec = round(time.time() - overall_start, 3)

        return {
            "run_id": self.run_id,
            "status": "Success",
            "total_duration_seconds": total_duration_sec,
            "total_raw_events": len(raw_events),
            "final_events_count": len(correlated_events),
            "duplicates_removed": dedup_stats["exact_duplicates_removed"] + dedup_stats["similar_duplicates_removed"],
            "retention_rate": dedup_stats["retention_rate"],
            "parsing_errors_count": len(parsing_errors),
            "stages": self.stage_logs,
            "errors": parsing_errors[:50]  # Return preview of parsing errors
        }
