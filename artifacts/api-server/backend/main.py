import gzip
import os
import io
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, StreamingResponse

from .database import init_db, get_connection, clear_events_and_iocs
from .models import EventFilterQuery, CaseNoteUpdate, IOCStatusUpdate, ReportRequest
from .pipeline import PipelineRunner
from .reporting import generate_incident_pdf, generate_incident_csv, generate_incident_json

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "samples" / "incident_timeline_cleaned.csv.gz"
TEST_SUITE_PATH = PROJECT_ROOT / "data" / "samples" / "test_incident_suite.csv"
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"

app = FastAPI(title="Cyber Incident Timeline Generator API", version="2.0.0")

# Enable CORS for local development and private access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database and preload default enterprise dataset if empty
@app.on_event("startup")
def startup_event():
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM events")
    count = cursor.fetchone()[0]
    conn.close()

    if count == 0:
        if DEFAULT_DATASET_PATH.exists():
            print(f"[+] Loading default enterprise dataset from {DEFAULT_DATASET_PATH}...")
            load_default_cleaned_dataset(max_records=100000, clear_existing=False)
            print("[+] Default enterprise dataset loaded successfully.")

@app.get("/api/health")
@app.get("/api/healthz")
def health_check():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]
    conn.close()
    return {
        "status": "online",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_events": total_events,
        "total_iocs": total_iocs,
        "mode": "Live Production Backend"
    }

@app.get("/api/dashboard")
def get_dashboard_metrics():
    conn = get_connection()
    cursor = conn.cursor()

    # Total events
    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    if total_events == 0:
        conn.close()
        return {
            "total_events": 0,
            "critical_events": 0,
            "high_events": 0,
            "medium_events": 0,
            "low_events": 0,
            "informational_events": 0,
            "unique_sources_count": 0,
            "unique_ips_count": 0,
            "incidents_count": 0,
            "time_range": {"start": None, "end": None},
            "severity_distribution": [],
            "source_distribution": [],
            "event_type_distribution": [],
            "temporal_distribution": [],
            "top_ips": [],
            "top_incidents": [],
            "iocs_count": 0
        }

    # Severity counts
    cursor.execute("""
        SELECT severity, COUNT(*) as cnt 
        FROM events 
        GROUP BY severity
    """)
    sev_map = {row["severity"]: row["cnt"] for row in cursor.fetchall()}

    # Unique Sources
    cursor.execute("SELECT COUNT(DISTINCT log_source) FROM events WHERE log_source IS NOT NULL")
    unique_sources_count = cursor.fetchone()[0]

    # Unique IPs
    cursor.execute("""
        SELECT COUNT(DISTINCT ip) FROM (
            SELECT source_ip AS ip FROM events WHERE source_ip IS NOT NULL AND source_ip != ''
            UNION
            SELECT destination_ip AS ip FROM events WHERE destination_ip IS NOT NULL AND destination_ip != ''
        )
    """)
    unique_ips_count = cursor.fetchone()[0]

    # Active Incidents (Unique Correlation IDs)
    cursor.execute("SELECT COUNT(DISTINCT correlation_id) FROM events WHERE correlation_id IS NOT NULL AND correlation_id != ''")
    incidents_count = cursor.fetchone()[0]

    # Date Range
    cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events WHERE timestamp IS NOT NULL AND timestamp != ''")
    min_ts, max_ts = cursor.fetchone()

    # Source Distribution
    cursor.execute("SELECT log_source, COUNT(*) as cnt FROM events GROUP BY log_source ORDER BY cnt DESC")
    source_distribution = [{"name": row["log_source"] or "Unknown", "count": row["cnt"]} for row in cursor.fetchall()]

    # Event Type Distribution
    cursor.execute("SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC LIMIT 8")
    event_type_distribution = [{"name": row["event_type"] or "Unknown", "count": row["cnt"]} for row in cursor.fetchall()]

    # Severity breakdown array
    sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
    severity_distribution = [{"name": s, "count": sev_map.get(s, 0)} for s in sev_order]

    # Temporal distribution (grouped by hourly or daily bucket)
    cursor.execute("""
        SELECT substr(timestamp, 1, 13) as time_bucket, COUNT(*) as cnt
        FROM events
        WHERE timestamp IS NOT NULL
        GROUP BY time_bucket
        ORDER BY time_bucket ASC
        LIMIT 30
    """)
    temporal_distribution = [{"time": row["time_bucket"] + ":00", "count": row["cnt"]} for row in cursor.fetchall()]

    # Top IPs
    cursor.execute("""
        SELECT ip, COUNT(*) as cnt FROM (
            SELECT source_ip as ip FROM events WHERE source_ip IS NOT NULL
            UNION ALL
            SELECT destination_ip as ip FROM events WHERE destination_ip IS NOT NULL
        ) GROUP BY ip ORDER BY cnt DESC LIMIT 6
    """)
    top_ips = [{"ip": row["ip"], "count": row["cnt"]} for row in cursor.fetchall()]

    # Top Incidents
    cursor.execute("""
        SELECT correlation_id, COUNT(*) as cnt, MAX(severity) as max_sev
        FROM events
        WHERE correlation_id IS NOT NULL AND correlation_id != ''
        GROUP BY correlation_id
        ORDER BY cnt DESC
        LIMIT 6
    """)
    top_incidents = [{"correlation_id": row["correlation_id"], "count": row["cnt"], "severity": row["max_sev"]} for row in cursor.fetchall()]

    # IOC count
    cursor.execute("SELECT COUNT(*) FROM iocs")
    iocs_count = cursor.fetchone()[0]

    conn.close()

    return {
        "total_events": total_events,
        "critical_events": sev_map.get("Critical", 0),
        "high_events": sev_map.get("High", 0),
        "medium_events": sev_map.get("Medium", 0),
        "low_events": sev_map.get("Low", 0),
        "informational_events": sev_map.get("Informational", 0),
        "unique_sources_count": unique_sources_count,
        "unique_ips_count": unique_ips_count,
        "incidents_count": incidents_count,
        "time_range": {"start": min_ts, "end": max_ts},
        "severity_distribution": severity_distribution,
        "source_distribution": source_distribution,
        "event_type_distribution": event_type_distribution,
        "temporal_distribution": temporal_distribution,
        "top_ips": top_ips,
        "top_incidents": top_incidents,
        "iocs_count": iocs_count
    }

def build_filter_clause(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    log_sources: Optional[str] = None,
    severities: Optional[str] = None,
    ip: Optional[str] = None,
    username: Optional[str] = None,
    correlation_id: Optional[str] = None,
    search: Optional[str] = None
):
    where_clauses = []
    params = []

    if start_time:
        where_clauses.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        where_clauses.append("timestamp <= ?")
        params.append(end_time)
    if log_sources:
        src_list = [s.strip() for s in log_sources.split(",") if s.strip()]
        if src_list:
            placeholders = ",".join(["?"] * len(src_list))
            where_clauses.append(f"log_source IN ({placeholders})")
            params.extend(src_list)
    if severities:
        sev_list = [s.strip() for s in severities.split(",") if s.strip()]
        if sev_list:
            placeholders = ",".join(["?"] * len(sev_list))
            where_clauses.append(f"severity IN ({placeholders})")
            params.extend(sev_list)
    if ip:
        ip_clean = f"%{ip.strip()}%"
        where_clauses.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
        params.extend([ip_clean, ip_clean])
    if username:
        user_clean = f"%{username.strip()}%"
        where_clauses.append("username LIKE ?")
        params.append(user_clean)
    if correlation_id:
        where_clauses.append("correlation_id = ?")
        params.append(correlation_id.strip())
    if search:
        search_pattern = f"%{search.strip()}%"
        where_clauses.append("(description LIKE ? OR raw_record LIKE ? OR hostname LIKE ? OR process_name LIKE ? OR event_id LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    return where_sql, params

@app.get("/api/events")
def list_events(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    log_sources: Optional[str] = None,
    severities: Optional[str] = None,
    ip: Optional[str] = None,
    username: Optional[str] = None,
    correlation_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str = "timestamp",
    sort_order: str = "ASC"
):
    conn = get_connection()
    cursor = conn.cursor()

    # Sanitize sort fields
    valid_sorts = {"timestamp", "severity", "log_source", "event_type", "id"}
    sort_col = sort_by if str(sort_by) in valid_sorts else "timestamp"
    order_dir = "DESC" if str(sort_order).upper() == "DESC" else "ASC"

    where_sql, params = build_filter_clause(
        start_time, end_time, log_sources, severities, ip, username, correlation_id, search
    )

    # Count total matched
    count_sql = f"SELECT COUNT(*) FROM events {where_sql}"
    cursor.execute(count_sql, params)
    total_matched = cursor.fetchone()[0]

    # Query items with deterministic secondary tie-breaker (id ASC/DESC)
    query_sql = f"""
        SELECT * FROM events
        {where_sql}
        ORDER BY {sort_col} {order_dir}, id {order_dir}
        LIMIT ? OFFSET ?
    """
    query_params = params + [limit, offset]
    cursor.execute(query_sql, query_params)

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return {
        "total_matched": total_matched,
        "limit": limit,
        "offset": offset,
        "events": rows
    }

@app.get("/api/events/{event_id}")
def get_event_detail(event_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Event not found")

    event_data = dict(row)

    # Fetch correlated events (sharing correlation_id or session_id or same source_ip)
    correlated = []
    corr_id = event_data.get("correlation_id")
    sess_id = event_data.get("session_id")
    sip = event_data.get("source_ip")

    if corr_id:
        cursor.execute("SELECT id, timestamp, log_source, severity, event_type, action, source_ip, destination_ip FROM events WHERE correlation_id = ? AND id != ? LIMIT 10", (corr_id, event_id))
        correlated = [dict(r) for r in cursor.fetchall()]
    elif sess_id:
        cursor.execute("SELECT id, timestamp, log_source, severity, event_type, action, source_ip, destination_ip FROM events WHERE session_id = ? AND id != ? LIMIT 10", (sess_id, event_id))
        correlated = [dict(r) for r in cursor.fetchall()]
    elif sip:
        cursor.execute("SELECT id, timestamp, log_source, severity, event_type, action, source_ip, destination_ip FROM events WHERE (source_ip = ? OR destination_ip = ?) AND id != ? LIMIT 10", (sip, sip, event_id))
        correlated = [dict(r) for r in cursor.fetchall()]

    event_data["correlated_events"] = correlated
    conn.close()
    return event_data

@app.get("/api/iocs")
def list_iocs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM iocs ORDER BY occurrence_count DESC, last_seen DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

@app.post("/api/iocs/update")
def update_ioc_status(payload: IOCStatusUpdate):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE iocs
        SET analyst_status = ?, notes = ?
        WHERE indicator_value = ?
    """, (payload.analyst_status, payload.notes or '', payload.indicator_value))
    conn.commit()
    conn.close()
    return {"status": "success", "indicator": payload.indicator_value, "analyst_status": payload.analyst_status}

@app.get("/api/case")
def get_case_details():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM investigation_cases WHERE case_id = 'CASE-001'")
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        "case_id": "CASE-001",
        "title": "Incident Investigation",
        "status": "In Progress",
        "assigned_analyst": "SOC Lead Analyst",
        "notes": "",
        "updated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }

@app.post("/api/case")
def update_case_details(payload: CaseNoteUpdate):
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO investigation_cases (case_id, title, status, assigned_analyst, notes, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(case_id) DO UPDATE SET
            title = COALESCE(excluded.title, title),
            status = COALESCE(excluded.status, status),
            assigned_analyst = COALESCE(excluded.assigned_analyst, assigned_analyst),
            notes = excluded.notes,
            updated_at = excluded.updated_at
    """, (
        payload.case_id,
        payload.title or "Multi-Source Cyber Security Incident",
        payload.status or "In Progress",
        payload.assigned_analyst or "SOC Lead Analyst",
        payload.notes,
        now_str
    ))
    conn.commit()
    conn.close()
    return {"status": "success", "updated_at": now_str}

@app.get("/api/pipeline/status")
def get_pipeline_status():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pipeline_logs ORDER BY id DESC LIMIT 15")
    logs = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) FROM parsing_errors")
    total_errors = cursor.fetchone()[0]

    cursor.execute("SELECT * FROM parsing_errors ORDER BY id DESC LIMIT 20")
    error_records = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "stages": logs,
        "total_errors": total_errors,
        "error_records": error_records,
        "errors": error_records
    }

def load_default_cleaned_dataset(max_records: int = 100000, clear_existing: bool = True):
    cleaned_path = DEFAULT_DATASET_PATH
    if not cleaned_path.exists():
        raise HTTPException(status_code=404, detail="incident_timeline_cleaned.csv not found")

    import csv
    from .engine.normalizer import normalize_timestamp, normalize_severity

    t0 = time.time()
    if clear_existing:
        clear_events_and_iocs()

    conn = get_connection()
    cursor = conn.cursor()

    columns = [
        "event_id_unique", "timestamp", "log_source", "event_id", "event_type",
        "severity", "action", "username", "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol", "hostname", "device_type",
        "department", "country", "session_id", "correlation_id", "process_name",
        "file_name", "file_hash", "bytes_sent", "bytes_received", "response_code",
        "description", "status", "raw_record", "source_file", "source_row_index"
    ]
    placeholders = ",".join(["?"] * len(columns))
    sql = f"INSERT INTO events ({','.join(columns)}) VALUES ({placeholders})"

    batch = []
    total_loaded = 0
    with gzip.open(cleaned_path, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header
        for idx, line in enumerate(reader, start=1):
            if not line or len(line) < 10:
                continue
            ts = normalize_timestamp(line[1])
            sev = normalize_severity(line[5])
            sport = int(line[10]) if line[10] and line[10].isdigit() else None
            dport = int(line[11]) if line[11] and line[11].isdigit() else None
            user = line[7] if line[7] != '-' else None
            proc = line[16] if len(line) > 16 and line[16] and line[16] != '-' else None
            fname = line[17] if len(line) > 17 and line[17] and line[17] != '-' else None
            fhash = line[18] if len(line) > 18 and line[18] and line[18] != '-' else None

            row = [
                line[0], ts, line[2], line[3], line[4],
                sev, line[6], user, line[8], line[9],
                sport, dport, line[12], line[13],
                "Server" if "DC" in line[13] or "SERVER" in line[13] else "Workstation",
                "Enterprise Infrastructure", "Global", line[14], line[15], proc,
                fname, fhash, None, None, None,
                f"{line[2]} {line[4]} ({line[6]})", "Logged", ",".join(line),
                "incident_timeline_cleaned.csv", idx
            ]
            batch.append(row)

            if len(batch) >= 10000:
                cursor.executemany(sql, batch)
                conn.commit()
                total_loaded += len(batch)
                batch = []
                if max_records and total_loaded >= max_records:
                    break

        if batch:
            cursor.executemany(sql, batch)
            conn.commit()
            total_loaded += len(batch)

    # Sync IOCs
    cursor.execute("""
    INSERT OR REPLACE INTO iocs (indicator_value, indicator_type, first_seen, last_seen, occurrence_count, detection_rule, analyst_status, notes)
    SELECT ip, 'IP Address', MIN(timestamp), MAX(timestamp), COUNT(*), 'Public Inbound/Outbound IP', 'Observed', ''
    FROM (
        SELECT source_ip as ip, timestamp FROM events WHERE source_ip IS NOT NULL AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '192.168.%' AND source_ip NOT LIKE '172.%'
        UNION ALL
        SELECT destination_ip as ip, timestamp FROM events WHERE destination_ip IS NOT NULL AND destination_ip NOT LIKE '10.%' AND destination_ip NOT LIKE '192.168.%' AND destination_ip NOT LIKE '172.%'
    )
    GROUP BY ip;
    """)
    cursor.execute("""
    INSERT OR REPLACE INTO iocs (indicator_value, indicator_type, first_seen, last_seen, occurrence_count, detection_rule, analyst_status, notes)
    SELECT 'Port ' || port, 'Suspicious Port', MIN(timestamp), MAX(timestamp), COUNT(*), 'High-Risk Network Service Port', 'Observed', ''
    FROM (
        SELECT destination_port as port, timestamp FROM events WHERE destination_port IN (22, 23, 135, 139, 445, 3389, 5128)
        UNION ALL
        SELECT source_port as port, timestamp FROM events WHERE source_port IN (22, 23, 135, 139, 445, 3389, 5128)
    )
    GROUP BY port;
    """)
    cursor.execute("""
    INSERT OR REPLACE INTO iocs (indicator_value, indicator_type, first_seen, last_seen, occurrence_count, detection_rule, analyst_status, notes)
    SELECT file_hash, 'SHA256 Hash', MIN(timestamp), MAX(timestamp), COUNT(*), 'Observed Artifact Execution Hash', 'Observed', ''
    FROM events WHERE file_hash IS NOT NULL AND length(file_hash) = 64
    GROUP BY file_hash;
    """)

    duration_ms = round((time.time() - t0) * 1000, 2)
    cursor.execute("""
        INSERT INTO pipeline_logs (run_id, stage, status, duration_ms, input_count, output_count, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f"RUN-ENTERPRISE-{int(time.time())}",
        "Enterprise Timeline Ingestion",
        "Completed",
        duration_ms,
        total_loaded,
        total_loaded,
        f"Loaded {total_loaded:,} enterprise records from incident_timeline_cleaned.csv",
        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return {
        "status": "Success",
        "dataset": "incident_timeline_cleaned.csv",
        "total_raw_events": total_loaded,
        "final_events_count": total_loaded,
        "duplicates_removed": 0,
        "retention_rate": 100.0,
        "parsing_errors_count": 0,
        "duration_seconds": round(time.time() - t0, 3)
    }

@app.post("/api/pipeline/load-demo")
def load_demo_dataset():
    """
    Explicitly loads the curated multi-source logs:
    - firewall_logs.csv
    - windows_events.csv
    - syslog.log
    - app_logs.log
    """
    raw_dir = RAW_DATA_DIR
    file_inputs = []

    for name in ["firewall_logs.csv", "windows_events.csv", "syslog.log", "app_logs.log"]:
        fpath = raw_dir / name
        if fpath.exists():
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                file_inputs.append((name, f.read()))

    if not file_inputs:
        raise HTTPException(status_code=404, detail="Demo raw files not found in data/raw")

    runner = PipelineRunner()
    result = runner.process_files(file_inputs, clear_existing=True)
    return result

@app.post("/api/pipeline/load-enterprise")
def load_enterprise_dataset():
    """
    Loads the enterprise incident dataset from incident_timeline_cleaned.csv.
    """
    return load_default_cleaned_dataset(max_records=100000, clear_existing=True)

@app.post("/api/pipeline/load-test-suite")
def load_test_suite_dataset():
    """
    Loads the specialized test suite with deliberate edge cases:
    - Malformed timestamps
    - Exact duplicate rows
    - Sliding window bursts
    - Multiple log sources
    - Known IOCs
    """
    test_path = TEST_SUITE_PATH
    if not test_path.exists():
        # Generate on demand
        from .test_suite_gen import generate_test_suite_file
        generate_test_suite_file(test_path)

    with open(test_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    runner = PipelineRunner()
    result = runner.process_files([("test_incident_suite.csv", content)], clear_existing=True)
    return result

@app.post("/api/upload")
async def upload_log_files(files: List[UploadFile] = File(...)):
    """
    Receives user uploaded files (.csv, .json, .log, .txt)
    and processes them through the pipeline.
    """
    file_inputs = []
    for f in files:
        contents = await f.read()
        try:
            content_str = contents.decode("utf-8")
        except UnicodeDecodeError:
            content_str = contents.decode("latin-1", errors="replace")
        file_inputs.append((f.filename, content_str))

    runner = PipelineRunner()
    result = runner.process_files(file_inputs, clear_existing=True)
    return result

@app.get("/api/errors")
def get_parsing_errors(limit: int = 100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM parsing_errors ORDER BY id DESC LIMIT ?", (limit,))
    errors = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return errors

# Report Exporters
@app.post("/api/export/pdf")
def export_pdf(payload: ReportRequest):
    conn = get_connection()
    cursor = conn.cursor()

    # Query events based on scope
    if payload.scope == "incident" and payload.correlation_id:
        cursor.execute("SELECT * FROM events WHERE correlation_id = ? ORDER BY timestamp ASC, id ASC", (payload.correlation_id,))
        filter_summary = f"Incident Cluster: {payload.correlation_id}"
    else:
        cursor.execute("SELECT * FROM events ORDER BY timestamp ASC, id ASC LIMIT 500")
        filter_summary = "Active Timeline Scope (Up to 500 events)"

    events = [dict(r) for r in cursor.fetchall()]

    # Case info
    cursor.execute("SELECT * FROM investigation_cases WHERE case_id = 'CASE-001'")
    case_row = cursor.fetchone()
    case_info = dict(case_row) if case_row else {}

    # IOCs
    cursor.execute("SELECT * FROM iocs ORDER BY occurrence_count DESC LIMIT 30")
    iocs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    pdf_bytes = generate_incident_pdf(
        events=events,
        case_info=case_info,
        iocs=iocs,
        report_title=payload.report_title,
        filter_summary=filter_summary
    )

    filename = f"Incident_Report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.post("/api/export/csv")
def export_csv(payload: ReportRequest):
    conn = get_connection()
    cursor = conn.cursor()

    if payload.scope == "incident" and payload.correlation_id:
        cursor.execute("SELECT * FROM events WHERE correlation_id = ? ORDER BY timestamp ASC, id ASC", (payload.correlation_id,))
        filename = f"Incident_{payload.correlation_id}_{datetime.utcnow().strftime('%Y%m%d')}.csv"
    else:
        cursor.execute("SELECT * FROM events ORDER BY timestamp ASC, id ASC")
        filename = f"Incident_Timeline_Export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    events = [dict(r) for r in cursor.fetchall()]
    conn.close()

    csv_text = generate_incident_csv(events)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.post("/api/export/json")
def export_json(payload: ReportRequest):
    conn = get_connection()
    cursor = conn.cursor()

    if payload.scope == "incident" and payload.correlation_id:
        cursor.execute("SELECT * FROM events WHERE correlation_id = ? ORDER BY timestamp ASC, id ASC", (payload.correlation_id,))
        filter_summary = f"Incident: {payload.correlation_id}"
        filename = f"Incident_{payload.correlation_id}_{datetime.utcnow().strftime('%Y%m%d')}.json"
    else:
        cursor.execute("SELECT * FROM events ORDER BY timestamp ASC, id ASC")
        filter_summary = "Complete Event Scope"
        filename = f"Incident_Evidence_Package_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

    events = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM investigation_cases WHERE case_id = 'CASE-001'")
    case_row = cursor.fetchone()
    case_info = dict(case_row) if case_row else {}

    cursor.execute("SELECT * FROM iocs ORDER BY occurrence_count DESC")
    iocs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    json_str = generate_incident_json(events, case_info, iocs, filter_summary)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# The React artifact serves the frontend; this service owns only API routes.
