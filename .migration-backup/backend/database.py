import sqlite3
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "processed" / "cyber_incident.db"

def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id_unique TEXT UNIQUE,
        timestamp TEXT,
        log_source TEXT,
        event_id TEXT,
        event_type TEXT,
        severity TEXT,
        action TEXT,
        username TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        hostname TEXT,
        device_type TEXT,
        department TEXT,
        country TEXT,
        session_id TEXT,
        correlation_id TEXT,
        process_name TEXT,
        file_name TEXT,
        file_hash TEXT,
        bytes_sent INTEGER,
        bytes_received INTEGER,
        response_code TEXT,
        description TEXT,
        status TEXT,
        raw_record TEXT,
        source_file TEXT,
        source_row_index INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_source ON events(log_source);
    CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_sip ON events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_dip ON events(destination_ip);
    CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
    CREATE INDEX IF NOT EXISTS idx_events_corr ON events(correlation_id);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

    CREATE TABLE IF NOT EXISTS investigation_cases (
        case_id TEXT PRIMARY KEY,
        title TEXT,
        status TEXT,
        assigned_analyst TEXT,
        notes TEXT,
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS iocs (
        indicator_value TEXT PRIMARY KEY,
        indicator_type TEXT,
        first_seen TEXT,
        last_seen TEXT,
        occurrence_count INTEGER,
        detection_rule TEXT,
        analyst_status TEXT,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS pipeline_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT,
        stage TEXT,
        status TEXT,
        duration_ms REAL,
        input_count INTEGER,
        output_count INTEGER,
        details TEXT,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS parsing_errors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file TEXT,
        row_index INTEGER,
        error_reason TEXT,
        raw_data TEXT,
        created_at TEXT
    );
    """)

    # Ensure a default investigation case exists
    cursor.execute("SELECT COUNT(*) FROM investigation_cases WHERE case_id = 'CASE-001'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO investigation_cases (case_id, title, status, assigned_analyst, notes, updated_at)
            VALUES ('CASE-001', 'Multi-Source Cyber Security Incident', 'In Progress', 'SOC Lead Analyst', 'Initial triage established. Awaiting full correlation and IOC validation.', datetime('now'))
        """)

    conn.commit()
    conn.close()

def clear_events_and_iocs():
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events")
    cursor.execute("DELETE FROM iocs")
    cursor.execute("DELETE FROM parsing_errors")
    cursor.execute("DELETE FROM pipeline_logs")
    conn.commit()
    conn.close()

def bulk_insert_events(events: List[Dict[str, Any]]):
    if not events:
        return
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
    sql = f"INSERT OR REPLACE INTO events ({','.join(columns)}) VALUES ({placeholders})"

    rows = []
    for evt in events:
        row = [
            evt.get("event_id_unique"),
            evt.get("timestamp"),
            evt.get("log_source"),
            evt.get("event_id"),
            evt.get("event_type"),
            evt.get("severity"),
            evt.get("action"),
            evt.get("username"),
            evt.get("source_ip"),
            evt.get("destination_ip"),
            evt.get("source_port"),
            evt.get("destination_port"),
            evt.get("protocol"),
            evt.get("hostname"),
            evt.get("device_type"),
            evt.get("department"),
            evt.get("country"),
            evt.get("session_id"),
            evt.get("correlation_id"),
            evt.get("process_name"),
            evt.get("file_name"),
            evt.get("file_hash"),
            evt.get("bytes_sent"),
            evt.get("bytes_received"),
            evt.get("response_code"),
            evt.get("description"),
            evt.get("status"),
            evt.get("raw_record"),
            evt.get("source_file"),
            evt.get("source_row_index"),
        ]
        rows.append(row)

    cursor.executemany(sql, rows)
    conn.commit()
    conn.close()
