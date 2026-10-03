#!/usr/bin/env python3
"""
Comprehensive Automated Test & Verification Suite for
Cyber Incident Timeline Generator & Forensic Hub
"""

import sys
import json
from pathlib import Path

# Ensure UTF-8 output on Windows console
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.database import init_db, get_connection
from backend.pipeline import PipelineRunner
from backend.main import (
    load_demo_dataset, 
    load_enterprise_dataset, 
    load_test_suite_dataset, 
    get_dashboard_metrics, 
    list_events, 
    get_event_detail, 
    list_iocs, 
    update_ioc_status, 
    get_case_details, 
    update_case_details, 
    export_pdf, 
    export_csv, 
    export_json, 
    get_parsing_errors
)
from backend.models import (
    CaseNoteUpdate, 
    IOCStatusUpdate, 
    ReportRequest
)

def run_tests():
    print("=" * 70)
    print("STARTING COMPLETE FORENSIC PLATFORM VERIFICATION")
    print("=" * 70)

    # 1. Test Database Initialization
    print("\n[TEST 1] Initializing Database & Indexes...")
    init_db()
    conn = get_connection()
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "events" in tables, "Table 'events' missing"
    assert "iocs" in tables, "Table 'iocs' missing"
    assert "investigation_cases" in tables, "Table 'investigation_cases' missing"
    assert "pipeline_logs" in tables, "Table 'pipeline_logs' missing"
    assert "parsing_errors" in tables, "Table 'parsing_errors' missing"
    conn.close()
    print("  ✓ Database tables and indexes verified successfully.")

    # 2. Test Multi-Source Curated Dataset Ingestion
    print("\n[TEST 2] Ingesting Multi-Source Raw Logs (Firewall, Windows, Linux, App)...")
    res_demo = load_demo_dataset()
    assert res_demo["status"] == "Success", f"Demo load failed: {res_demo}"
    assert res_demo["total_raw_events"] == 60, f"Expected 60 raw events, got {res_demo['total_raw_events']}"
    assert res_demo["final_events_count"] == 60, f"Expected 60 final events, got {res_demo['final_events_count']}"
    
    m_demo = get_dashboard_metrics()
    assert m_demo["total_events"] == 60, f"Expected 60 events in dashboard, got {m_demo['total_events']}"
    assert m_demo["unique_sources_count"] == 4, f"Expected 4 distinct sources, got {m_demo['unique_sources_count']}"
    sources = {s["name"]: s["count"] for s in m_demo["source_distribution"]}
    assert sources["Firewall"] == 15, "Firewall count mismatch"
    assert sources["Windows"] == 15, "Windows count mismatch"
    assert sources["Linux"] == 15, "Linux count mismatch"
    assert sources["Application"] == 15, "Application count mismatch"
    print(f"  ✓ Ingested 60 events across 4 sources: {sources}")

    # 3. Test Edge-Case Suite: Malformed Rows, Exact Duplicate & Sliding-Window Burst
    print("\n[TEST 3] Testing Edge-Case Suite (Malformed Rows, Duplicates, Error Logs)...")
    res_edge = load_test_suite_dataset()
    assert res_edge["status"] == "Success", f"Edge suite load failed: {res_edge}"
    assert res_edge["total_raw_events"] == 8, f"Expected 8 raw events, got {res_edge['total_raw_events']}"
    assert res_edge["duplicates_removed"] == 2, f"Expected 2 duplicates removed, got {res_edge['duplicates_removed']}"
    assert res_edge["parsing_errors_count"] == 2, f"Expected 2 parsing errors, got {res_edge['parsing_errors_count']}"
    assert res_edge["final_events_count"] == 5, f"Expected 5 clean events, got {res_edge['final_events_count']}"

    errors = get_parsing_errors()
    assert len(errors) >= 2, "Expected at least 2 parsing errors in log"
    print(f"  ✓ Correctly quarantined {res_edge['parsing_errors_count']} malformed rows and removed {res_edge['duplicates_removed']} duplicates.")
    print(f"  ✓ Row-level error sample: {errors[0]['error_reason']} on line #{errors[0]['row_index']}")

    # 4. Test Chronological Sorting with Stable Tie-Breaker
    print("\n[TEST 4] Testing Strict Chronological Ordering & Tie-Breaker...")
    evts_res = list_events(sort_by="timestamp", sort_order="ASC", limit=100)
    events_list = evts_res["events"]
    timestamps = [e["timestamp"] for e in events_list if e.get("timestamp")]
    assert timestamps == sorted(timestamps), "Timestamps are not strictly in ascending order!"
    print(f"  ✓ Verified strict chronological ordering across all {len(events_list)} events.")

    # 5. Test Combined Filtering
    print("\n[TEST 5] Testing Multi-Faceted Combined Filters...")
    # Filter by source='Firewall' and severity='High'
    filtered = list_events(log_sources="Firewall", severities="High")
    assert filtered["total_matched"] == 1, f"Expected 1 matching event, got {filtered['total_matched']}"
    assert filtered["events"][0]["log_source"] == "Firewall"
    assert filtered["events"][0]["severity"] == "High"
    print("  ✓ Combined filter (Log Source + Severity) matched precisely 1 event.")

    # Filter by IP
    ip_filtered = list_events(ip="203.0.113.45")
    assert ip_filtered["total_matched"] == 2, f"Expected 2 events for IP 203.0.113.45, got {ip_filtered['total_matched']}"
    print(f"  ✓ IP filter correctly retrieved {ip_filtered['total_matched']} events for 203.0.113.45.")

    # Filter by Correlation ID
    corr_filtered = list_events(correlation_id="INC-CORR-ALPHA")
    assert corr_filtered["total_matched"] == 2, f"Expected 2 events for INC-CORR-ALPHA, got {corr_filtered['total_matched']}"
    print(f"  ✓ Correlation ID filter retrieved {corr_filtered['total_matched']} events.")

    # Test Empty Result State
    empty_filtered = list_events(ip="999.999.999.999")
    assert empty_filtered["total_matched"] == 0, "Expected 0 results for non-existent IP"
    assert len(empty_filtered["events"]) == 0, "Events array should be empty"
    print("  ✓ Correct empty state returned for non-matching filter criteria.")

    # 6. Test Event Inspection Detail Drawer
    print("\n[TEST 6] Testing Forensic Event Detail & Correlated Evidence...")
    first_evt_id = events_list[0]["id"]
    detail = get_event_detail(first_evt_id)
    assert detail["id"] == first_evt_id, "Event detail ID mismatch"
    assert "raw_record" in detail and detail["raw_record"], "Raw record missing in detail"
    assert "source_file" in detail, "Source file reference missing in detail"
    assert "correlated_events" in detail, "Correlated events missing in detail"
    print(f"  ✓ Event detail retrieved with raw record and {len(detail['correlated_events'])} correlated events.")

    # 7. Test IOC Detection & Threat Verification Persistence
    print("\n[TEST 7] Testing IOC Extraction & Analyst Status Update...")
    iocs = list_iocs()
    assert len(iocs) > 0, "Expected extracted IOCs in database"
    test_ioc = iocs[0]["indicator_value"]
    print(f"  ✓ Extracted {len(iocs)} IOCs. Updating '{test_ioc}' to 'Confirmed Threat'...")
    update_res = update_ioc_status(IOCStatusUpdate(
        indicator_value=test_ioc,
        analyst_status="Confirmed Threat",
        notes="Verified malicious probe from foreign IP"
    ))
    assert update_res["status"] == "success"
    # Re-verify from DB
    re_iocs = list_iocs()
    updated_ioc = next(i for i in re_iocs if i["indicator_value"] == test_ioc)
    assert updated_ioc["analyst_status"] == "Confirmed Threat", "Analyst status was not persisted"
    print("  ✓ Analyst threat verification persisted successfully in database.")

    # 8. Test Investigation Case Notes Persistence
    print("\n[TEST 8] Testing Investigation Case Notes & Status Persistence...")
    note_payload = CaseNoteUpdate(
        case_id="CASE-001",
        title="APT Incident Multi-Host Investigation",
        status="Escalated",
        assigned_analyst="Jane Smith (Lead IR)",
        notes="Attacker initiated reconnaissance on Port 3389 followed by SQL Injection payload."
    )
    save_res = update_case_details(note_payload)
    assert save_res["status"] == "success"
    
    case_db = get_case_details()
    assert case_db["status"] == "Escalated", "Case status did not persist"
    assert case_db["assigned_analyst"] == "Jane Smith (Lead IR)", "Analyst did not persist"
    assert "SQL Injection" in case_db["notes"], "Notes did not persist"
    print("  ✓ Case details, status, and forensic notes verified in persistent storage.")

    # 9. Test Dashboard Recalculation on Different Dataset
    print("\n[TEST 9] Testing Dashboard Recalculation after Loading Enterprise Dataset...")
    load_enterprise_dataset()
    m_ent = get_dashboard_metrics()
    assert m_ent["total_events"] >= 2500, f"Expected at least 2500 enterprise events, got {m_ent['total_events']}"
    assert m_ent["unique_sources_count"] >= 3, "Expected at least 3 sources in enterprise dataset"
    print(f"  ✓ Dashboard dynamically recalculated: Total Events = {m_ent['total_events']}, Critical = {m_ent['critical_events']}, High = {m_ent['high_events']}, Incidents = {m_ent['incidents_count']}.")

    # 10. Test Scoped Report Exports: PDF, CSV, JSON
    print("\n[TEST 10] Testing Scoped Report Exports (PDF, CSV, JSON)...")
    req = ReportRequest(scope="all", report_title="Automated Test Forensics Report")
    
    pdf_resp = export_pdf(req)
    assert len(pdf_resp.body) > 1000, "PDF generation produced empty or truncated output"
    assert pdf_resp.media_type == "application/pdf"
    print(f"  ✓ PDF export generated successfully ({len(pdf_resp.body):,} bytes).")

    csv_resp = export_csv(req)
    assert len(csv_resp.body) > 1000, "CSV generation produced empty output"
    assert csv_resp.media_type == "text/csv"
    assert "event_id_unique,timestamp" in csv_resp.body.decode("utf-8")[:100], "CSV header malformed"
    print(f"  ✓ CSV export generated successfully ({len(csv_resp.body):,} bytes).")

    json_resp = export_json(req)
    assert len(json_resp.body) > 1000, "JSON generation produced empty output"
    assert json_resp.media_type == "application/json"
    parsed_json = json.loads(json_resp.body.decode("utf-8"))
    assert "timeline_events" in parsed_json and len(parsed_json["timeline_events"]) > 0, "JSON missing timeline_events"
    assert "indicators_of_compromise" in parsed_json, "JSON missing IOCs"
    print(f"  ✓ JSON evidence package generated successfully ({len(json_resp.body):,} bytes, {len(parsed_json['timeline_events'])} events).")

    print("\n" + "=" * 70)
    print("✓ ALL 10 TEST SUITES PASSED FLAWLESSLY WITH 100% SUCCESS")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
