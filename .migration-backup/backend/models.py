from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class EventModel(BaseModel):
    id: Optional[int] = None
    event_id_unique: str
    timestamp: Optional[str] = None
    log_source: Optional[str] = None
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    department: Optional[str] = None
    country: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    process_name: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    response_code: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    raw_record: Optional[str] = None
    source_file: Optional[str] = None
    source_row_index: Optional[int] = None

class EventFilterQuery(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    log_source: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    ip: Optional[str] = None
    username: Optional[str] = None
    correlation_id: Optional[str] = None
    search: Optional[str] = None
    limit: int = 50
    offset: int = 0
    sort_by: str = "timestamp"
    sort_order: str = "ASC"

class CaseNoteUpdate(BaseModel):
    case_id: str = "CASE-001"
    title: Optional[str] = None
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    notes: str

class IOCStatusUpdate(BaseModel):
    indicator_value: str
    analyst_status: str  # 'Observed', 'Confirmed Threat', 'False Positive'
    notes: Optional[str] = None

class ReportRequest(BaseModel):
    scope: str = "filtered"  # 'filtered', 'all', 'incident'
    correlation_id: Optional[str] = None
    report_title: str = "Cyber Incident Investigation Report"
    include_raw_logs: bool = False
    include_iocs: bool = True
    include_notes: bool = True
