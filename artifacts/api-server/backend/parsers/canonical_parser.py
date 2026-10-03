import csv
import io
import uuid
from typing import List, Dict, Any, Tuple

CANONICAL_FIELDS = [
    "event_id_unique", "timestamp", "log_source", "event_id", "event_type",
    "severity", "action", "username", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol", "hostname", "device_type",
    "department", "country", "session_id", "correlation_id", "process_name",
    "file_name", "file_hash", "bytes_sent", "bytes_received", "response_code",
    "description", "status"
]

def clean_val(val: Any) -> Any:
    if val is None:
        return None
    s = str(val).strip()
    if s == "" or s == "-" or s.lower() == "none" or s.lower() == "nan" or s.lower() == "null":
        return None
    return s

def clean_int(val: Any) -> Any:
    cleaned = clean_val(val)
    if cleaned is None:
        return None
    try:
        return int(float(cleaned))
    except (ValueError, TypeError):
        return None

def parse_canonical_csv(content: str, filename: str = "dataset.csv") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events = []
    errors = []

    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return [], [{"source_file": filename, "row_index": 0, "error_reason": "Empty CSV or no header found", "raw_data": content[:100]}]

    field_map = {f.strip().lower(): f for f in reader.fieldnames if f}

    for row_idx, row in enumerate(reader, start=1):
        try:
            raw_line = ",".join(str(v) for v in row.values())
            
            # Find timestamp
            ts_key = next((k for k in ['timestamp', 'time', 'datetime', 'timecreated'] if k in field_map), None)
            timestamp = clean_val(row.get(field_map[ts_key])) if ts_key else None

            if not timestamp:
                errors.append({
                    "source_file": filename,
                    "row_index": row_idx,
                    "error_reason": "Missing or null timestamp in canonical row",
                    "raw_data": raw_line
                })
                continue

            event_id_unique = clean_val(row.get(field_map.get('event_id_unique', '')))
            if not event_id_unique:
                event_id_unique = f"EVT-{row_idx:08d}"

            log_source = clean_val(row.get(field_map.get('log_source', ''))) or "Unknown"
            event_id = clean_val(row.get(field_map.get('event_id', '')))
            event_type = clean_val(row.get(field_map.get('event_type', ''))) or "Security Event"
            severity = clean_val(row.get(field_map.get('severity', ''))) or "Informational"
            action = clean_val(row.get(field_map.get('action', ''))) or "Logged"
            username = clean_val(row.get(field_map.get('username', '')))
            source_ip = clean_val(row.get(field_map.get('source_ip', '')))
            destination_ip = clean_val(row.get(field_map.get('destination_ip', '')))
            source_port = clean_int(row.get(field_map.get('source_port', '')))
            destination_port = clean_int(row.get(field_map.get('destination_port', '')))
            protocol = clean_val(row.get(field_map.get('protocol', '')))
            hostname = clean_val(row.get(field_map.get('hostname', '')))
            device_type = clean_val(row.get(field_map.get('device_type', '')))
            department = clean_val(row.get(field_map.get('department', '')))
            country = clean_val(row.get(field_map.get('country', '')))
            session_id = clean_val(row.get(field_map.get('session_id', '')))
            correlation_id = clean_val(row.get(field_map.get('correlation_id', '')))
            process_name = clean_val(row.get(field_map.get('process_name', '')))
            file_name = clean_val(row.get(field_map.get('file_name', '')))
            file_hash = clean_val(row.get(field_map.get('file_hash', '')))
            bytes_sent = clean_int(row.get(field_map.get('bytes_sent', '')))
            bytes_received = clean_int(row.get(field_map.get('bytes_received', '')))
            response_code = clean_val(row.get(field_map.get('response_code', '')))
            description = clean_val(row.get(field_map.get('description', '')))
            if not description:
                description = f"{log_source} {event_type} {action or ''}".strip()
            status = clean_val(row.get(field_map.get('status', ''))) or "Logged"

            event_record = {
                "event_id_unique": event_id_unique,
                "timestamp": timestamp,
                "log_source": log_source,
                "event_id": event_id,
                "event_type": event_type,
                "severity": severity,
                "action": action,
                "username": username,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol,
                "hostname": hostname,
                "device_type": device_type,
                "department": department,
                "country": country,
                "session_id": session_id,
                "correlation_id": correlation_id,
                "process_name": process_name,
                "file_name": file_name,
                "file_hash": file_hash,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "response_code": response_code,
                "description": description,
                "status": status,
                "raw_record": raw_line,
                "source_file": filename,
                "source_row_index": row_idx
            }
            events.append(event_record)

        except Exception as e:
            errors.append({
                "source_file": filename,
                "row_index": row_idx,
                "error_reason": f"Row exception: {str(e)}",
                "raw_data": str(row)
            })

    return events, errors
