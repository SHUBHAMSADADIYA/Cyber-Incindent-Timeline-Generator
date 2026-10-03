import json
import uuid
from typing import List, Dict, Any, Tuple
from .canonical_parser import clean_val, clean_int

def parse_json_data(content: str, filename: str = "logs.json") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events = []
    errors = []

    try:
        data = json.loads(content)
    except Exception as e:
        return [], [{"source_file": filename, "row_index": 0, "error_reason": f"Invalid JSON syntax: {str(e)}", "raw_data": content[:200]}]

    if isinstance(data, dict):
        # Look for standard keys like 'events' or 'logs'
        for key in ['events', 'logs', 'records', 'data']:
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]

    if not isinstance(data, list):
        return [], [{"source_file": filename, "row_index": 0, "error_reason": "JSON must be an array of objects or contain an array", "raw_data": str(data)[:200]}]

    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            errors.append({
                "source_file": filename,
                "row_index": idx,
                "error_reason": "JSON array element is not an object",
                "raw_data": str(item)
            })
            continue

        raw_str = json.dumps(item)
        ts = clean_val(item.get('timestamp') or item.get('time') or item.get('datetime') or item.get('TimeCreated'))
        if not ts:
            errors.append({
                "source_file": filename,
                "row_index": idx,
                "error_reason": "Missing timestamp in JSON event",
                "raw_data": raw_str
            })
            continue

        evt = {
            "event_id_unique": clean_val(item.get('event_id_unique')) or f"JSON-{uuid.uuid4().hex[:8].upper()}-{idx}",
            "timestamp": ts,
            "log_source": clean_val(item.get('log_source') or item.get('source_type') or item.get('source')) or "JSON",
            "event_id": clean_val(item.get('event_id')),
            "event_type": clean_val(item.get('event_type')) or "Application Event",
            "severity": clean_val(item.get('severity') or item.get('level')) or "Informational",
            "action": clean_val(item.get('action')) or "Logged",
            "username": clean_val(item.get('username') or item.get('user')),
            "source_ip": clean_val(item.get('source_ip') or item.get('src_ip')),
            "destination_ip": clean_val(item.get('destination_ip') or item.get('dst_ip')),
            "source_port": clean_int(item.get('source_port') or item.get('src_port')),
            "destination_port": clean_int(item.get('destination_port') or item.get('dst_port')),
            "protocol": clean_val(item.get('protocol')),
            "hostname": clean_val(item.get('hostname') or item.get('host')),
            "device_type": clean_val(item.get('device_type')),
            "department": clean_val(item.get('department')),
            "country": clean_val(item.get('country')),
            "session_id": clean_val(item.get('session_id')),
            "correlation_id": clean_val(item.get('correlation_id')),
            "process_name": clean_val(item.get('process_name') or item.get('process')),
            "file_name": clean_val(item.get('file_name')),
            "file_hash": clean_val(item.get('file_hash') or item.get('hash')),
            "bytes_sent": clean_int(item.get('bytes_sent')),
            "bytes_received": clean_int(item.get('bytes_received')),
            "response_code": clean_val(item.get('response_code')),
            "description": clean_val(item.get('description') or item.get('message')),
            "status": clean_val(item.get('status')) or "Logged",
            "raw_record": raw_str,
            "source_file": filename,
            "source_row_index": idx
        }
        events.append(evt)

    return events, errors
