import csv
import io
import uuid
from typing import List, Dict, Any, Tuple

def parse_firewall_csv(content: str, filename: str = "firewall_logs.csv") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses Firewall CSV logs.
    Expected columns: date, time, src_ip, dst_ip, src_port, dst_port, action, protocol
    """
    events = []
    errors = []

    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return [], [{"source_file": filename, "row_index": 0, "error_reason": "Empty CSV or missing header", "raw_data": content[:100]}]

    field_map = {f.strip().lower(): f for f in reader.fieldnames if f}

    for row_idx, row in enumerate(reader, start=1):
        try:
            raw_line = ",".join(str(v) for v in row.values())

            # Combine date and time
            date_col = next((k for k in ['date', 'event_date'] if k in field_map), None)
            time_col = next((k for k in ['time', 'event_time'] if k in field_map), None)
            
            raw_date = row.get(field_map[date_col], "").strip() if date_col else ""
            raw_time = row.get(field_map[time_col], "").strip() if time_col else ""

            if raw_date and raw_time:
                timestamp = f"{raw_date} {raw_time}"
            elif 'timestamp' in field_map:
                timestamp = row.get(field_map['timestamp'], "").strip()
            else:
                timestamp = raw_date or raw_time

            if not timestamp:
                errors.append({
                    "source_file": filename,
                    "row_index": row_idx,
                    "error_reason": "Missing timestamp in firewall event",
                    "raw_data": raw_line
                })
                continue

            src_ip_col = next((k for k in ['src_ip', 'source_ip', 'src'] if k in field_map), None)
            dst_ip_col = next((k for k in ['dst_ip', 'destination_ip', 'dst'] if k in field_map), None)
            src_port_col = next((k for k in ['src_port', 'source_port', 'spt'] if k in field_map), None)
            dst_port_col = next((k for k in ['dst_port', 'destination_port', 'dpt'] if k in field_map), None)
            act_col = next((k for k in ['action', 'act'] if k in field_map), None)
            proto_col = next((k for k in ['protocol', 'proto'] if k in field_map), None)

            source_ip = row.get(field_map[src_ip_col], "").strip() if src_ip_col else None
            destination_ip = row.get(field_map[dst_ip_col], "").strip() if dst_ip_col else None
            
            src_port_raw = row.get(field_map[src_port_col], "").strip() if src_port_col else None
            dst_port_raw = row.get(field_map[dst_port_col], "").strip() if dst_port_col else None
            
            source_port = int(src_port_raw) if src_port_raw and src_port_raw.isdigit() else None
            destination_port = int(dst_port_raw) if dst_port_raw and dst_port_raw.isdigit() else None
            
            action = row.get(field_map[act_col], "").strip().upper() if act_col else "UNKNOWN"
            protocol = row.get(field_map[proto_col], "").strip().upper() if proto_col else "TCP"

            is_blocked = action in ["BLOCKED", "DROP", "DENIED", "REJECTED"]
            severity = "High" if is_blocked else "Low"
            event_type = "Firewall Filter"
            description = f"Firewall {action} {protocol} connection from {source_ip or 'unknown'}:{source_port or '-'} to {destination_ip or 'unknown'}:{destination_port or '-'}"

            event_record = {
                "event_id_unique": f"FW-{uuid.uuid4().hex[:8].upper()}-{row_idx}",
                "timestamp": timestamp,
                "log_source": "Firewall",
                "event_id": f"FW-{action}",
                "event_type": event_type,
                "severity": severity,
                "action": action.capitalize(),
                "username": None,
                "source_ip": source_ip or None,
                "destination_ip": destination_ip or None,
                "source_port": source_port,
                "destination_port": destination_port,
                "protocol": protocol or None,
                "hostname": "FIREWALL-01",
                "device_type": "Firewall",
                "department": "Security Infrastructure",
                "country": None,
                "session_id": None,
                "correlation_id": None,
                "process_name": None,
                "file_name": None,
                "file_hash": None,
                "bytes_sent": None,
                "bytes_received": None,
                "response_code": None,
                "description": description,
                "status": "Logged",
                "raw_record": raw_line,
                "source_file": filename,
                "source_row_index": row_idx
            }
            events.append(event_record)

        except Exception as e:
            errors.append({
                "source_file": filename,
                "row_index": row_idx,
                "error_reason": f"Firewall row parsing exception: {str(e)}",
                "raw_data": str(row)
            })

    return events, errors
