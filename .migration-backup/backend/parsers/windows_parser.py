import re
import csv
import io
import uuid
from typing import List, Dict, Any, Tuple

IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
USER_REGEX = re.compile(r'(?:user|account|logon as)[:\s]+([a-zA-Z0-9_\-\\]+)', re.IGNORECASE)

def parse_windows_csv(content: str, filename: str = "windows_events.csv") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses Windows Event Log CSV.
    Expected columns: TimeCreated, Computer, Level, Message, EventID (optional)
    """
    events = []
    errors = []
    
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return [], [{"source_file": filename, "row_index": 0, "error_reason": "Empty CSV or no header found", "raw_data": content[:100]}]
    
    # Normalize fieldnames map (case insensitive)
    field_map = {f.strip().lower(): f for f in reader.fieldnames if f}

    for row_idx, row in enumerate(reader, start=1):
        try:
            raw_line = ",".join(str(v) for v in row.values())
            
            # Extract timestamp
            ts_key = next((k for k in ['timecreated', 'timestamp', 'time', 'date_time', 'datetime'] if k in field_map), None)
            timestamp = row.get(field_map[ts_key], "").strip() if ts_key else ""
            
            if not timestamp:
                errors.append({
                    "source_file": filename,
                    "row_index": row_idx,
                    "error_reason": "Missing timestamp in Windows event",
                    "raw_data": raw_line
                })
                continue
            
            # Hostname / Computer
            comp_key = next((k for k in ['computer', 'hostname', 'host', 'computername'] if k in field_map), None)
            hostname = row.get(field_map[comp_key], "").strip() if comp_key else ""
            
            # Severity / Level
            lvl_key = next((k for k in ['level', 'severity', 'type'] if k in field_map), None)
            level = row.get(field_map[lvl_key], "").strip() if lvl_key else "Informational"
            
            # Message / Description
            msg_key = next((k for k in ['message', 'description', 'details'] if k in field_map), None)
            message = row.get(field_map[msg_key], "").strip() if msg_key else ""
            
            # EventID
            eid_key = next((k for k in ['eventid', 'event_id', 'id'] if k in field_map), None)
            event_id = row.get(field_map[eid_key], "").strip() if eid_key else ""
            
            # Action and username inference from message
            extracted_ips = IP_REGEX.findall(message)
            source_ip = extracted_ips[0] if extracted_ips else None
            
            extracted_users = USER_REGEX.findall(message)
            username = extracted_users[0] if extracted_users else None
            
            # Classification
            event_type = "Authentication"
            if "logon" in message.lower() or "login" in message.lower() or event_id in ["4624", "4625"]:
                event_type = "Authentication"
                action = "Successful" if "success" in message.lower() or event_id == "4624" else "Failed"
            elif "privilege" in message.lower() or event_id in ["4672", "4673"]:
                event_type = "Privilege Escalation"
                action = "Special Privileges Assigned"
            elif "process" in message.lower() or event_id == "4688":
                event_type = "Process Creation"
                action = "Process Created"
            elif "file" in message.lower() or "access" in message.lower():
                event_type = "File Access"
                action = "Access Denied" if "denied" in message.lower() else "File Accessed"
            elif "firewall" in message.lower() or "rule" in message.lower():
                event_type = "Network Policy"
                action = "Policy Applied"
            elif "ddos" in message.lower() or "attack" in message.lower():
                event_type = "Security Alert"
                action = "Attack Detected"
            else:
                event_type = "System Event"
                action = "Logged"

            # Severity mapping
            lvl_lower = level.lower()
            if "crit" in lvl_lower or "5128" in event_id:
                severity = "Critical"
            elif "err" in lvl_lower or "denied" in message.lower():
                severity = "High"
            elif "warn" in lvl_lower:
                severity = "Medium"
            else:
                severity = "Low"

            # Device type
            device_type = "Domain Controller" if "DC" in hostname else ("Server" if "SERVER" in hostname else "Workstation")

            event_record = {
                "event_id_unique": f"WIN-{uuid.uuid4().hex[:8].upper()}-{row_idx}",
                "timestamp": timestamp,
                "log_source": "Windows",
                "event_id": event_id or None,
                "event_type": event_type,
                "severity": severity,
                "action": action,
                "username": username,
                "source_ip": source_ip,
                "destination_ip": None,
                "source_port": None,
                "destination_port": None,
                "protocol": "TCP" if source_ip else None,
                "hostname": hostname or None,
                "device_type": device_type,
                "department": None,
                "country": None,
                "session_id": None,
                "correlation_id": None,
                "process_name": None,
                "file_name": None,
                "file_hash": None,
                "bytes_sent": None,
                "bytes_received": None,
                "response_code": None,
                "description": message,
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
                "error_reason": f"Row parsing exception: {str(e)}",
                "raw_data": str(row)
            })

    return events, errors
