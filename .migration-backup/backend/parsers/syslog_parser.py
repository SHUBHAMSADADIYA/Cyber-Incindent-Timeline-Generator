import re
import uuid
from datetime import datetime
from typing import List, Dict, Any, Tuple

# Standard syslog pattern: "Jan 15 08:23:45 LINUX01 process[1234]: message"
SYSLOG_REGEX = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$'
)

IP_SRC_REGEX = re.compile(r'(?:SRC=|from\s+)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')
IP_DST_REGEX = re.compile(r'DST=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')
PORT_SRC_REGEX = re.compile(r'(?:SPT=|port\s+)(\d+)')
PORT_DST_REGEX = re.compile(r'DPT=(\d+)')
PROTO_REGEX = re.compile(r'PROTO=([A-Za-z]+)')
USER_REGEX = re.compile(r'(?:user\s+|USER=)([a-zA-Z0-9_\-]+)')

def parse_syslog_text(content: str, filename: str = "syslog.log", default_year: int = 2024) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events = []
    errors = []
    lines = content.splitlines()

    for row_idx, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str:
            continue

        match = SYSLOG_REGEX.match(line_str)
        if not match:
            errors.append({
                "source_file": filename,
                "row_index": row_idx,
                "error_reason": "Line did not match standard Syslog format",
                "raw_data": line_str
            })
            continue

        raw_ts, hostname, process_name, pid, message = match.groups()

        # Parse syslog timestamp adding the year
        try:
            parsed_dt = datetime.strptime(f"{default_year} {raw_ts}", "%Y %b %d %H:%M:%S")
            timestamp = parsed_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            timestamp = f"{default_year}-{raw_ts}"

        # Extract embedded fields from message
        src_ip_m = IP_SRC_REGEX.search(message)
        dst_ip_m = IP_DST_REGEX.search(message)
        spt_m = PORT_SRC_REGEX.search(message)
        dpt_m = PORT_DST_REGEX.search(message)
        proto_m = PROTO_REGEX.search(message)
        user_m = USER_REGEX.search(message)

        source_ip = src_ip_m.group(1) if src_ip_m else None
        destination_ip = dst_ip_m.group(1) if dst_ip_m else None
        source_port = int(spt_m.group(1)) if spt_m else None
        destination_port = int(dpt_m.group(1)) if dpt_m else None
        protocol = proto_m.group(1) if proto_m else ("TCP" if source_port or destination_port else None)
        username = user_m.group(1) if user_m else None

        # Severity and classification
        msg_lower = message.lower()
        if "curl" in msg_lower or "malicious" in msg_lower or "kill process" in msg_lower:
            severity = "Critical"
            event_type = "Threat Execution"
            action = "Execution Blocked / Monitored"
        elif "ufw block" in msg_lower or "failed" in msg_lower or "invalid user" in msg_lower or "ban" in msg_lower or "authentication failure" in msg_lower:
            severity = "High"
            event_type = "Access Violation"
            action = "Blocked" if "block" in msg_lower or "ban" in msg_lower else "Failed Authentication"
        elif "sudo" in msg_lower or "shadow" in msg_lower:
            severity = "Medium"
            event_type = "Privilege Escalation"
            action = "Privilege Invoked"
        else:
            severity = "Low"
            event_type = "Service Operation"
            action = "Status Changed"

        event_record = {
            "event_id_unique": f"LNX-{uuid.uuid4().hex[:8].upper()}-{row_idx}",
            "timestamp": timestamp,
            "log_source": "Linux",
            "event_id": f"SYS-{process_name}",
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
            "device_type": "Linux Server",
            "department": "Engineering / Infrastructure",
            "country": None,
            "session_id": pid or None,
            "correlation_id": None,
            "process_name": process_name,
            "file_name": None,
            "file_hash": None,
            "bytes_sent": None,
            "bytes_received": None,
            "response_code": None,
            "description": message,
            "status": "Logged",
            "raw_record": line_str,
            "source_file": filename,
            "source_row_index": row_idx
        }
        events.append(event_record)

    return events, errors
