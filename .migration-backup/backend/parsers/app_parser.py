import re
import uuid
from typing import List, Dict, Any, Tuple

# Pattern: [TIMESTAMP] LEVEL - MESSAGE - User: USER IP: IP
APP_REGEX = re.compile(
    r'^\[(.*?)\]\s+([A-Z]+)\s+-\s+(.*?)(?:\s+-\s+User:\s+(\S+))?(?:\s+IP:\s+(\S+))?$'
)

def parse_app_text(content: str, filename: str = "app_logs.log") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events = []
    errors = []
    lines = content.splitlines()

    for row_idx, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str:
            continue

        match = APP_REGEX.match(line_str)
        if not match:
            # Fallback simple extractor
            if line_str.startswith("[") and "]" in line_str:
                ts = line_str[1:line_str.index("]")]
                rest = line_str[line_str.index("]") + 1:].strip()
                timestamp = ts
                severity = "Informational"
                description = rest
                username = None
                source_ip = None
            else:
                errors.append({
                    "source_file": filename,
                    "row_index": row_idx,
                    "error_reason": "Failed to parse application log format",
                    "raw_data": line_str
                })
                continue
        else:
            timestamp, raw_level, description, username, source_ip = match.groups()
            raw_lvl_up = (raw_level or "INFO").upper()
            if "CRIT" in raw_lvl_up:
                severity = "Critical"
            elif "ERR" in raw_lvl_up:
                severity = "High"
            elif "WARN" in raw_lvl_up:
                severity = "Medium"
            else:
                severity = "Low"

        # Classification from description
        desc_lower = (description or "").lower()
        if "sql injection" in desc_lower or "unauthorized" in desc_lower or "exfiltration" in desc_lower:
            event_type = "Web Application Attack"
            action = "Blocked" if "blocked" in desc_lower else "Alert Triggered"
            severity = "Critical"
        elif "login" in desc_lower or "authentication" in desc_lower:
            event_type = "Authentication"
            action = "Failed Login" if "failed" in desc_lower else "Successful Login"
        elif "privilege" in desc_lower:
            event_type = "Privilege Escalation"
            action = "Privilege Attempted"
        elif "file" in desc_lower:
            event_type = "File Operation"
            action = "File Uploaded"
        else:
            event_type = "Application Activity"
            action = "Executed"

        event_record = {
            "event_id_unique": f"APP-{uuid.uuid4().hex[:8].upper()}-{row_idx}",
            "timestamp": timestamp,
            "log_source": "Application",
            "event_id": f"APP-LOG",
            "event_type": event_type,
            "severity": severity,
            "action": action,
            "username": username if username and username != "-" else None,
            "source_ip": source_ip if source_ip and source_ip != "-" else None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": "HTTP/HTTPS",
            "hostname": "APP-01",
            "device_type": "Application Server",
            "department": "Digital Banking / Web Services",
            "country": None,
            "session_id": None,
            "correlation_id": None,
            "process_name": "webapp.py",
            "file_name": None,
            "file_hash": None,
            "bytes_sent": None,
            "bytes_received": None,
            "response_code": "200" if severity == "Low" else "403",
            "description": description,
            "status": "Logged",
            "raw_record": line_str,
            "source_file": filename,
            "source_row_index": row_idx
        }
        events.append(event_record)

    return events, errors
