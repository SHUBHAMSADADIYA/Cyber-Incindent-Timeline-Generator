import re
from datetime import datetime, timezone
from dateutil import parser as dt_parser
from typing import Optional, Dict, Any

SEVERITY_MAP = {
    "crit": "Critical",
    "critical": "Critical",
    "fatal": "Critical",
    "emergency": "Critical",
    "alert": "Critical",
    "err": "High",
    "error": "High",
    "high": "High",
    "blocked": "High",
    "denied": "High",
    "attack": "High",
    "warn": "Medium",
    "warning": "Medium",
    "medium": "Medium",
    "anomaly": "Medium",
    "info": "Informational",
    "informational": "Informational",
    "notice": "Informational",
    "debug": "Informational",
    "low": "Low",
    "allowed": "Low",
    "accepted": "Low",
    "success": "Low",
    "successful": "Low"
}

def normalize_timestamp(ts_str: Optional[str]) -> Optional[str]:
    if not ts_str:
        return None
    s = str(ts_str).strip()
    if not s or s.lower() in ["none", "nan", "null", "—", "-"]:
        return None

    # Handle common ISO formats first for speed (e.g. 2026-05-06 11:43:35 or 2024-01-15T08:23:45Z)
    try:
        if len(s) >= 10 and s[2] == '-' and s[5] == '-':
            # European format DD-MM-YYYY HH:MM:SS
            parts = s.split(' ')
            d, m, y = parts[0].split('-')
            tm = parts[1] if len(parts) > 1 else '00:00:00'
            if len(tm) == 5:
                tm += ':00'
            return f"{y}-{m.zfill(2)}-{d.zfill(2)} {tm}"
        if len(s) == 19 and s[4] == '-' and s[7] == '-' and (s[10] == ' ' or s[10] == 'T'):
            return s[:10] + " " + s[11:19]
        if len(s) == 16 and s[4] == '-' and s[7] == '-' and (s[10] == ' ' or s[10] == 'T'):
            return s[:10] + " " + s[11:16] + ":00"

        dt = dt_parser.parse(s, dayfirst=True)
        # Standardize to naive UTC representation: YYYY-MM-DD HH:MM:SS
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def normalize_severity(sev_str: Optional[str]) -> str:
    if not sev_str:
        return "Informational"
    s = str(sev_str).strip().lower()
    for prefix, mapped in SEVERITY_MAP.items():
        if prefix in s:
            return mapped
    return "Medium"

def normalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    norm = dict(record)
    norm["timestamp"] = normalize_timestamp(norm.get("timestamp"))
    norm["severity"] = normalize_severity(norm.get("severity"))
    
    if norm.get("protocol"):
        norm["protocol"] = str(norm["protocol"]).strip().upper()
    if norm.get("action"):
        norm["action"] = str(norm["action"]).strip().capitalize()
    if norm.get("status"):
        norm["status"] = str(norm["status"]).strip().capitalize()
    if norm.get("log_source"):
        norm["log_source"] = str(norm["log_source"]).strip().capitalize()
        
    return norm
