import re
from typing import List, Dict, Any
from ..database import get_connection

DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|sh|ru|io|xyz|top|cc|info)\b', re.IGNORECASE)
HASH_SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
HASH_MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')

SUSPICIOUS_PORTS = {
    22: "SSH Remote Access (Port 22)",
    23: "Telnet Cleartext Protocol (Port 23)",
    135: "Windows RPC Service (Port 135)",
    139: "NetBIOS Session Service (Port 139)",
    445: "SMB File Sharing / Lateral Movement (Port 445)",
    3389: "Remote Desktop Protocol RDP (Port 3389)",
    5128: "SQL Database Protocol (Port 5128)"
}

def is_public_ipv4(ip: str) -> bool:
    if not ip or ip == "-":
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return False
        if p0 == 172 and (16 <= p1 <= 31):
            return False
        if p0 == 192 and p1 == 168:
            return False
        if p0 == 127:
            return False
        return True
    except Exception:
        return False

def extract_and_sync_iocs(events: List[Dict[str, Any]]):
    """
    Extracts Indicators of Compromise from events according to documented rules
    and synchronizes them into the SQLite iocs table, preserving analyst confirmations.
    """
    if not events:
        return

    extracted = {}

    for evt in events:
        ts = evt.get("timestamp") or "Unknown"
        desc = str(evt.get("description") or "")
        raw = str(evt.get("raw_record") or "")
        combined_text = f"{desc} {raw}"

        # 1. Check Public IPs in high/critical or blocked events
        for ip_field in ["source_ip", "destination_ip"]:
            ip_val = evt.get(ip_field)
            if ip_val and is_public_ipv4(ip_val):
                rule = "Public Inbound/Outbound IP"
                if evt.get("severity") in ["High", "Critical"] or "block" in str(evt.get("action")).lower():
                    rule = f"Suspicious External IP ({evt.get('action') or 'Alert'})"
                
                if ip_val not in extracted:
                    extracted[ip_val] = {
                        "type": "IP Address",
                        "first_seen": ts,
                        "last_seen": ts,
                        "count": 1,
                        "rule": rule
                    }
                else:
                    extracted[ip_val]["count"] += 1
                    if ts < extracted[ip_val]["first_seen"]:
                        extracted[ip_val]["first_seen"] = ts
                    if ts > extracted[ip_val]["last_seen"]:
                        extracted[ip_val]["last_seen"] = ts

        # 2. Check Suspicious Ports
        for p_field in ["source_port", "destination_port"]:
            p_val = evt.get(p_field)
            if p_val and int(p_val) in SUSPICIOUS_PORTS:
                port_str = f"Port {p_val}"
                rule = SUSPICIOUS_PORTS[int(p_val)]
                if port_str not in extracted:
                    extracted[port_str] = {
                        "type": "Suspicious Port",
                        "first_seen": ts,
                        "last_seen": ts,
                        "count": 1,
                        "rule": rule
                    }
                else:
                    extracted[port_str]["count"] += 1

        # 3. Check File Hashes
        f_hash = evt.get("file_hash")
        if f_hash and f_hash != "-":
            h_clean = f_hash.strip().lower()
            if len(h_clean) in [32, 64]:
                h_type = "SHA256 Hash" if len(h_clean) == 64 else "MD5 Hash"
                if h_clean not in extracted:
                    extracted[h_clean] = {
                        "type": h_type,
                        "first_seen": ts,
                        "last_seen": ts,
                        "count": 1,
                        "rule": f"Observed Artifact Hash ({evt.get('file_name') or 'unknown'})"
                    }
                else:
                    extracted[h_clean]["count"] += 1

        # 4. Check Domains in text
        for domain in DOMAIN_REGEX.findall(combined_text):
            d_clean = domain.lower()
            if d_clean not in ["example.com", "schema.org"]:
                if d_clean not in extracted:
                    extracted[d_clean] = {
                        "type": "Domain Name",
                        "first_seen": ts,
                        "last_seen": ts,
                        "count": 1,
                        "rule": "Observed Network / URI Indicator"
                    }
                else:
                    extracted[d_clean]["count"] += 1

    # Sync to SQLite without overwriting existing analyst confirmation
    conn = get_connection()
    cursor = conn.cursor()

    for val, meta in extracted.items():
        cursor.execute("SELECT analyst_status, notes FROM iocs WHERE indicator_value = ?", (val,))
        existing = cursor.fetchone()

        if existing:
            # Preserve analyst status and notes
            cursor.execute("""
                UPDATE iocs
                SET first_seen = MIN(first_seen, ?),
                    last_seen = MAX(last_seen, ?),
                    occurrence_count = occurrence_count + ?
                WHERE indicator_value = ?
            """, (meta["first_seen"], meta["last_seen"], meta["count"], val))
        else:
            # New indicator: default to 'Observed'
            cursor.execute("""
                INSERT INTO iocs (indicator_value, indicator_type, first_seen, last_seen, occurrence_count, detection_rule, analyst_status, notes)
                VALUES (?, ?, ?, ?, ?, ?, 'Observed', '')
            """, (val, meta["type"], meta["first_seen"], meta["last_seen"], meta["count"], meta["rule"]))

    conn.commit()
    conn.close()
