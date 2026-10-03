from typing import Dict, Any

RULES_EXPLANATION = {
    "AUTH_SUCCESS": "Windows Event 4624 or SSH Accepted -> Successful Authentication",
    "AUTH_FAIL": "Windows Event 4625 or SSH Failed password -> Failed Authentication Attempt",
    "PRIV_ESC": "Special privileges assigned (Event 4672/4673) or Linux Sudo invocation -> Privilege Escalation",
    "PROC_EXEC": "Process creation event (Event 4688 or sys process) -> Process Execution",
    "FILE_ACC": "File copied/read/modified -> File System Activity",
    "NET_BLOCK": "Firewall connection blocked or UFW drop -> Inbound/Outbound Connection Blocked",
    "NET_ALLOW": "Firewall connection allowed -> Authorized Network Traffic",
    "WEB_ATTACK": "Keywords 'SQL Injection' or 'Unauthorized API' -> Web Application Attack",
    "EXFIL": "Data exfiltration pattern detected -> Data Exfiltration Attempt",
    "THREAT_EXEC": "Execution of suspicious payload via curl/bash/powershell -> Threat Payload Execution",
}

def classify_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transparent, rule-based classification based on explicit security signatures.
    """
    classified = dict(record)
    
    eid = str(classified.get("event_id") or "")
    source = str(classified.get("log_source") or "").lower()
    desc = str(classified.get("description") or "").lower()
    action = str(classified.get("action") or "").lower()
    
    # 1. Critical Threats
    if "sql injection" in desc or "unauthorized api" in desc:
        classified["event_type"] = "Web Application Attack"
        classified["severity"] = "Critical"
        classified["action"] = "Attack Blocked / Detected"
        return classified

    if "exfiltration" in desc:
        classified["event_type"] = "Data Exfiltration"
        classified["severity"] = "Critical"
        return classified

    if "curl" in desc and ("bash" in desc or "sh" in desc):
        classified["event_type"] = "Threat Payload Execution"
        classified["severity"] = "Critical"
        classified["action"] = "Command Executed"
        return classified

    # 2. Windows Specific Rules
    if source == "windows" or eid in ["4624", "4625", "4672", "4673", "4688", "4720", "5128"]:
        if eid == "4624" or ("logon" in desc and "failed" not in desc):
            classified["event_type"] = "Authentication"
            classified["action"] = "Successful Login"
            classified["severity"] = "Low"
        elif eid == "4625" or "failed login" in desc:
            classified["event_type"] = "Authentication"
            classified["action"] = "Failed Login"
            classified["severity"] = "High"
        elif eid in ["4672", "4673"] or "privilege" in desc:
            classified["event_type"] = "Privilege Escalation"
            classified["severity"] = "Medium"
        elif eid == "4688" or "process" in desc:
            classified["event_type"] = "Process Creation"
            classified["severity"] = "Low"
        elif eid == "5128":
            classified["event_type"] = "System Error"
            classified["severity"] = "Critical"
        elif "ddos" in desc:
            classified["event_type"] = "DDoS Attack"
            classified["severity"] = "High"
        return classified

    # 3. Linux Specific Rules
    if source == "linux":
        if "invalid user" in desc or "failed password" in desc or "authentication failure" in desc:
            classified["event_type"] = "Authentication"
            classified["action"] = "Failed Login"
            classified["severity"] = "High"
        elif "accepted publickey" in desc or "accepted password" in desc:
            classified["event_type"] = "Authentication"
            classified["action"] = "Successful Login"
            classified["severity"] = "Low"
        elif "sudo" in desc:
            classified["event_type"] = "Privilege Escalation"
            classified["severity"] = "Medium"
        elif "ufw block" in desc or "ban" in desc:
            classified["event_type"] = "Network Security"
            classified["action"] = "Blocked"
            classified["severity"] = "High"
        elif "ufw allow" in desc:
            classified["event_type"] = "Network Security"
            classified["action"] = "Allowed"
            classified["severity"] = "Low"
        elif "auditd" in desc or "execve" in desc:
            classified["event_type"] = "Process Execution"
            classified["severity"] = "High"
        return classified

    # 4. Firewall Specific Rules
    if source == "firewall":
        if "blocked" in action or "rejected" in action:
            classified["event_type"] = "Firewall Filter"
            classified["severity"] = "High"
        elif "port scan" in desc or "fw-003" in eid.lower():
            classified["event_type"] = "Reconnaissance (Port Scan)"
            classified["severity"] = "High"
        else:
            classified["event_type"] = "Firewall Filter"
            classified["severity"] = "Low"
        return classified

    # Fallback to existing or Informational
    if not classified.get("event_type"):
        classified["event_type"] = "System Event"
        
    return classified
