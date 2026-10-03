import re
from typing import Dict, Any, Tuple, Optional

IPV4_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

def is_valid_ipv4(ip: Optional[str]) -> bool:
    if not ip:
        return True  # Absent is valid
    s = str(ip).strip()
    if not IPV4_REGEX.match(s):
        return False
    octets = s.split('.')
    return all(0 <= int(o) <= 255 for o in octets)

def clean_and_validate_record(record: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Cleans values without changing evidence.
    Returns (cleaned_record, warning_message_or_None)
    """
    cleaned = dict(record)
    warning = None

    # Validate source IP
    src_ip = cleaned.get("source_ip")
    if src_ip and not is_valid_ipv4(src_ip):
        warning = f"Invalid IPv4 syntax in source_ip: {src_ip}"
        # Keep raw_record intact, set source_ip to None or keep note
        cleaned["source_ip"] = None

    # Validate destination IP
    dst_ip = cleaned.get("destination_ip")
    if dst_ip and not is_valid_ipv4(dst_ip):
        warning = f"Invalid IPv4 syntax in destination_ip: {dst_ip}"
        cleaned["destination_ip"] = None

    # Validate ports
    for p_field in ["source_port", "destination_port"]:
        port_val = cleaned.get(p_field)
        if port_val is not None:
            try:
                p_int = int(port_val)
                if not (1 <= p_int <= 65535):
                    cleaned[p_field] = None
                    warning = f"Port out of range (1-65535): {port_val}"
                else:
                    cleaned[p_field] = p_int
            except (ValueError, TypeError):
                cleaned[p_field] = None
                warning = f"Invalid numeric port: {port_val}"

    # Trim string fields safely
    for key, val in cleaned.items():
        if isinstance(val, str):
            trimmed = val.strip()
            if trimmed in ["", "-", "None", "nan", "null", "—"]:
                cleaned[key] = None
            else:
                cleaned[key] = trimmed

    return cleaned, warning
