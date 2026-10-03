import uuid
from typing import List, Dict, Any
from collections import defaultdict

def correlate_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Correlates events across log sources based on:
    1. Pre-existing correlation_id
    2. Identical session_id
    3. External suspicious IPs participating across multiple sources
    4. Compromised username pivot
    """
    if not events:
        return []

    # Map of IP -> list of event indices
    ip_to_indices = defaultdict(list)
    user_to_indices = defaultdict(list)
    session_to_indices = defaultdict(list)

    for idx, evt in enumerate(events):
        sip = evt.get("source_ip")
        dip = evt.get("destination_ip")
        user = evt.get("username")
        session = evt.get("session_id")
        
        if sip:
            ip_to_indices[sip].append(idx)
        if dip:
            ip_to_indices[dip].append(idx)
        if user and user.lower() not in ["-", "unknown", "none", "system"]:
            user_to_indices[user.lower()].append(idx)
        if session:
            session_to_indices[session].append(idx)

    # Detect multi-source suspicious IP clusters
    # e.g., IPs that appear in 2 or more distinct log sources or have High/Critical severity
    ip_cluster_id = {}
    for ip, indices in ip_to_indices.items():
        if len(indices) >= 2:
            sources = set(events[i].get("log_source") for i in indices)
            has_alert = any(events[i].get("severity") in ["High", "Critical"] for i in indices)
            if len(sources) > 1 or has_alert:
                ip_clean = ip.replace(".", "-")
                ip_cluster_id[ip] = f"INC-IP-{ip_clean}"

    # Assign or preserve correlation IDs
    correlated = []
    for idx, evt in enumerate(events):
        record = dict(evt)
        existing_corr = record.get("correlation_id")

        if existing_corr and existing_corr != "-":
            record["correlation_id"] = existing_corr
        elif record.get("session_id") and len(session_to_indices[record["session_id"]]) > 1:
            record["correlation_id"] = f"INC-SES-{record['session_id'][:8].upper()}"
        elif record.get("source_ip") in ip_cluster_id:
            record["correlation_id"] = ip_cluster_id[record["source_ip"]]
        elif record.get("destination_ip") in ip_cluster_id:
            record["correlation_id"] = ip_cluster_id[record["destination_ip"]]
        else:
            # Standalone or unclustered
            record["correlation_id"] = None

        correlated.append(record)

    return correlated
