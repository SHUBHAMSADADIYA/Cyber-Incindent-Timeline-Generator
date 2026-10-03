from typing import List, Dict, Any, Tuple
from datetime import datetime

def deduplicate_events(events: List[Dict[str, Any]], window_seconds: int = 5) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    High-performance O(N log N) deduplication.
    Identifies exact duplicates and rapid burst duplicates within sliding window.
    """
    if not events:
        return [], {
            "total_before": 0,
            "exact_duplicates_removed": 0,
            "similar_duplicates_removed": 0,
            "total_after": 0,
            "retention_rate": 100.0
        }

    total_before = len(events)
    seen_exact = set()
    first_pass = []
    exact_removed = 0

    # Step 1: Remove exact duplicates
    for evt in events:
        key = (
            evt.get("timestamp"),
            evt.get("log_source"),
            evt.get("source_ip"),
            evt.get("destination_ip"),
            evt.get("source_port"),
            evt.get("destination_port"),
            evt.get("action"),
            evt.get("event_type"),
            evt.get("username"),
            evt.get("description")
        )
        if key in seen_exact:
            exact_removed += 1
            continue
        seen_exact.add(key)
        first_pass.append(evt)

    # Step 2: Detect burst similar duplicates within time window
    # Sort by timestamp for linear sliding-window comparison
    sorted_events = sorted(
        first_pass,
        key=lambda x: (x.get("timestamp") or "", x.get("event_id_unique") or "")
    )

    deduped = []
    similar_removed = 0
    recent_events_by_flow = {}

    for evt in sorted_events:
        flow_key = (
            evt.get("source_ip"),
            evt.get("destination_ip"),
            evt.get("action"),
            evt.get("log_source")
        )
        ts_str = evt.get("timestamp")
        
        is_duplicate = False
        if ts_str and flow_key in recent_events_by_flow:
            prev_ts_str = recent_events_by_flow[flow_key]
            try:
                dt_curr = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                dt_prev = datetime.strptime(prev_ts_str[:19], "%Y-%m-%d %H:%M:%S")
                diff = abs((dt_curr - dt_prev).total_seconds())
                if diff <= window_seconds and evt.get("event_type") == "Firewall Filter":
                    # Rapid firewall packet burst
                    is_duplicate = True
            except Exception:
                pass

        if is_duplicate:
            similar_removed += 1
        else:
            deduped.append(evt)
            if ts_str:
                recent_events_by_flow[flow_key] = ts_str

    total_after = len(deduped)
    retention_rate = round((total_after / total_before * 100), 2) if total_before > 0 else 100.0

    stats = {
        "total_before": total_before,
        "exact_duplicates_removed": exact_removed,
        "similar_duplicates_removed": similar_removed,
        "total_after": total_after,
        "retention_rate": retention_rate
    }

    return deduped, stats
