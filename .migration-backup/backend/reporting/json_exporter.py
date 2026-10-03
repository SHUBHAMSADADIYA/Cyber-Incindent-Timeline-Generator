import json
from datetime import datetime
from typing import List, Dict, Any, Optional

def generate_incident_json(
    events: List[Dict[str, Any]],
    case_info: Optional[Dict[str, Any]] = None,
    iocs: Optional[List[Dict[str, Any]]] = None,
    filter_summary: str = "Active Filter Scope"
) -> str:
    payload = {
        "metadata": {
            "title": "Cyber Incident Investigation Export",
            "exported_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scope": filter_summary,
            "total_events": len(events),
            "case": case_info or {}
        },
        "indicators_of_compromise": iocs or [],
        "timeline_events": events
    }
    return json.dumps(payload, indent=2)
