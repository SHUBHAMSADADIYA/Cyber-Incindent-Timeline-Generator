import csv
import io
from typing import List, Dict, Any

CANONICAL_EXPORT_COLUMNS = [
    "event_id_unique", "timestamp", "log_source", "event_id", "event_type",
    "severity", "action", "username", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol", "hostname", "device_type",
    "department", "country", "session_id", "correlation_id", "process_name",
    "file_name", "file_hash", "bytes_sent", "bytes_received", "response_code",
    "description", "status"
]

def generate_incident_csv(events: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CANONICAL_EXPORT_COLUMNS, extrasaction='ignore')
    writer.writeheader()

    for evt in events:
        row = {col: ("" if evt.get(col) is None else evt.get(col)) for col in CANONICAL_EXPORT_COLUMNS}
        writer.writerow(row)

    return output.getvalue()
