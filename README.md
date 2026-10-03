# Cyber Incident Timeline Generator & Forensic Investigation Hub

A high-performance, data-driven security operations and digital forensics platform designed to ingest multi-source raw logs, normalize timestamps into strict chronological order, detect duplicates, classify security events via transparent rules, correlate incidents across disparate entities, manage IOC indicators with analyst verification, and export executive incident reports.

---

## Key Features & Highlights

1. **100% Data-Driven Architecture**:
   - Zero hardcoded or decorative mock metrics.
   - All dashboard KPI cards, temporal graphs, source distributions, severity breakdowns, and IOC counts are dynamically computed from the active SQLite dataset.
2. **Canonical Unified Schema (27 Common Fields + Raw Evidence)**:
   - `event_id_unique`, `timestamp` (UTC ISO-8601), `log_source`, `event_id`, `event_type`, `severity`, `action`, `username`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `hostname`, `device_type`, `department`, `country`, `session_id`, `correlation_id`, `process_name`, `file_name`, `file_hash`, `bytes_sent`, `bytes_received`, `response_code`, `description`, `status`.
   - **Missing values are preserved as missing (`—`)** rather than substituted with placeholder dates or invented strings.
   - **Original raw log records and source file references** are preserved verbatim in `raw_record`, `source_file`, and `source_row_index`.
3. **Multi-Source Log Parsers**:
   - **Windows Event Logs (CSV)**: Maps `TimeCreated`, `Computer`, `Level`, `Message`, and `EventID` (e.g. 4624, 4625, 4672, 4688, 5128).
   - **Firewall Logs (CSV)**: Parses `date`, `time`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `action`, `protocol`.
   - **Linux Syslog (.log / .txt)**: Regular expression parser extracting timestamp, hostname, daemon/process, PID, UFW blocks, SSH authentication, and auditd execution commands.
   - **Application Logs (.log / .txt)**: Bracketed timestamp, severity, action, username, and IP address parser.
   - **Canonical CSV / 1M Dataset**: Direct mapping parser with type-safe sanitization and row-level error reporting.
   - **JSON Format**: Flexible JSON object/array parser.
4. **Deterministic Tie-Breaker Chronological Ordering**:
   - Solves the preview defect where timestamps restarted partway down or looped.
   - Queries use strict SQL indexing: `ORDER BY timestamp ASC, id ASC`, ensuring reliable timeline ordering.
5. **Consolidated Forensic Pipeline Monitor**:
   - Replaces fragmented duplicate screens with a single interactive monitor.
   - Transparently audits all 8 pipeline stages: Parsing, Timestamp Normalization, Evidence Cleaning, Deduplication, Rule-based Classification, Multi-source Correlation, IOC Detection, and Indexed Storage.
   - Row-level parsing error inspection with file name, line number, rejection cause, and raw log text.
6. **Multi-Faceted Combined Filtering**:
   - Combined filters across Time range (From / To), Log Source, Severity, IP Address, Username, Correlation / Incident ID, and Free-text Search.
   - Synchronously updates matched count and timeline without data loss.
7. **Indicators of Compromise (IOC) Registry**:
   - Deterministic regex extraction of Public IPs, Suspicious Ports (22, 23, 135, 139, 445, 3389, 5128), SHA256/MD5 hashes, and Domain names.
   - **Analyst Threat Verification**: Allows investigators to tag indicators as `Observed`, `Confirmed Threat`, or `False Positive`, persisted to database.
8. **Persistent Investigation Workspace**:
   - Stores Case Status (`New`, `In Progress`, `Under Review`, `Escalated`, `Closed`), Assigned Lead Analyst, and Forensic Notes in SQLite, persisting across page refreshes.
9. **Multi-Format Scoped Report Exports**:
   - **Executive PDF Summary**: Formatted ReportLab PDF with executive overview, KPI summary table, IOC table, and chronological timeline table.
   - **Filtered CSV**: Standard canonical 27-field CSV export matching active filter scope.
   - **Evidence JSON**: Complete structured JSON export with case metadata, IOC registry, and event streams.

---

## Directory Structure

```
Cyber-Incindent-Timeline-Generator/
├── backend/
│   ├── engine/
│   │   ├── classifier.py      # Deterministic rule-based event classifier
│   │   ├── cleaner.py         # Evidence-preserving data cleaner & validator
│   │   ├── correlator.py      # IP, session, user, and incident correlator
│   │   ├── deduplicator.py    # O(N log N) exact and burst deduplication engine
│   │   ├── ioc_detector.py    # IOC extraction & analyst threat verification
│   │   └── normalizer.py      # UTC ISO-8601 timestamp & severity normalizer
│   ├── parsers/
│   │   ├── app_parser.py       # Application log parser
│   │   ├── canonical_parser.py # Canonical 27-field CSV parser
│   │   ├── firewall_parser.py  # Firewall CSV parser
│   │   ├── json_parser.py      # JSON array/object parser
│   │   ├── syslog_parser.py    # Linux Syslog parser
│   │   └── windows_parser.py   # Windows Event CSV parser
│   ├── reporting/
│   │   ├── csv_exporter.py    # CSV export generator
│   │   ├── json_exporter.py   # JSON export generator
│   │   └── pdf_exporter.py    # ReportLab Executive PDF generator
│   ├── database.py            # SQLite database, schema, WAL mode & indexes
│   ├── main.py                # FastAPI REST API & static file server
│   ├── models.py              # Pydantic data models
│   ├── pipeline.py            # 8-stage pipeline orchestrator
│   └── test_suite_gen.py      # Edge-case benchmark suite generator
├── data/
│   ├── raw/                   # Multi-source raw log files (firewall, windows, syslog, app)
│   ├── samples/               # Enterprise production dataset (incident_timeline_cleaned.csv) & test suites
│   └── processed/             # SQLite database storage (cyber_incident.db)
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── DashboardTab.jsx      # Metrics, severity & source charts, incident clusters
│   │   │   ├── EventDetailDrawer.jsx # 27 canonical fields, raw log, correlated events
│   │   │   ├── Header.jsx            # Top navbar, active case badge, health status
│   │   │   ├── InvestigationTab.jsx  # Persistent case notes & status editor
│   │   │   ├── IOCTab.jsx            # IOC registry with analyst threat verdict toggle
│   │   │   ├── PipelineTab.jsx       # Consolidated pipeline monitor & error audit
│   │   │   ├── ReportModal.jsx       # PDF, CSV, JSON export dialog
│   │   │   ├── TimelineTab.jsx       # Chronological table, combined filters, pagination
│   │   │   └── UploadModal.jsx       # Ingestion modal & one-click benchmark loaders
│   │   ├── App.jsx
│   │   ├── index.css
│   │   └── main.jsx
│   ├── dist/                  # Built production frontend assets
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
├── run.py                     # Unified launcher script
├── requirements.txt           # Python backend dependencies
└── README.md                  # System documentation
```

---

## Installation & Setup

### Prerequisites
- Python 3.8+ (Python 3.14 compatible)
- pip

### 1. Install Backend Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies: `fastapi`, `uvicorn[standard]`, `pandas`, `reportlab`, `python-dateutil`, `python-multipart`)*

### 2. Run the Application
```bash
python run.py
```

The application will start immediately at:
**`http://127.0.0.1:8000`**

- Web Interface: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Interactive API Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Backend Health Check: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

### Deploying on Replit

Import this repository into Replit and create a deployment. The `.replit` configuration installs the Python requirements, builds the frontend, and starts the FastAPI server. The application binds to `0.0.0.0` and uses Replit's assigned `PORT` automatically. SQLite data is stored under `data/processed/`; use persistent storage if uploaded data and investigation changes must survive redeployments.

---

## Verifying the End-to-End Workflow

1. **Ingest / Load Benchmark Data**:
   - Open [http://127.0.0.1:8000](http://127.0.0.1:8000).
   - Click **"Ingest / Demo Data"** in the top navigation.
   - Click **"Multi-Source Logs"** to load the representative Firewall, Windows, Linux, and Application logs (60 events).
   - Or click **"Enterprise Incident Dataset"** to load 100,000 production incident records from `incident_timeline_cleaned.csv` with full network topology and correlations.
   - Or click **"Edge-Case Suite"** to verify row-level error reporting on malformed timestamps and duplicate pruning.
2. **Review Data-Driven Dashboard**:
   - Inspect dynamically computed KPIs (Total Events, High/Critical count, Unique Sources, Unique IPs, Incident Clusters).
   - Inspect Severity and Log Source distribution bars.
   - Click on an incident cluster or log source to filter the timeline immediately.
3. **Inspect Chronological Incident Timeline**:
   - Navigate to the **Incident Timeline** tab.
   - Verify strict timestamp ordering (`timestamp ASC, id ASC`). No timestamp restarts or looping.
   - Use combined filters (e.g., Log Source = `Windows`, Severity = `High`, or search IP `203.0.113.45`).
   - Click any event row to open the **Event Inspection Drawer** to review all 27 canonical fields, missing fields as `—`, the unaltered raw log, and correlated events.
4. **Review & Tag IOCs**:
   - Navigate to **IOC & Threat Evidence**.
   - Change an indicator's analyst verdict from `Observed` to `Confirmed Threat` or `False Positive`.
5. **Update Investigation Notes**:
   - Navigate to **Investigation Case**.
   - Update Case Status (e.g. `Escalated` or `In Progress`) and write forensic notes.
   - Click **Save Case Notes**. Refresh the browser and verify the notes and status persist.
6. **Export Deliverables**:
   - Click **Export Report** in the header.
   - Select **Executive PDF**, **Filtered CSV**, or **Evidence JSON**.
   - Download and open the generated deliverable.
