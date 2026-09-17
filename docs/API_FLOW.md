# CYBERTRACE - API & DATA FLOW GUIDE

## 1. General Architectural Flow

```
BROWSER (User Action)
         ↓
JAVASCRIPT fetch()
         ↓  (HTTP GET / POST over port 8000)
PYTHON SERVER (server.py)
         ↓  (Route matching & body parsing)
PYTHON BACKEND MODULES (Pandas / Anomaly Engine / Supabase)
         ↓  (Database queries & computations)
RESULT GENERATION
         ↓  (Python dict / JSON serialization)
HTTP JSON RESPONSE
         ↓  (Status 200 OK + application/json)
JAVASCRIPT
         ↓  (DOM Manipulation & State Update)
USER INTERFACE UPDATED
```

---

## 2. Step-by-Step Flow: "When I Click Upload Logs, What Happens?"

```
1. USER CLICKS UPLOAD
   └─ User selects a CSV file on upload.html and clicks "Ingest, Clean & Analyze Logs".

2. HTML FORM & JAVASCRIPT
   └─ main.js captures the submit event and reads the file text.

3. JAVASCRIPT fetch()
   └─ Sends POST /api/upload with the raw CSV string.

4. PYTHON SERVER (server.py)
   └─ CyberTraceRequestHandler receives the POST request and passes payload to events.py.

5. PANDAS PREPROCESSING (ai/preprocessing.py)
   └─ Reads CSV into DataFrame, cleans null values, removes duplicates, validates headers.

6. ANOMALY DETECTION (ai/anomaly_detection.py)
   └─ Evaluates each event against cybersecurity rules (0-100 score) and identifies anomalies.

7. SUPABASE STORAGE (backend/database.py)
   └─ Inserts cleaned, scored event records into the PostgreSQL database.

8. EVENT CORRELATION (backend/correlation.py)
   └─ Groups suspicious events into incident dossiers (INC-001) and builds evidence links.

9. JSON RESPONSE RETURNED
   └─ Python returns {"status": "success", "total_events": 8, "stats": {...}}.

10. JAVASCRIPT UPDATES THE UI
    └─ Shows success toast and redirects user to timeline.html to step through the Time Machine!
```

---

## 3. REST API Reference

| Endpoint | Method | Description | Sample Response |
|---|---|---|---|
| `/api/status` | `GET` | Database backend status and general statistics | `{"database": {"connected": true, "type": "Supabase PostgreSQL"}}` |
| `/api/events` | `GET` | All security events stored in database | `{"events": [...], "count": 8}` |
| `/api/stats` | `GET` | KPI metrics & severity distribution | `{"total_events": 8, "suspicious_events": 7, "avg_risk_score": 49.6}` |
| `/api/anomalies` | `GET` | Flagged threats with risk penalty breakdown | `{"total_anomalies": 7, "critical_count": 1, "anomalies": [...]}` |
| `/api/incidents` | `GET` | Correlated multi-stage incident cases | `{"incidents": [{"incident_id": "INC-001", ...}]}` |
| `/api/timeline` | `GET` | Ordered timeline steps for Time Machine player | `{"total_steps": 8, "first_suspicious_index": 1, "steps": [...]}` |
| `/api/evidence` | `GET` | Entity relationship nodes & links | `{"nodes": [...], "links": [...]}` |
| `/api/demo` | `POST` | Ingests a pre-built demo scenario CSV | `{"status": "success", "scenario": "account_compromise"}` |
| `/api/upload` | `POST` | Ingests custom uploaded CSV file | `{"status": "success", "total_events": 8}` |
| `/api/investigate`| `POST`| Natural language forensic query responder | `{"question": "What happened?", "answer": "...", "confidence": 0.98}` |
| `/api/report` | `GET` | Full structured incident report JSON | `{"incident_id": "INC-001", "remediation_steps": [...]}` |
| `/api/report/pdf` | `GET` | Generates & streams ReportLab PDF binary | `Binary PDF document (attachment)` |
| `/api/clear` | `POST` | Clears all active workspace logs | `{"status": "success"}` |
