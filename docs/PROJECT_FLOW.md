# CyberTrace — Project Architecture & Data Flow

This document details the complete end-to-end data lifecycle in the **CyberTrace** Digital Forensics & Incident Response platform.

---

## 1. High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      CYBERTRACE FRONTEND                    │
│      (HTML5 + CSS3 + Bootstrap 5 + Vanilla JavaScript)       │
│                                                             │
│  • Dashboard (index.html)        • Investigation Dossiers   │
│  • Upload (upload.html)          • Attack Timeline Player   │
│  • Event Explorer (events.html)  • Evidence Graph Chain     │
│  • Anomalies (anomalies.html)    • AI Investigator Q&A      │
└──────────────┬───────────────────────────────▲──────────────┘
               │                               │
       HTTP Multipart/JSON               JSON Response
               │                               │
┌──────────────▼───────────────────────────────┴──────────────┐
│                  JAVA SPRING BOOT BACKEND                   │
│                                                             │
│  • SecurityEventController (/api/events/analyze)            │
│  • InvestigatorController (/api/investigator/query)         │
│  • ReportController (/api/report/pdf)                       │
│                                                             │
│  Services:                                                  │
│  ├─ CsvProcessingService (RFC4180 parsing & validation)     │
│  ├─ RiskAnalysisService (0-100 heuristic scoring)           │
│  ├─ AnomalyDetectionService (Suspicious event isolation)    │
│  ├─ IncidentService (Multi-vector INC-001 correlation)      │
│  ├─ TimelineService (Chronological attack progression)      │
│  ├─ EvidenceService (User->Device->IP->File mapping)        │
│  ├─ InvestigatorService (Evidence-grounded reasoning)       │
│  └─ PdfReportService (OpenPDF binary report compiler)       │
└─────────────────────────────────────────────────────────────┘
                               ▲
                               │
                       Browser Persistence
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    BROWSER LOCALSTORAGE                     │
│                                                             │
│  • cybertrace_events          • cybertrace_evidence         │
│  • cybertrace_anomalies       • cybertrace_timeline         │
│  • cybertrace_incidents       • cybertrace_investigations   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Step-by-Step Data Lifecycle

### 1. Ingestion (`/upload.html`)
- User drops a CSV file or selects a pre-built demo scenario (`Account Compromise`, `Data Exfiltration`, `Normal Activity`).
- JavaScript sends the file via `POST /api/events/analyze` to Spring Boot.

### 2. Processing & Validation (`CsvProcessingService`)
- Checks for required columns: `timestamp`, `user`, `device`, `ip`, `action`.
- Parses data sizes and files.

### 3. Threat Scoring (`RiskAnalysisService`)
- Evaluates IPs against RFC1918 subnets (`10.x`, `192.168.x`, `172.16-31.x`).
- Flags sensitive credential assets (`passwords.txt`, `database.sql`).
- Calculates cumulative threat score (0–100) and severity badge.

### 4. Correlation & Dossier Generation (`IncidentService`)
- Groups related anomalous events into active incident cases (e.g. `INC-001`).
- Identifies the initial attack vector and compiles recommended SOC containment actions.

### 5. Timeline Reconstruction (`TimelineService`)
- Sequences events chronologically.
- Automatically flags the **FIRST SUSPICIOUS EVENT** for immediate visualization.

### 6. Relationship Extraction (`EvidenceService`)
- Maps the forensic relationship chain: `USER ➔ DEVICE ➔ IP ➔ FILE ➔ TRANSFER`.

### 7. Browser Storage (`storage.js`)
- Resulting JSON is written to browser `localStorage`.
- All pages dynamically read from `localStorage` on page load.

### 8. Interactive Investigation & Export (`/investigator.html` & `/report.html`)
- Investigator answers forensic questions strictly using ground-truth evidence.
- OpenPDF compiles an official incident report PDF.
