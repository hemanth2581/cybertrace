# CyberTrace — Beginner's Technical Guide

Welcome to the **CyberTrace** beginner's guide! This document explains the core technical concepts used in CyberTrace in simple, clear language so you can confidently explain the project to codeathon judges.

---

## 1. Core Technology Concepts

### What is Java?
**Java** is a robust, object-oriented, typed programming language. It is widely used in enterprise cybersecurity systems for its performance, type safety, and reliability.

### What is Spring Boot?
**Spring Boot** is a modern Java framework that makes it easy to build production-grade web applications and REST APIs. It provides an embedded web server (Tomcat), automatic configuration, and dependency injection so we can focus on cybersecurity logic.

### What is a REST API?
A **REST API** (Representational State Transfer Application Programming Interface) allows the frontend (HTML/JavaScript in your browser) to communicate with the backend (Java Spring Boot server) using standard HTTP requests like `POST` and `GET`.
- The frontend sends raw data (e.g. CSV file or text).
- Java processes the data and responds with structured **JSON** (JavaScript Object Notation).

### What is a Controller?
In Spring Boot, a **Controller** (`@RestController`) defines the web endpoints (like `/api/events/analyze`). It receives incoming HTTP requests from the browser and passes them to Services.

### What is a Service?
A **Service** (`@Service`) contains the core business logic. In CyberTrace, services handle:
- Parsing CSV files (`CsvProcessingService`)
- Calculating risk scores (`RiskAnalysisService`)
- Filtering suspicious anomalies (`AnomalyDetectionService`)
- Correlating incidents (`IncidentService`)
- Building attack timelines (`TimelineService`)
- Extracting evidence chains (`EvidenceService`)
- Answering forensic questions (`InvestigatorService`)
- Generating PDF reports (`PdfReportService`)

### What is a Model?
A **Model** is a simple Java class (Plain Old Java Object / POJO) that represents structured data, such as a `SecurityEvent`, `Incident`, `Anomaly`, `TimelineEvent`, or `Evidence`.

### What is localStorage?
**localStorage** is a built-in browser database that saves key-value pairs directly inside the user's web browser.
- **Why we use it:** It eliminates the need for complex external database setups (like PostgreSQL, MySQL, or Supabase) during a codeathon while keeping the investigation data persistent even if you refresh the browser page.

---

## 2. CyberTrace Forensic Pipeline Flow

```
   Raw CSV Logs (User Upload or Demo)
                 │
                 ▼
     [POST /api/events/analyze]
                 │
                 ▼
       Spring Boot Java Backend
   ┌────────────────────────────────┐
   │ 1. CsvProcessingService        │ (Validates columns & parses records)
   │ 2. RiskAnalysisService         │ (Calculates 0-100 risk score)
   │ 3. AnomalyDetectionService     │ (Filters suspicious events)
   │ 4. IncidentService             │ (Correlates multi-stage INC-001)
   │ 5. TimelineService             │ (Flags FIRST SUSPICIOUS EVENT)
   │ 6. EvidenceService             │ (Builds User->Device->IP->File chain)
   └────────────────────────────────┘
                 │
                 ▼
            JSON Response
                 │
                 ▼
      Browser JavaScript Storage
    (Saved into localStorage keys)
                 │
                 ▼
      Interactive SOC Dashboard
```

---

## 3. How Risk Scoring Works

Risk scores (0 to 100) are computed deterministically using standard cybersecurity heuristic rules:

| Condition | Risk Penalty | Forensic Rationale |
| :--- | :---: | :--- |
| **Failed Login / Auth Failure** | `+20 pts` | Indicates password guessing / brute-force attempt |
| **External Public IP** | `+20 pts` | Infiltration origin outside internal RFC1918 subnets |
| **Sensitive File Access** | `+20 pts` | Accessing `passwords.txt`, `credentials.txt`, `database.sql` |
| **Large Data Outbound** | `+15 pts` | Exfiltration transfer volume &ge; 500 MB |
| **Privilege Escalation** | `+10 pts` | Sudo / administrator elevation commands |
| **Compound Penalty** | `+7 pts` | Applied when 3 or more distinct suspicious triggers co-occur |

### Threat Tiers:
- `0 - 20`: **NORMAL**
- `21 - 40`: **LOW**
- `41 - 60`: **MEDIUM**
- `61 - 80`: **HIGH**
- `81 - 100`: **CRITICAL**

---

## 4. Key Takeaways for Judges

1. **Zero Database Overhead:** Persistent across page refreshes via client-side `localStorage`.
2. **Deterministic & Verifiable:** No AI hallucinations; every investigator answer and risk score is strictly grounded in evidence.
3. **End-to-End Java Forensics:** Complete multi-stage attack reconstruction from raw CSV ingestion to PDF case report generation.
