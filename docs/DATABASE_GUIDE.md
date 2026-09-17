# CYBERTRACE - DATABASE GUIDE (SUPABASE POSTGRESQL)

## Overview
CyberTrace uses Supabase PostgreSQL as its central data persistence layer. This document explains the schema design, tables, relationships, and configuration.

---

## 1. Supabase PostgreSQL Schema Overview

```
┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│        security_events          │       │            incidents            │
├─────────────────────────────────┤       ├─────────────────────────────────┤
│ id (PK)                         │       │ id (PK)                         │
│ timestamp                       │       │ incident_id (Unique) ─────────┐ │
│ user                            │       │ title                           │
│ device                          │       │ start_time                      │
│ ip                              │       │ end_time                        │
│ event_type                      │       │ risk_score                      │
│ action                          │       │ severity                        │
│ file                            │       │ summary                         │
│ data_size                       │       │ created_at                      │
│ risk_score                      │       └────────────────┬────────────────┘
│ severity                        │                        │ (1 to N)
│ reason                          │                        │
│ is_anomaly                      │       ┌────────────────▼────────────────┐
│ created_at                      │       │            evidence             │
└─────────────────────────────────┘       ├─────────────────────────────────┤
                                          │ id (PK)                         │
                                          │ incident_id (FK)                │
                                          │ entity_type                     │
                                          │ entity_value                    │
                                          │ related_entity                  │
                                          │ relationship                    │
                                          │ created_at                      │
                                          └─────────────────────────────────┘
                                                           │
                                          ┌────────────────▼────────────────┐
                                          │      investigation_reports      │
                                          ├─────────────────────────────────┤
                                          │ id (PK)                         │
                                          │ incident_id (FK)                │
                                          │ summary                         │
                                          │ timeline (JSONB)                │
                                          │ evidence_summary                │
                                          │ ai_explanation                  │
                                          │ created_at                      │
                                          └─────────────────────────────────┘
```

---

## 2. Table Definitions

### 1. `security_events`
Stores every ingested security log with computed risk metrics.
- `id` (BIGSERIAL PK): Unique auto-incrementing ID.
- `timestamp` (VARCHAR): Time of the event (e.g., `10:01`).
- `user` (VARCHAR): User account name (e.g., `Rahul`).
- `device` (VARCHAR): Host device ID (e.g., `DEV01`).
- `ip` (VARCHAR): Source IP address (e.g., `185.23.45.10`).
- `event_type` (VARCHAR): Category (e.g., `LOGIN`, `FILE_ACCESS`, `DATA_TRANSFER`, `PERMISSION`).
- `action` (VARCHAR): Specific operation (e.g., `SUCCESS`, `FAILED`, `READ`, `UPLOAD`, `CHANGED`).
- `file` (VARCHAR): Targeted filename (e.g., `passwords.txt`).
- `data_size` (INTEGER): Data volume transferred in KB/MB.
- `risk_score` (INTEGER): Calculated threat penalty (0-100).
- `severity` (VARCHAR): `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- `reason` (TEXT): Semicolon-separated rule violations.
- `is_anomaly` (BOOLEAN): `TRUE` if flagged as a suspicious threat.
- `created_at` (TIMESTAMP): Record creation timestamp.

### 2. `incidents`
Correlated multi-event cyber security cases.
- `id` (BIGSERIAL PK)
- `incident_id` (VARCHAR UNIQUE): Case identifier (e.g., `INC-001`).
- `title` (VARCHAR): Human-readable incident title.
- `start_time` (VARCHAR): First suspicious event time.
- `end_time` (VARCHAR): Last observed threat action time.
- `risk_score` (INTEGER): Peak threat level reached (0-100).
- `severity` (VARCHAR): Overall incident severity.
- `summary` (TEXT): High-level attack progression synopsis.

### 3. `evidence`
Entity relationship connections.
- `id` (BIGSERIAL PK)
- `incident_id` (VARCHAR FK -> `incidents.incident_id`)
- `entity_type` (VARCHAR): `USER`, `DEVICE`, `IP`, `FILE`, `TRANSFER`.
- `entity_value` (VARCHAR): e.g., `Rahul`, `185.23.45.10`, `passwords.txt`.
- `related_entity` (VARCHAR): e.g., `DEV01`.
- `relationship` (VARCHAR): e.g., `OPERATED_DEVICE`, `CONNECTED_FROM`, `READ_FILE`.

### 4. `investigation_reports`
Synthesized audit reports.
- `id` (BIGSERIAL PK)
- `incident_id` (VARCHAR FK -> `incidents.incident_id`)
- `summary` (TEXT): Executive summary.
- `timeline` (JSONB): Structured array of chronological steps.
- `evidence_summary` (TEXT): Corroborating entity links.
- `ai_explanation` (TEXT): Plain-English forensic deduction and remediation plan.

---

## 3. Configuring Supabase Credentials in `.env`

Create or edit your `.env` file:
```env
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_KEY=your-supabase-anon-or-service-role-key
```

### Zero-Friction Fallback Store:
If no credentials are provided in `.env`, CyberTrace seamlessly runs with its internal in-memory store so all demo scenarios and test uploads work out-of-the-box. As soon as you enter real Supabase credentials, it automatically writes directly to your PostgreSQL database!
