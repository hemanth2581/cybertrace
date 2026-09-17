# CYBERTRACE - FILE GUIDE & DIRECTORY BREAKDOWN

This document explains every single file in the CyberTrace codebase, its purpose, its inputs, and its outputs.

---

## Root Files

| File | Purpose | Key Details |
|---|---|---|
| `server.py` | Built-in Python HTTP Server | Runs `ThreadingHTTPServer` on port 8000, routes static web pages and REST API endpoints (`/api/*`), handles uploads and PDF streaming without Django/Flask. |
| `requirements.txt` | Dependencies | Specifies `pandas`, `numpy`, `scikit-learn`, `reportlab`, `supabase`, `python-dotenv`. |
| `.env` | Environment Config | Contains `SUPABASE_URL` and `SUPABASE_KEY`. Kept private and ignored by git. |
| `.env.example` | Config Template | Reference file showing how to configure Supabase credentials. |
| `.gitignore` | Git Ignore Rules | Prevents uploading `.env`, `__pycache__`, virtual environments, and generated PDFs to GitHub. |

---

## `backend/` Directory (Core Logic)

| File | Purpose | Description |
|---|---|---|
| `backend/database.py` | Database Client & Fallback | Connects to Supabase PostgreSQL when `.env` keys exist. Automatically falls back to an in-memory store so the app never crashes if offline. |
| `backend/events.py` | Event Processing & Statistics | Coordinates log ingestion, calls preprocessing and anomaly scoring, saves records to DB, and computes dashboard metrics. |
| `backend/anomaly.py` | Anomaly Service | Filters flagged events, sorts by risk score, and summarizes rule violations for investigators. |
| `backend/correlation.py` | Incident Correlator | Groups suspicious events by user, IP, and time window into incident cases (`INC-001`), calculating peak severity and stages. |
| `backend/timeline.py` | Time Machine Engine | Builds the chronological sequence of events with status headlines, cumulative risk metrics, and first anomaly index. |
| `backend/evidence.py` | Evidence Relationship Graph | Generates linked entity tuples (`USER` -> `DEVICE` -> `IP` -> `FILE` -> `DATA_TRANSFER`) with first/last seen metadata. |
| `backend/investigator.py` | AI Forensic QA | Answers natural-language forensic questions strictly grounded in actual database logs without hallucinating. |
| `backend/report.py` | Report & PDF Exporter | Builds comprehensive incident dossiers and generates downloadable PDFs using Python **ReportLab**. |

---

## `ai/` Directory (Data Science & Detection)

| File | Purpose | Description |
|---|---|---|
| `ai/preprocessing.py` | Pandas Log Ingestion | Reads raw CSVs, strips whitespace, removes duplicates, validates headers, and standardizes data types. |
| `ai/anomaly_detection.py` | Risk Scoring & Rules Engine | Evaluates foreign IPs, failed logins, sensitive files, data volume, and permission changes (0-100 score). Also includes Scikit-Learn IsolationForest. |

---

## `frontend/` Directory (User Interface)

| File | Purpose | Description |
|---|---|---|
| `frontend/index.html` | Command Center Dashboard | Displays KPI cards, threat severity breakdown bar, demo scenario triggers, and recent suspicious events table. |
| `frontend/upload.html` | Log Upload Portal | Drag-and-drop CSV file selector, raw CSV text area, schema guide, and preset demo buttons. |
| `frontend/events.html` | Security Events Explorer | Filterable and searchable table of all ingested security audit logs. |
| `frontend/anomalies.html` | Anomalies View | Detailed table of flagged anomalies with itemized rule penalty tags. |
| `frontend/investigation.html` | Active Incidents | Correlated incident case dossiers and multi-stage threat progression. |
| `frontend/timeline.html` | Digital Forensics Time Machine | Interactive player with slider, Play, Pause, Next, Previous, Jump to First Anomaly, and live event inspector. |
| `frontend/evidence.html` | Evidence Graph Explorer | Interactive node chain and click-to-inspect asset cards. |
| `frontend/investigator.html` | AI Investigator QA | Natural-language question box with quick inquiry chips and evidence-grounded answers. |
| `frontend/report.html` | Incident Report Preview | Formatted incident report with one-click **Download Official PDF** button. |
| `frontend/how-it-works.html` | Pipeline Visualizer | Interactive 8-step walkthrough explaining what happens at each stage of the system. |
| `frontend/css/style.css` | Design System | Cybersecurity dark theme, cyan neon accents, badges, sliders, and responsive cards. |
| `frontend/js/main.js` | Frontend Controller | Handles `fetch()` API calls, playback timer loops, DOM updates, and UI notifications. |

---

## `sample_data/` Directory (Demo Datasets)

| File | Scenario | Key Characteristics |
|---|---|---|
| `sample_data/account_compromise.csv` | Master Demo Scenario | Rahul: normal login -> 10:15 foreign IP -> failed logins -> passwords.txt access -> 850 KB upload -> permission change (Risk: 92/100, CRITICAL). |
| `sample_data/normal_activity.csv` | Baseline Operations | Normal logins, file reads, and logouts with 0 anomalies (Risk: 0, LOW). |
| `sample_data/data_exfiltration.csv` | Data Exfiltration | Multi-stage brute-force attack exfiltrating database dump (1420 KB) from external IP (Risk: 95/100, CRITICAL). |

---

## `database/` Directory

| File | Purpose | Description |
|---|---|---|
| `database/supabase_schema.sql` | PostgreSQL DDL | Complete SQL script creating `security_events`, `incidents`, `evidence`, and `investigation_reports` tables with indexes. |
