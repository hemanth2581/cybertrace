# CyberTrace — AI Digital Forensics Time Machine

> An AI-powered Digital Forensics & Incident Response (DFIR) platform that ingests raw security logs, detects complex multi-stage anomalies, visualizes entity attack chains, reconstructs chronological incident timelines, powers an evidence-grounded AI investigator, and generates formal PDF executive incident reports.

---

## 🚀 Quick Start (Run in 10 Seconds)

### 1. Prerequisites
- Python 3.9+ installed on your computer.

### 2. Install Required Dependencies
Open your terminal / command prompt in this project folder and run:
```bash
pip install -r requirements.txt
```

### 3. Start the Server
```bash
python server.py
```

### 4. Open in Browser
Open your browser and navigate to:
👉 **`http://localhost:8000`** (or **`http://127.0.0.1:8000`**)

---

## 🌟 Key Features

1. **Zero-Framework Lightweight Architecture:**
   - Pure Python standard library `http.server` backend (NO Django, NO Flask, NO Node.js required).
   - Instant startup with zero configuration overhead.
2. **Dual Database Engine:**
   - Runs **100% offline** out of the box using built-in in-memory forensic store.
   - Ready to connect to **Supabase Cloud PostgreSQL** by simply adding keys to `.env`.
3. **AI Anomaly Detection Engine (0–100 Risk Scoring):**
   - Progressive scoring combining rule heuristics and Scikit-Learn IsolationForest ML.
4. **Forensics Time Machine:**
   - Step-by-step incident playback with automatic first-suspicious-event marker.
5. **Evidence Relationship Graph:**
   - Entity mapping connecting `User -> Device -> IP -> File -> Payload`.
6. **AI Forensic Investigator:**
   - Evidence-grounded natural language Q&A console (strictly factual, zero hallucinations).
7. **ReportLab PDF Exporter:**
   - Generates official forensic case investigation reports downloadable directly from the browser.

---

## 📂 Project Architecture

```text
├── server.py                     # Built-in Python multi-threaded HTTP server & REST APIs
├── requirements.txt              # Python dependencies (pandas, reportlab, scikit-learn, etc.)
├── .env                          # Supabase environment configuration
│
├── ai/
│   ├── anomaly_detection.py      # Risk scoring & ML Isolation Forest algorithms
│   └── preprocessing.py          # Pandas CSV log ingestion & normalization
│
├── backend/
│   ├── anomaly.py                # Threat breakdown & re-evaluation service
│   ├── correlation.py            # Multi-stage incident case correlator (INC-001)
│   ├── database.py               # Supabase PostgreSQL client & memory fallback
│   ├── events.py                 # Log ingestion controller & dashboard KPIs
│   ├── evidence.py               # Entity relationship graph builder
│   ├── investigator.py           # Evidence-grounded AI QA engine
│   ├── report.py                 # Report synthesizer & ReportLab PDF exporter
│   └── timeline.py               # Forensics Time Machine sequence generator
│
├── frontend/
│   ├── index.html                # SOC Dashboard (White & Blue Theme)
│   ├── timeline.html             # Forensics Time Machine Player
│   ├── evidence.html             # Evidence Relationship Explorer
│   ├── investigator.html         # AI Investigator QA Console
│   ├── anomalies.html            # Threat & Anomaly Explorer
│   ├── investigation.html        # Incident Cases Dossier
│   ├── report.html               # Incident Report & PDF Exporter
│   ├── upload.html               # CSV Upload & Demo Scenario Hub
│   ├── how-it-works.html         # Architecture & Project Flow Guide
│   ├── css/style.css             # Unified SOC Design System (White & Blue)
│   └── js/main.js                # Vanilla JavaScript Frontend Controller
│
├── sample_data/
│   ├── account_compromise.csv    # Master Hackathon Demo (Rahul 10:01-10:27, Peak 92)
│   ├── data_exfiltration.csv     # Database dump exfiltration scenario
│   └── normal_activity.csv       # Baseline 0-anomalies dataset
│
└── docs/                         # Beginner & architecture guides
```

---

## 🧪 Running Automated Tests
```bash
python test_cybertrace.py
python test_server_http.py
```
