# CYBERTRACE - PROJECT FLOW & ARCHITECTURE

## Overview
CyberTrace is an AI-powered Digital Forensics Time Machine that allows security analysts and beginners to step through the chronological timeline of a cyber incident.

---

## 1. End-to-End System Pipeline

```
                 UPLOAD SECURITY LOGS (CSV)
                             ↓
                    CLEAN & VALIDATE (Pandas)
                             ↓
                 ANOMALY DETECTION & RISK SCORING
                             ↓
                     STORE IN DATABASE
                  (Supabase PostgreSQL / Local)
                             ↓
                     EVENT CORRELATION
                     (Create Incidents)
                             ↓
               DIGITAL FORENSICS TIME MACHINE
                             ↓
                     EVIDENCE MAPPING
                             ↓
                   AI FORENSIC INVESTIGATOR
                             ↓
               OFFICIAL INCIDENT REPORT (PDF)
```

---

## 2. Master Demo Scenario (Account Compromise)

| Timestamp | User | Device | IP Address | Action / Event | Risk Score | Severity | Forensic Trigger |
|---|---|---|---|---|---|---|---|
| **10:01** | Rahul | DEV01 | 192.168.1.20 | LOGIN SUCCESS | 0 | LOW | Normal corporate baseline login |
| **10:15** | Rahul | DEV01 | **185.23.45.10** | LOGIN SUCCESS | 20 | LOW | 🚨 **First Suspicious Event**: Foreign external IP |
| **10:17** | Rahul | DEV01 | 185.23.45.10 | LOGIN FAILED | 30 | LOW | External IP + Failed password attempt |
| **10:18** | Rahul | DEV01 | 185.23.45.10 | LOGIN FAILED | 40 | MEDIUM | External IP + Multiple brute-force attempts |
| **10:20** | Rahul | DEV01 | 185.23.45.10 | LOGIN SUCCESS | 40 | MEDIUM | Successful access after repeated failures |
| **10:23** | Rahul | DEV01 | 185.23.45.10 | FILE READ passwords.txt | 60 | MEDIUM | Sensitive credential file accessed |
| **10:25** | Rahul | DEV01 | 185.23.45.10 | DATA UPLOAD (850 KB) | 75 | HIGH | High-volume data exfiltration |
| **10:27** | Rahul | DEV01 | 185.23.45.10 | PERMISSION CHANGED | **92** | **CRITICAL** | Privilege escalation & persistent backdoor |

### Final Incident Outcome:
- **Incident ID**: `INC-001`
- **First Suspicious Event**: `10:15`
- **Peak Risk Score**: `92/100`
- **Severity**: `CRITICAL`
- **Flagged Reasons**: Unusual IP, Multiple failed logins, Sensitive file access, Large data transfer, Permission change.

---

## 3. Technology Story
```
Frontend (HTML / CSS / JavaScript fetch)
                ↓ (HTTP GET / POST)
Python Built-in HTTP Server (server.py)
                ↓
Backend Core & AI Pipeline:
  • ai/preprocessing.py (Pandas CSV Cleaning)
  • ai/anomaly_detection.py (Rule-based Risk Engine & ML)
  • backend/correlation.py (Incident Linker)
  • backend/timeline.py (Time Machine Builder)
  • backend/evidence.py (Entity Relationship Graph)
  • backend/investigator.py (Factual QA)
  • backend/report.py (ReportLab PDF Export)
                ↓
Database:
  • backend/database.py (Supabase PostgreSQL / Local Fallback)
```
