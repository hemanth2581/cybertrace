# CYBERTRACE - AI & ANOMALY DETECTION GUIDE

## Overview
CyberTrace employs a hybrid detection architecture:
1. **Deterministic Rule-Based Risk Engine:** Fast, predictable, and explainable cybersecurity heuristic checks.
2. **Unsupervised Machine Learning (Isolation Forest):** Multi-dimensional outlier detection using Scikit-Learn.

---

## 1. Rule-Based Scoring Breakdown

Each log event is evaluated by `ai/anomaly_detection.py` against explicit risk indicators:

| Threat Indicator | Points Added | Rationale |
|---|---|---|
| **Unusual External IP** | `+20` | Connections from non-corporate, foreign public IPs (e.g., `185.23.45.10`) indicate possible remote account hijacking. |
| **Multiple Failed Logins** | `+20` | Repeated authentication failures indicate brute-force password guessing or credential stuffing. |
| **Single Failed Login** | `+10` | Isolated password failure. |
| **Unrecognized Device** | `+15` | User authenticating from an unfamiliar device hardware ID. |
| **Sensitive File Access** | `+20` | Accessing credential vaults or dumps (e.g. `passwords.txt`, `shadow`, `.env`, `database_dump.sql`). |
| **High Data Volume Transfer** | `+15` | Large outbound upload volumes (>500 KB/MB) indicate active data exfiltration. |
| **Permission Modification** | `+10` | Role or policy changes indicate privilege escalation or persistent backdoor creation. |
| **Compounding Attack Bonus** | `+7` | When 3+ threat indicators occur consecutively from an external IP, compounding escalation is triggered. |

---

## 2. Severity Classification Scale

Risk scores range from `0` to `100`:

| Risk Score | Severity Level | UI Badge | Action Required |
|---|---|---|---|
| **0 - 30** | `LOW` | 🟢 Green | Routine activity. No immediate alert. |
| **31 - 60** | `MEDIUM` | 🟡 Yellow | Flagged for suspicious behavior. Monitored. |
| **61 - 80** | `HIGH` | 🟠 Orange | Elevated threat. Multiple suspicious indicators. |
| **81 - 100** | `CRITICAL` | 🔴 Red | High-priority security breach in progress. Immediate containment. |

---

## 3. Unsupervised Machine Learning (Scikit-Learn Isolation Forest)

In addition to explicit rules, CyberTrace converts each log into a multi-feature mathematical vector:
$$X = [\text{data\_size}, \text{is\_foreign\_ip}, \text{is\_failed\_login}, \text{is\_sensitive\_file}]$$

Scikit-Learn's `IsolationForest` randomly partitions feature space:
- Normal events require many partitions to isolate.
- Anomalous outliers are isolated in very few partitions.
- Generates an unsupervised anomaly index from `0.0` to `1.0`.

---

## 4. Grounded AI Forensic Investigator (No Hallucinations)

The AI Investigator in `backend/investigator.py`:
- Extracts facts directly from the database (actual users, IP addresses, files, timestamps).
- Formulates deductive conclusions without inventing non-existent evidence.
- Matches user queries (e.g., *"What was the first suspicious event?"*) to precise chronological log indexes.
