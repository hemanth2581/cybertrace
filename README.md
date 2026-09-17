# CYBERTRACE
### AI Digital Forensics & Incident Response Platform

![Java](https://img.shields.io/badge/Java-21-orange.svg)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4.3-brightgreen.svg)
![Architecture](https://img.shields.io/badge/Architecture-Java%20%2B%20HTML5%2FJS%20%2B%20localStorage-blue.svg)
![Database](https://img.shields.io/badge/Database-None%20(Pure%20Browser%20Storage)-purple.svg)

CyberTrace is a modern, lightweight digital forensics and incident response (DFIR) web platform designed for rapid security log triage, heuristic anomaly detection, attack timeline reconstruction, entity evidence mapping, and grounded AI investigation.

---

## 🌟 Key Features

1. **Zero Database Architecture:** Uses browser `localStorage` for all persistent investigation records (`cybertrace_events`, `cybertrace_incidents`, `cybertrace_evidence`, etc.).
2. **Java Heuristic Scoring:** Deterministic penalty scoring (0–100) detecting failed logins, external IPs, sensitive file access, and large outbound data transfers.
3. **Forensic Time Machine:** Interactive chronological attack progression player with automated identification of the **FIRST SUSPICIOUS EVENT**.
4. **Evidence Relationship Graph:** Visual correlation mapping: `USER ➔ DEVICE ➔ IP ➔ FILE ➔ DATA TRANSFER`.
5. **Grounded AI Investigator:** 100% evidence-grounded Q&A reasoning engine that answers forensic inquiries directly from verifiable logs without cloud AI hallucinations.
6. **One-Click PDF Case Report:** Generates an official, publication-ready Digital Forensics Incident Report PDF via OpenPDF.
7. **Responsive Cybersecurity SOC UI:** Dark glassmorphism interface built with HTML5, CSS3, and Bootstrap 5, optimized for mobile (320px+) through 4K displays.

---

## 🛠️ Technology Stack

- **Backend:** Java 21, Spring Boot 3.4.3 (Spring Web, Maven)
- **PDF Generation:** OpenPDF
- **CSV Engine:** Apache Commons CSV
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Bootstrap 5, Bootstrap Icons
- **Storage:** Browser `localStorage` (No SQL, No NoSQL, No Supabase)

---

## 🚀 Getting Started (Run Locally)

### Prerequisites
- **Java 21** or higher installed (`java -version`)

### Quick Start
1. Clone or open the repository:
   ```bash
   cd "cyber trace code A THON"
   ```

2. Run the application using the included Maven wrapper:
   - **Windows:**
     ```cmd
     .\mvnw.cmd spring-boot:run
     ```
   - **Linux / macOS:**
     ```bash
     ./mvnw spring-boot:run
     ```

3. Open your browser and navigate to:
   ```
   http://localhost:8080
   ```

---

## 🎯 Codeathon Demo Walkthrough

1. **Open CyberTrace** at `http://localhost:8080` (Shows clean dashboard with Empty State).
2. **Click "Upload Security Logs"** or navigate to `upload.html`.
3. **Click "Account Compromise"** (or choose your own CSV file).
4. Spring Boot parses the CSV, computes risk scores, detects anomalies, correlates `INC-001`, and returns the results to browser storage.
5. **View Dashboard:** Inspect Total Events, Suspicious Anomalies, Critical Threats, Active Incident card, and Severity Distribution bar.
6. **Navigate to Forensic Time Machine (`timeline.html`):** Click **Play** to watch the sequential attack progression from initial infiltration to privilege escalation.
7. **Navigate to Evidence Graph (`evidence.html`):** Inspect the connected entity chain (`Shiva ➔ DEV01 ➔ 185.23.45.10 ➔ passwords.txt ➔ 850 MB`).
8. **Open AI Investigator (`investigator.html`):** Ask questions like:
   - *"What happened?"*
   - *"What was the first suspicious event?"*
   - *"Which IP was involved?"*
9. **Open Incident Report (`report.html`):** Click **"Download Official PDF Report"** to export the compiled case report.

---

## 📖 Documentation & Guides

- [Beginner's Technical Guide](docs/BEGINNER_GUIDE.md) — Explains core concepts (Java, Spring Boot, REST APIs, Models, Services, localStorage) in simple terms.
- [Project Architecture & Data Flow](docs/PROJECT_FLOW.md) — End-to-end data lifecycle diagram.
- [File Structure Guide](docs/FILE_GUIDE.md) — Comprehensive guide to every file in the repository.

---

## 🛡️ License
CyberTrace is built for codeathon and educational cybersecurity demonstrations.
