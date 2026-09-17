# CYBERTRACE - RECOMMENDED LEARNING ORDER

Follow this step-by-step learning roadmap to master full-stack Python development and digital forensics with CyberTrace:

---

### Phase 1: Frontend Fundamentals
1. **HTML Basics:** Learn tags, forms, tables, buttons, and layout containers in [`index.html`](file:///frontend/index.html) and [`upload.html`](file:///frontend/upload.html).
2. **CSS Basics:** Learn styling, colors, grid layouts, flexbox, and cybersecurity themes in [`style.css`](file:///frontend/css/style.css).
3. **JavaScript Basics:** Learn variables, arrays, objects, functions, and DOM manipulation in [`main.js`](file:///frontend/js/main.js).

---

### Phase 2: Python Backend & Networking
4. **Python Basics:** Master basic syntax, lists, dictionaries, conditionals, and loops.
5. **Python Functions:** Understand parameters, return values, type hints, and modular organization.
6. **Python File Handling:** Learn how Python reads and writes CSV and text files using `open()`.
7. **Python HTTP Server:** Study [`server.py`](file:///server.py) to see how Python's built-in `http.server` serves web pages without heavy frameworks like Django or Flask.
8. **JSON Data Format:** Learn how dictionaries convert to JSON text and back using `json.dumps()` and `json.loads()`.
9. **APIs (REST):** Understand how GET and POST endpoints receive and return data.
10. **JavaScript `fetch()`:** Learn how frontend JS makes asynchronous network calls to Python and handles responses.

---

### Phase 3: Database & Persistence
11. **Supabase Basics:** Understand managed cloud database services, API keys, and configuration with `.env`.
12. **PostgreSQL Basics:** Learn SQL schemas, primary keys, foreign keys, and indexes in [`database/supabase_schema.sql`](file:///database/supabase_schema.sql).
13. **Python + Supabase:** Study [`backend/database.py`](file:///backend/database.py) to see how Python inserts and retrieves data from PostgreSQL.

---

### Phase 4: Data Science & AI Threat Detection
14. **Pandas & Data Cleaning:** Study [`ai/preprocessing.py`](file:///ai/preprocessing.py) to understand DataFrames, column normalization, and handling missing data.
15. **Rule-Based Anomaly Detection:** Study [`ai/anomaly_detection.py`](file:///ai/anomaly_detection.py) to learn how security rules calculate Risk Scores (0-100).
16. **Event Correlation:** Study [`backend/correlation.py`](file:///backend/correlation.py) to understand how isolated logs are grouped into multi-stage cyber incidents (`INC-001`).

---

### Phase 5: Digital Forensics & Reporting
17. **Forensic Timeline:** Study [`backend/timeline.py`](file:///backend/timeline.py) and [`timeline.html`](file:///frontend/timeline.html) to see how the Time Machine lets investigators travel through an attack.
18. **Evidence Mapping:** Study [`backend/evidence.py`](file:///backend/evidence.py) and [`evidence.html`](file:///frontend/evidence.html) to visualize links between Users, Devices, IPs, and Files.
19. **Report Generation & ReportLab PDF:** Study [`backend/report.py`](file:///backend/report.py) to see how Python automatically generates publication-ready PDF documents.
