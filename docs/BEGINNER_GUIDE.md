# CYBERTRACE - BEGINNER-FRIENDLY FULL-STACK GUIDE

Welcome to full-stack development with Python! This guide explains every concept used in CyberTrace using simple, everyday language and concrete project examples.

---

## 1. Web Technologies (Frontend)

### HTML (HyperText Markup Language)
- **What is it?** HTML provides the structure and skeleton of web pages (headings, buttons, inputs, tables).
- **CyberTrace Example:** `upload.html` uses an `<input type="file">` to let you pick a CSV file and `<button>` to start analysis.

### CSS (Cascading Style Sheets)
- **What is it?** CSS styles the HTML, making it look beautiful with dark colors, glowing borders, and rounded cards.
- **CyberTrace Example:** `style.css` uses deep slate background colors (`#070b14`) and cyan neon highlights (`#00f2fe`) to create a professional cybersecurity dashboard look.

### JavaScript (JS)
- **What is it?** JavaScript runs inside your browser to make web pages interactive without needing to refresh.
- **CyberTrace Example:** In `timeline.html`, when you click **Play** or move the **Slider**, JavaScript updates the active event card in real time.

---

## 2. Backend & Server

### Python
- **What is it?** Python is a clean, readable programming language that runs on your computer or server.
- **CyberTrace Example:** Python handles reading files, calculating risk math, generating PDF files, and connecting to the database.

### Python Built-in HTTP Server (`http.server`)
- **What is it?** Python comes with its own built-in web server. You don't need heavy frameworks like Django or Flask to receive requests or serve HTML.
- **CyberTrace Example:** `server.py` listens on port `8000`. When you open `http://127.0.0.1:8000`, Python serves `index.html` and routes API requests.

---

## 3. Communication & APIs

### API (Application Programming Interface)
- **What is it?** A way for two different programs (the frontend in your browser and the backend in Python) to talk to each other.

### HTTP Request & HTTP Response
- **Request:** The browser sends a message to Python: *"Hey Python, give me the latest timeline steps!"* (`GET /api/timeline`).
- **Response:** Python sends back the data: *"Here are the 8 steps!"* (JSON data with status 200 OK).

### JavaScript `fetch()`
- **What is it?** The standard JavaScript function used to send HTTP requests to Python.
- **Example:**
```javascript
const response = await fetch("/api/events");
const data = await response.json();
console.log(data.events);
```

### JSON (JavaScript Object Notation)
- **What is it?** A lightweight text format for exchanging structured data between Python and JavaScript.
- **Example:**
```json
{
  "timestamp": "10:01",
  "user": "Rahul",
  "risk_score": 92,
  "severity": "CRITICAL"
}
```

---

## 4. Databases

### PostgreSQL
- **What is it?** A powerful, enterprise-grade relational database management system that stores information in structured tables with rows and columns.

### Supabase
- **What is it?** A modern cloud database service that gives you a hosted PostgreSQL database with simple Python client libraries.

### Database Concepts:
- **Table:** A collection of related data (like an Excel sheet). CyberTrace has `security_events`, `incidents`, `evidence`, and `investigation_reports`.
- **Row / Record:** A single entry in a table (e.g. one event at 10:01 for user Rahul).
- **Column / Field:** A specific attribute of each record (e.g. `timestamp`, `ip`, `risk_score`).

---

## 5. AI & Data Analysis

### CSV (Comma-Separated Values)
- **What is it?** A plain text file where data rows are separated by newlines and column values are separated by commas.

### Pandas & DataFrames
- **What is Pandas?** A Python library used for working with tabular data.
- **What is a DataFrame?** A 2D table held in Python memory.
- **Why clean data?** Real security logs might have empty spaces, missing usernames, or lowercase/uppercase inconsistencies. Pandas cleans them so math calculations never fail.

### Rule-Based Anomaly Detection
- **What is it?** Checking specific security rules:
  - Is the IP address external? (+20 points)
  - Did logins fail repeatedly? (+20 points)
  - Was `passwords.txt` accessed? (+20 points)
  - Was large data uploaded? (+15 points)
  - Were permissions changed? (+10 points)

### Risk Score vs. Anomaly Flag:
- **Risk Score:** A number from `0` to `100` showing threat magnitude.
- **Anomaly Flag:** A `True` or `False` boolean indicating if this event warrants investigation (Score > 30).

---

## 6. Digital Forensics Concepts

### Event Correlation
- Connecting multiple individual logs that involve the same user, device, and network address into a single coordinated incident.

### Time Machine Reconstruction
- Ordering all security events by timestamp so an analyst can watch what happened step by step.

### Legal Chain of Custody & Evidence
- Showing how evidence is linked (`Rahul` -> `DEV01` -> `185.23.45.10` -> `passwords.txt` -> `850 KB Data Transfer`).
