# CyberTrace — Complete File Structure Guide

This guide describes every key file and directory in the **CyberTrace** repository.

```
CyberTrace/
│
├── src/main/java/com/cybertrace/
│   ├── CyberTraceApplication.java         # Main Spring Boot Application entry point
│   │
│   ├── controller/
│   │   ├── SecurityEventController.java   # POST /api/events/analyze (CSV upload & analysis)
│   │   ├── AnalysisController.java        # POST /api/analyze (JSON payload analysis)
│   │   ├── IncidentController.java        # POST /api/incidents/analyze
│   │   ├── TimelineController.java        # POST /api/timeline/generate
│   │   ├── EvidenceController.java        # POST /api/evidence/generate
│   │   ├── InvestigatorController.java    # POST /api/investigator/query (Forensic Q&A)
│   │   ├── ReportController.java          # POST /api/report/pdf (Binary PDF generation)
│   │   └── HealthController.java          # GET /api/health (System status)
│   │
│   ├── service/
│   │   ├── CsvProcessingService.java      # Validates CSV columns & parses stream
│   │   ├── RiskAnalysisService.java       # Heuristic penalty scoring (0-100)
│   │   ├── AnomalyDetectionService.java   # Filters suspicious events into anomalies
│   │   ├── IncidentService.java           # Correlates anomalies into INC-001 cases
│   │   ├── TimelineService.java           # Reconstructs attack chronology & flags 1st event
│   │   ├── EvidenceService.java           # Builds User->Device->IP->File relationship chain
│   │   ├── InvestigatorService.java       # Evidence-grounded deterministic Q&A reasoning
│   │   └── PdfReportService.java          # Compiles official PDF report using OpenPDF
│   │
│   ├── model/
│   │   ├── SecurityEvent.java             # Normalized event entity
│   │   ├── Anomaly.java                   # Flagged suspicious event model
│   │   ├── Incident.java                  # Correlated incident case dossier
│   │   ├── TimelineEvent.java             # Chronological timeline item
│   │   └── Evidence.java                  # Entity relationship chain model
│   │
│   ├── dto/
│   │   ├── AnalysisResult.java            # Pipeline response container
│   │   ├── InvestigatorRequest.java       # Question + evidence payload
│   │   └── InvestigatorResponse.java      # Answer + confidence payload
│   │
│   └── util/
│       ├── IpUtils.java                   # RFC1918 private subnet vs external IP validator
│       └── RiskUtils.java                 # Sensitive files and severity level mapping
│
├── src/main/resources/
│   ├── application.properties             # Spring Boot configuration (Port 8080, uploads)
│   │
│   └── static/                            # Frontend Web Application (HTML/CSS/JS)
│       ├── index.html                     # SOC Dashboard & KPIs
│       ├── upload.html                    # CSV Upload & Demo Scenario Selector
│       ├── events.html                    # Filterable Event Explorer
│       ├── anomalies.html                 # Flagged Anomalies & Scoring Matrix
│       ├── investigation.html             # Incident Investigation Dossiers
│       ├── timeline.html                  # Forensic Time Machine Player
│       ├── evidence.html                  # Evidence Relationship Graph
│       ├── investigator.html              # AI Forensic Q&A Chat Window
│       ├── report.html                    # Incident Report & PDF Exporter
│       ├── how-it-works.html              # 8-step pipeline explainer
│       │
│       ├── css/
│       │   └── style.css                  # Dark cybersecurity SOC theme
│       │
│       └── js/
│           ├── storage.js                 # Pure browser localStorage operations
│           ├── api.js                     # Fetch client for Spring Boot REST endpoints
│           ├── nav.js                     # Unified sidebar, header, and mobile offcanvas
│           ├── dashboard.js               # Dashboard metrics & active incident card
│           ├── upload.js                  # Dropzone & demo loader
│           ├── events.js                  # Search and multi-filter table
│           ├── anomalies.js               # Anomaly table rendering
│           ├── investigation.js           # Dossier rendering & SOC playbooks
│           ├── timeline.js                # Timeline playback controller
│           ├── evidence.js                # Evidence relationship chain rendering
│           ├── investigator.js            # Chat Q&A & quick prompt pills
│           └── report.js                  # Report preview & PDF download handler
│
├── demo/
│   ├── account_compromise.csv             # Multi-stage credential compromise demo
│   ├── data_exfiltration.csv              # Database exfiltration demo
│   └── normal_activity.csv               # Clean enterprise operational baseline
│
├── docs/
│   ├── BEGINNER_GUIDE.md                  # Introductory guide for codeathon judges
│   ├── PROJECT_FLOW.md                    # Data flow & architecture explanation
│   └── FILE_GUIDE.md                      # Comprehensive file directory reference
│
├── pom.xml                                # Maven build definition & dependencies
├── mvnw.cmd                               # Windows Maven wrapper script
├── README.md                              # Main project documentation
└── .gitignore                             # Git ignore rules
```
