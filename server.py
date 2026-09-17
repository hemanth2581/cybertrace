"""
========================================================
CYBERTRACE - AI DIGITAL FORENSICS TIME MACHINE
Standard Library Built-in Python Server (server.py)
========================================================

Beginner Concepts:
- What is server.py?
  This file runs a lightweight web server using Python's built-in `http.server` module.
  There is NO Django, NO Flask, and NO FastAPI needed!
- What does it do?
  1. Serves HTML, CSS, and JavaScript files to your browser.
  2. Listens for API requests sent by JavaScript `fetch()`.
  3. Executes our Python AI and forensic modules (Pandas, Anomaly Detection, Correlation, Timeline, ReportLab).
  4. Returns results back to the browser as JSON data or PDF downloads.
"""

import os
import json
import urllib.parse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from typing import Dict, Any

# Import backend modules
import backend.database as db
import backend.events as events_service
import backend.anomaly as anomaly_service
import backend.correlation as correlation_service
import backend.timeline as timeline_service
import backend.evidence as evidence_service
import backend.investigator as investigator_service
import backend.report as report_service

# Directory configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
SAMPLE_DATA_DIR = os.path.join(BASE_DIR, "sample_data")
REPORTS_DIR = os.path.join(BASE_DIR, "generated_reports")
PORT = int(os.getenv("PORT", 8000))


class CyberTraceRequestHandler(SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler that routes both static frontend web pages
    and backend REST API endpoints.
    """

    def __init__(self, *args, **kwargs):
        # Serve static assets from frontend directory by default
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    # ----------------------------------------------------
    # HTTP HELPER METHODS
    # ----------------------------------------------------
    def send_json_response(self, data: Any, status_code: int = 200):
        """Sends a JSON response to the browser."""
        response_bytes = json.dumps(data, indent=2, default=str).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(response_bytes)

    def read_post_body(self) -> bytes:
        """Reads raw POST body bytes sent by browser."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            return self.rfile.read(content_length)
        return b''

    def do_OPTIONS(self):
        """Handles CORS preflight checks."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    # ----------------------------------------------------
    # GET REQUEST ROUTER
    # ----------------------------------------------------
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # 1. API Endpoints
        if path == '/api/status':
            status = db.get_connection_status()
            stats = events_service.compute_event_stats()
            self.send_json_response({"database": status, "stats": stats})
            return

        elif path == '/api/events':
            events = events_service.get_all_events()
            self.send_json_response({"events": events, "count": len(events)})
            return

        elif path == '/api/stats':
            stats = events_service.compute_event_stats()
            self.send_json_response(stats)
            return

        elif path == '/api/anomalies':
            anomalies = anomaly_service.get_detected_anomalies()
            self.send_json_response(anomalies)
            return

        elif path == '/api/incidents':
            incidents = db.get_incidents()
            if not incidents:
                incidents = correlation_service.correlate_events_into_incidents()
            self.send_json_response({"incidents": incidents, "count": len(incidents)})
            return

        elif path == '/api/timeline':
            timeline = timeline_service.generate_forensic_timeline()
            self.send_json_response(timeline)
            return

        elif path == '/api/evidence':
            graph = evidence_service.get_evidence_graph()
            self.send_json_response(graph)
            return

        elif path == '/api/report':
            inc_id = query_params.get('incident_id', [None])[0]
            report = report_service.generate_incident_report(inc_id)
            self.send_json_response(report)
            return

        elif path == '/api/report/pdf':
            # Generate ReportLab PDF and stream binary file
            try:
                inc_id = query_params.get('incident_id', [None])[0]
                pdf_path = report_service.export_report_pdf(inc_id)
                with open(pdf_path, 'rb') as f:
                    pdf_bytes = f.read()

                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Disposition', f'attachment; filename="{os.path.basename(pdf_path)}"')
                self.send_header('Content-Length', str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            except Exception as e:
                self.send_json_response({"error": f"Failed to generate PDF: {str(e)}"}, status_code=500)
                return

        # 2. HTML Page Routing / Fallbacks
        # If accessing root URL, serve index.html
        if path == '/' or path == '':
            self.path = '/index.html'
        elif not os.path.splitext(path)[1]:
            # If path doesn't have an extension (e.g. /timeline), check if /timeline.html exists
            candidate = os.path.join(FRONTEND_DIR, path.lstrip('/') + '.html')
            if os.path.exists(candidate):
                self.path = path + '.html'

        # Serve static file using parent handler
        return super().do_GET()

    # ----------------------------------------------------
    # POST REQUEST ROUTER
    # ----------------------------------------------------
    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        raw_body = self.read_post_body()

        # 1. Upload CSV Logs Endpoint
        if path == '/api/upload':
            try:
                # Support direct CSV string, multipart payload, or JSON with csv content
                csv_payload = raw_body
                content_type = self.headers.get('Content-Type', '')

                if 'application/json' in content_type:
                    json_body = json.loads(raw_body.decode('utf-8'))
                    csv_payload = json_body.get('csv', '')
                elif 'multipart/form-data' in content_type:
                    # Basic extraction for multipart form upload
                    body_str = raw_body.decode('utf-8', errors='ignore')
                    lines = body_str.split('\r\n')
                    # Find beginning of CSV data after header boundary
                    csv_lines = []
                    inside_content = False
                    for line in lines:
                        if inside_content:
                            if line.startswith('------'):
                                break
                            csv_lines.append(line)
                        elif line == '' and not inside_content:
                            inside_content = True
                    csv_payload = '\n'.join(csv_lines)

                analyzed, stats, error = events_service.process_and_save_csv_logs(csv_payload)
                if error:
                    self.send_json_response({"status": "error", "message": error}, status_code=400)
                    return

                # Auto-run correlation to create incidents
                correlation_service.correlate_events_into_incidents(analyzed)

                self.send_json_response({
                    "status": "success",
                    "message": f"Successfully ingested and analyzed {len(analyzed)} security events.",
                    "total_events": len(analyzed),
                    "stats": stats
                })
            except Exception as e:
                self.send_json_response({"status": "error", "message": f"Upload processing error: {str(e)}"}, status_code=500)
            return

        # 2. Load Demo Scenario Endpoint
        elif path == '/api/demo':
            try:
                body_json = json.loads(raw_body.decode('utf-8')) if raw_body else {}
                scenario = body_json.get('scenario', 'account_compromise')
                
                # Map scenario name to sample CSV file
                filename_map = {
                    'normal_activity': 'normal_activity.csv',
                    'account_compromise': 'account_compromise.csv',
                    'data_exfiltration': 'data_exfiltration.csv'
                }
                sample_file = filename_map.get(scenario, 'account_compromise.csv')
                sample_path = os.path.join(SAMPLE_DATA_DIR, sample_file)

                if not os.path.exists(sample_path):
                    self.send_json_response({"status": "error", "message": f"Sample file not found: {sample_file}"}, status_code=404)
                    return

                with open(sample_path, 'r', encoding='utf-8') as f:
                    csv_content = f.read()

                analyzed, stats, error = events_service.process_and_save_csv_logs(csv_content)
                if error:
                    self.send_json_response({"status": "error", "message": error}, status_code=400)
                    return

                # Correlate events into incidents
                incidents = correlation_service.correlate_events_into_incidents(analyzed)

                self.send_json_response({
                    "status": "success",
                    "scenario": scenario,
                    "filename": sample_file,
                    "message": f"Loaded demo scenario: '{scenario.replace('_', ' ').title()}' ({len(analyzed)} events).",
                    "stats": stats,
                    "incidents_created": len(incidents)
                })
            except Exception as e:
                self.send_json_response({"status": "error", "message": f"Demo loading failed: {str(e)}"}, status_code=500)
            return

        # 3. AI Investigator Query Endpoint
        elif path == '/api/investigate':
            try:
                body_json = json.loads(raw_body.decode('utf-8')) if raw_body else {}
                question = body_json.get('question', 'What happened?')
                result = investigator_service.answer_investigator_query(question)
                self.send_json_response(result)
            except Exception as e:
                self.send_json_response({"error": str(e)}, status_code=500)
            return

        # 4. Re-evaluate Anomalies Endpoint
        elif path == '/api/anomalies/reevaluate':
            res = anomaly_service.reevaluate_anomalies()
            self.send_json_response(res)
            return

        # 5. Clear Workspace Endpoint
        elif path == '/api/clear':
            db.clear_database()
            self.send_json_response({"status": "success", "message": "Database cleared successfully."})
            return

        self.send_json_response({"error": "Endpoint not found"}, status_code=404)


def run_server():
    """
    Initializes default demo data and starts the multi-threaded HTTP server.
    """
    # Preload the Master Demo Scenario (Account Compromise) on startup so the app is ready immediately
    master_demo_path = os.path.join(SAMPLE_DATA_DIR, 'account_compromise.csv')
    if os.path.exists(master_demo_path):
        try:
            with open(master_demo_path, 'r', encoding='utf-8') as f:
                analyzed, stats, _ = events_service.process_and_save_csv_logs(f.read())
                correlation_service.correlate_events_into_incidents(analyzed)
            print(f"[CyberTrace] Master Demo Scenario pre-loaded ({len(analyzed)} events).")
        except Exception as e:
            print(f"[CyberTrace] Note: Initial preload skipped ({e}).")

    server_address = ('127.0.0.1', PORT)
    httpd = ThreadingHTTPServer(server_address, CyberTraceRequestHandler)
    print("=" * 60)
    print("CYBERTRACE: AI DIGITAL FORENSICS TIME MACHINE")
    print(f"Server running at: http://127.0.0.1:{PORT}")
    print("Zero-Framework Python Full Stack (Built-in HTTP Server)")
    print("Press Ctrl+C to stop the server.")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[CyberTrace] Server stopped gracefully.")
        httpd.server_close()


if __name__ == '__main__':
    run_server()
