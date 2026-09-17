import os
import sys
import urllib.parse
import json
from http.server import BaseHTTPRequestHandler

# Ensure root project path is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import backend modules
import backend.database as db
import backend.events as events_service
import backend.anomaly as anomaly_service
import backend.correlation as correlation_service
import backend.timeline as timeline_service
import backend.evidence as evidence_service
import backend.investigator as investigator_service
import backend.report as report_service

SAMPLE_DATA_DIR = os.path.join(BASE_DIR, "sample_data")

# Preload master demo on cold-start if database is empty
def _ensure_initial_data():
    if not db.get_events():
        demo_path = os.path.join(SAMPLE_DATA_DIR, "account_compromise.csv")
        if os.path.exists(demo_path):
            try:
                with open(demo_path, "r", encoding="utf-8") as f:
                    analyzed, _, _ = events_service.process_and_save_csv_logs(f.read())
                    correlation_service.correlate_events_into_incidents(analyzed)
            except Exception:
                pass

_ensure_initial_data()


class handler(BaseHTTPRequestHandler):
    """
    Vercel Serverless Function Handler for CyberTrace REST APIs.
    """

    def send_json_response(self, data, status_code=200):
        response_bytes = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def read_post_body(self) -> bytes:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return self.rfile.read(content_length)
        return b""

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        _ensure_initial_data()
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Normalize path
        if not path.startswith("/api"):
            path = "/api" + path

        if path == "/api/status":
            status = db.get_connection_status()
            stats = events_service.compute_event_stats()
            self.send_json_response({"database": status, "stats": stats})
            return

        elif path == "/api/events":
            events = events_service.get_all_events()
            self.send_json_response({"events": events, "count": len(events)})
            return

        elif path == "/api/stats":
            stats = events_service.compute_event_stats()
            self.send_json_response(stats)
            return

        elif path == "/api/anomalies":
            anomalies = anomaly_service.get_detected_anomalies()
            self.send_json_response(anomalies)
            return

        elif path == "/api/incidents":
            incidents = db.get_incidents()
            if not incidents:
                incidents = correlation_service.correlate_events_into_incidents()
            self.send_json_response({"incidents": incidents, "count": len(incidents)})
            return

        elif path == "/api/timeline":
            timeline = timeline_service.generate_forensic_timeline()
            self.send_json_response(timeline)
            return

        elif path == "/api/evidence":
            graph = evidence_service.get_evidence_graph()
            self.send_json_response(graph)
            return

        elif path == "/api/report":
            inc_id = query_params.get("incident_id", [None])[0]
            report = report_service.generate_incident_report(inc_id)
            self.send_json_response(report)
            return

        elif path == "/api/report/pdf":
            try:
                inc_id = query_params.get("incident_id", [None])[0]
                pdf_path = report_service.export_report_pdf(inc_id)
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()

                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(pdf_path)}"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            except Exception as e:
                self.send_json_response({"error": f"Failed to generate PDF: {str(e)}"}, status_code=500)
                return

        self.send_json_response({"error": f"Endpoint not found: {path}"}, status_code=404)

    def do_POST(self):
        _ensure_initial_data()
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        if not path.startswith("/api"):
            path = "/api" + path

        raw_body = self.read_post_body()

        if path == "/api/upload":
            try:
                csv_payload = raw_body
                content_type = self.headers.get("Content-Type", "")

                if "application/json" in content_type:
                    json_body = json.loads(raw_body.decode("utf-8"))
                    csv_payload = json_body.get("csv", "")
                elif "multipart/form-data" in content_type:
                    body_str = raw_body.decode("utf-8", errors="ignore")
                    lines = body_str.split("\r\n")
                    csv_lines = []
                    inside_content = False
                    for line in lines:
                        if inside_content:
                            if line.startswith("------"):
                                break
                            csv_lines.append(line)
                        elif line == "" and not inside_content:
                            inside_content = True
                    csv_payload = "\n".join(csv_lines)

                analyzed, stats, error = events_service.process_and_save_csv_logs(csv_payload)
                if error:
                    self.send_json_response({"status": "error", "message": error}, status_code=400)
                    return

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

        elif path == "/api/demo":
            try:
                body_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                scenario = body_json.get("scenario", "account_compromise")
                
                filename_map = {
                    "normal_activity": "normal_activity.csv",
                    "account_compromise": "account_compromise.csv",
                    "data_exfiltration": "data_exfiltration.csv"
                }
                sample_file = filename_map.get(scenario, "account_compromise.csv")
                sample_path = os.path.join(SAMPLE_DATA_DIR, sample_file)

                if not os.path.exists(sample_path):
                    self.send_json_response({"status": "error", "message": f"Sample file not found: {sample_file}"}, status_code=404)
                    return

                with open(sample_path, "r", encoding="utf-8") as f:
                    csv_content = f.read()

                analyzed, stats, error = events_service.process_and_save_csv_logs(csv_content)
                if error:
                    self.send_json_response({"status": "error", "message": error}, status_code=400)
                    return

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

        elif path == "/api/investigate":
            try:
                body_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                question = body_json.get("question", "What happened?")
                result = investigator_service.answer_investigator_query(question)
                self.send_json_response(result)
            except Exception as e:
                self.send_json_response({"error": str(e)}, status_code=500)
            return

        elif path == "/api/anomalies/reevaluate":
            res = anomaly_service.reevaluate_anomalies()
            self.send_json_response(res)
            return

        elif path == "/api/clear":
            db.clear_database()
            self.send_json_response({"status": "success", "message": "Database cleared successfully."})
            return

        self.send_json_response({"error": f"Endpoint not found: {path}"}, status_code=404)
