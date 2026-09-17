"""
CyberTrace HTTP Endpoint Verification
-------------------------------------
Tests that server.py serves HTML, static CSS/JS, and REST API endpoints.
"""

import urllib.request
import json
import threading
import time
import os
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_endpoint(path, expected_status=200):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        status = response.status
        content_type = response.headers.get("Content-Type", "")
        data = response.read()
        print(f"[PASS] {path} -> Status {status} | Type: {content_type} ({len(data)} bytes)")
        assert status == expected_status

def main():
    server_thread = None
    httpd = None

    # Check if server is already running
    try:
        urllib.request.urlopen(f"{BASE_URL}/api/status", timeout=1)
        print("[CyberTrace Test] Existing server detected on port 8000.")
    except Exception:
        print("[CyberTrace Test] Starting temporary in-process test server...")
        from server import ThreadingHTTPServer, CyberTraceRequestHandler, PORT
        import backend.events as events_service
        import backend.correlation as correlation_service

        # Preload master demo scenario
        demo_path = os.path.join(os.path.dirname(__file__), 'sample_data', 'account_compromise.csv')
        if os.path.exists(demo_path):
            with open(demo_path, 'r', encoding='utf-8') as f:
                analyzed, _, _ = events_service.process_and_save_csv_logs(f.read())
                correlation_service.correlate_events_into_incidents(analyzed)

        httpd = ThreadingHTTPServer(('127.0.0.1', PORT), CyberTraceRequestHandler)
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        time.sleep(0.5)

    print("\nTesting CyberTrace Web & API Endpoints:")
    try:
        test_endpoint("/")
        test_endpoint("/index.html")
        test_endpoint("/upload.html")
        test_endpoint("/events.html")
        test_endpoint("/anomalies.html")
        test_endpoint("/investigation.html")
        test_endpoint("/timeline.html")
        test_endpoint("/evidence.html")
        test_endpoint("/investigator.html")
        test_endpoint("/report.html")
        test_endpoint("/how-it-works.html")
        test_endpoint("/css/style.css")
        test_endpoint("/js/main.js")
        test_endpoint("/api/status")
        test_endpoint("/api/events")
        test_endpoint("/api/stats")
        test_endpoint("/api/anomalies")
        test_endpoint("/api/incidents")
        test_endpoint("/api/timeline")
        test_endpoint("/api/evidence")
        test_endpoint("/api/report")
        test_endpoint("/api/report/pdf")
        print("\n[PASS] All Web Pages, Static Assets & REST APIs Verified Successfully!")
    finally:
        if httpd:
            httpd.shutdown()
            httpd.server_close()

if __name__ == "__main__":
    main()

