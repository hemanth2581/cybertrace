"""
CyberTrace Automated End-to-End Test Suite
-----------------------------------------
Validates all backend pipelines, AI anomaly detection, event correlation,
forensic timeline reconstruction, AI QA responder, and ReportLab PDF generation.
"""

import os
import sys

# Ensure current directory is on python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai.preprocessing import load_and_clean_csv
from ai.anomaly_detection import analyze_all_events
import backend.database as db
import backend.events as events_service
import backend.correlation as correlation_service
import backend.timeline as timeline_service
import backend.evidence as evidence_service
import backend.investigator as investigator_service
import backend.report as report_service


def test_master_scenario():
    print("\n--- TEST 1: MASTER DEMO SCENARIO (Account Compromise) ---")
    csv_path = os.path.join("sample_data", "account_compromise.csv")
    assert os.path.exists(csv_path), "account_compromise.csv not found!"
    
    with open(csv_path, "r", encoding="utf-8") as f:
        csv_content = f.read()
        
    analyzed, stats, error = events_service.process_and_save_csv_logs(csv_content)
    assert not error, f"Processing error: {error}"
    assert len(analyzed) == 8, f"Expected 8 events, got {len(analyzed)}"
    print(f"[PASS] Successfully processed {len(analyzed)} events.")
    
    # Check Master Scenario metrics
    max_risk = max(e['risk_score'] for e in analyzed)
    print(f"Peak Risk Score: {max_risk}/100")
    assert max_risk == 92, f"Expected max risk score 92, got {max_risk}"
    
    critical_events = [e for e in analyzed if e['severity'] == 'CRITICAL']
    assert len(critical_events) > 0, "Expected critical events!"
    print(f"[PASS] Verified Risk Score 92/100 and CRITICAL severity.")
    
    # Check Timeline & First Suspicious Event
    timeline = timeline_service.generate_forensic_timeline(analyzed)
    first_suspicious_idx = timeline['first_suspicious_index']
    first_suspicious = timeline['steps'][first_suspicious_idx]
    
    print(f"First Suspicious Event Index: {first_suspicious_idx} -> Timestamp: {first_suspicious['timestamp']}")
    assert first_suspicious['timestamp'] == '10:15', f"Expected 10:15, got {first_suspicious['timestamp']}"
    print("[PASS] Verified First Suspicious Event is 10:15.")
    
    # Check Correlation & Incidents
    incidents = correlation_service.correlate_events_into_incidents(analyzed)
    assert len(incidents) >= 1, "Expected at least 1 correlated incident"
    inc = incidents[0]
    print(f"[PASS] Incident Correlated: {inc['incident_id']} - {inc['title']} (Risk: {inc['risk_score']}, Severity: {inc['severity']})")
    assert inc['severity'] == 'CRITICAL'
    
    # Check Evidence Graph
    graph = evidence_service.get_evidence_graph()
    assert len(graph['nodes']) >= 4, f"Expected >=4 nodes, got {len(graph['nodes'])}"
    print(f"[PASS] Evidence graph generated with {len(graph['nodes'])} entities and {len(graph['links'])} links.")
    
    # Check AI Investigator
    q1 = investigator_service.answer_investigator_query("What was the first suspicious event?")
    print(f"AI QA (First Suspicious Event): {q1['answer'][:120]}...")
    assert "10:15" in q1['answer']
    
    q2 = investigator_service.answer_investigator_query("What happened?")
    print(f"AI QA (What happened): {q2['answer'][:120]}...")
    assert "Rahul" in q2['answer'] or "compromise" in q2['answer'].lower()
    print("[PASS] Verified AI Investigator queries are grounded in facts.")
    
    # Check ReportLab PDF Export
    pdf_path = report_service.export_report_pdf(inc['incident_id'])
    assert os.path.exists(pdf_path), f"PDF file was not created at {pdf_path}"
    file_size = os.path.getsize(pdf_path)
    assert file_size > 1000, f"PDF file seems too small: {file_size} bytes"
    print(f"[PASS] Verified ReportLab PDF generation: {pdf_path} ({file_size} bytes).")


def test_normal_activity_scenario():
    print("\n--- TEST 2: NORMAL ACTIVITY SCENARIO ---")
    csv_path = os.path.join("sample_data", "normal_activity.csv")
    with open(csv_path, "r", encoding="utf-8") as f:
        csv_content = f.read()
        
    analyzed, stats, error = events_service.process_and_save_csv_logs(csv_content)
    assert not error
    suspicious_count = len([e for e in analyzed if e.get('is_anomaly')])
    print(f"[PASS] Normal activity processed: {len(analyzed)} events, {suspicious_count} anomalies.")
    assert suspicious_count == 0, f"Expected 0 anomalies, got {suspicious_count}"


def test_data_exfiltration_scenario():
    print("\n--- TEST 3: DATA EXFILTRATION SCENARIO ---")
    csv_path = os.path.join("sample_data", "data_exfiltration.csv")
    with open(csv_path, "r", encoding="utf-8") as f:
        csv_content = f.read()
        
    analyzed, stats, error = events_service.process_and_save_csv_logs(csv_content)
    assert not error
    max_risk = max(e['risk_score'] for e in analyzed)
    print(f"[PASS] Data exfiltration processed: {len(analyzed)} events, peak risk: {max_risk}/100.")
    assert max_risk >= 80, "Expected high/critical risk for data exfiltration"


if __name__ == "__main__":
    print("==================================================")
    print("RUNNING CYBERTRACE AUTOMATED VERIFICATION TESTS")
    print("==================================================")
    try:
        test_master_scenario()
        test_normal_activity_scenario()
        test_data_exfiltration_scenario()
        print("\n==================================================")
        print("ALL AUTOMATED TESTS PASSED SUCCESSFULLY! (100%)")
        print("==================================================")
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
