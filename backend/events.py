"""
CyberTrace Events Manager
-------------------------
Handles log ingestion, anomaly scoring, event filtering, and dashboard statistics.
"""

from typing import List, Dict, Any, Tuple
from ai.preprocessing import load_and_clean_csv
from ai.anomaly_detection import analyze_all_events, compute_ml_isolation_forest
import backend.database as db


def process_and_save_csv_logs(csv_content: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any], str]:
    """
    Complete ingestion pipeline:
    1. Read and clean CSV using Pandas
    2. Score anomalies and calculate risk using rules + ML
    3. Clear previous workspace and persist to Supabase / Local DB
    4. Return analyzed records, summary statistics, and error message
    """
    # Step 1: Preprocess raw CSV
    df, clean_records, error = load_and_clean_csv(csv_content)
    if error:
        return [], {}, error
        
    if not clean_records:
        return [], {}, "No valid log records found in dataset."

    # Step 2: Anomaly detection and risk scoring
    analyzed_records = analyze_all_events(clean_records)
    
    # Optional ML IsolationForest anomaly score enrichment
    try:
        ml_scores = compute_ml_isolation_forest(analyzed_records)
        for i, score in enumerate(ml_scores):
            analyzed_records[i]['ml_anomaly_score'] = score
    except Exception:
        for ev in analyzed_records:
            ev['ml_anomaly_score'] = 0.0

    # Step 3: Persist into database
    db.clear_database()
    db.insert_events(analyzed_records)
    
    # Step 4: Compute dashboard stats
    stats = compute_event_stats(analyzed_records)
    
    return analyzed_records, stats, ""


def compute_event_stats(events: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Computes dashboard overview metrics:
    - Total Events
    - Suspicious Events (Risk > 30)
    - Critical Events (Risk > 80)
    - Average Risk Score
    - Severity Distribution
    """
    if events is None:
        events = db.get_events()
        
    if not events:
        return {
            "total_events": 0,
            "suspicious_events": 0,
            "critical_events": 0,
            "active_incidents": 0,
            "avg_risk_score": 0,
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "recent_events": [],
            "recent_suspicious": []
        }

    total = len(events)
    suspicious = [e for e in events if e.get('is_anomaly') or e.get('risk_score', 0) > 30]
    critical = [e for e in events if e.get('severity') == 'CRITICAL' or e.get('risk_score', 0) > 80]
    
    total_risk = sum(int(e.get('risk_score', 0) or 0) for e in events)
    avg_risk = round(total_risk / total, 1) if total > 0 else 0
    
    dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for e in events:
        sev = e.get('severity', 'LOW')
        dist[sev] = dist.get(sev, 0) + 1

    incidents = db.get_incidents()

    return {
        "total_events": total,
        "suspicious_events": len(suspicious),
        "critical_events": len(critical),
        "active_incidents": len(incidents) if incidents else (1 if len(suspicious) > 0 else 0),
        "avg_risk_score": avg_risk,
        "risk_distribution": dist,
        "recent_events": events[:10],
        "recent_suspicious": suspicious[:10]
    }


def get_all_events() -> List[Dict[str, Any]]:
    """
    Returns all events from database.
    """
    return db.get_events()


def get_anomalies_only() -> List[Dict[str, Any]]:
    """
    Returns only events flagged as anomalous or high/critical risk.
    """
    all_events = db.get_events()
    return [e for e in all_events if e.get('is_anomaly') or e.get('risk_score', 0) > 30]
