"""
CyberTrace Anomaly Service
--------------------------
Provides detailed anomaly insights and rule breakdowns for investigators.
"""

from typing import List, Dict, Any
import backend.database as db
from ai.anomaly_detection import analyze_all_events


def get_detected_anomalies() -> Dict[str, Any]:
    """
    Retrieves all detected anomalies, group by severity, and returns statistical breakdown.
    """
    events = db.get_events()
    anomalies = [e for e in events if e.get('is_anomaly') or e.get('risk_score', 0) > 30]
    
    # Sort by risk score descending
    anomalies_sorted = sorted(anomalies, key=lambda x: int(x.get('risk_score', 0) or 0), reverse=True)
    
    critical = [e for e in anomalies if e.get('severity') == 'CRITICAL']
    high = [e for e in anomalies if e.get('severity') == 'HIGH']
    medium = [e for e in anomalies if e.get('severity') == 'MEDIUM']
    
    # Extract unique detection reasons
    all_reasons = []
    for a in anomalies:
        for r in str(a.get('reason', '')).split(';'):
            r_clean = r.strip()
            if r_clean and r_clean not in all_reasons and r_clean != 'Normal routine activity':
                all_reasons.append(r_clean)

    return {
        "total_anomalies": len(anomalies),
        "critical_count": len(critical),
        "high_count": len(high),
        "medium_count": len(medium),
        "anomalies": anomalies_sorted,
        "flagged_reasons": all_reasons
    }


def reevaluate_anomalies() -> Dict[str, Any]:
    """
    Re-runs the anomaly detection engine across all stored logs.
    """
    current_events = db.get_events()
    if not current_events:
        return {"status": "error", "message": "No events loaded in database."}
        
    updated_events = analyze_all_events(current_events)
    db.clear_database()
    db.insert_events(updated_events)
    
    return {
        "status": "success",
        "message": f"Successfully reevaluated {len(updated_events)} events.",
        "results": get_detected_anomalies()
    }
