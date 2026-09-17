"""
CyberTrace Event Correlation Engine
-----------------------------------
Connects related suspicious security events into organized incident cases.

Beginner Concepts:
- What is Event Correlation?
  Individual security logs might just look like random events. Correlation connects the dots
  between the same user, device, IP address, and files over time to reveal a coordinated attack.
- Example:
  Rahul -> DEV01 -> 185.23.45.10 -> passwords.txt -> Data Transfer -> Permission Change.
"""

from typing import List, Dict, Any, Optional
import backend.database as db
from backend.evidence import extract_evidence_from_events


def correlate_events_into_incidents(events: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Groups suspicious security events by user/device/IP and creates structured Incident records.
    """
    if events is None:
        events = db.get_events()
        
    if not events:
        return []

    # Filter suspicious events
    suspicious_events = [e for e in events if e.get('is_anomaly') or e.get('risk_score', 0) > 30]
    
    if not suspicious_events:
        # If no high risk anomalies, create a baseline informational record if events exist
        incidents = []
        return incidents

    # Group suspicious events by primary user or IP
    user_groups: Dict[str, List[Dict[str, Any]]] = {}
    for ev in suspicious_events:
        user = str(ev.get('user', 'UNKNOWN')).strip()
        if user not in user_groups:
            user_groups[user] = []
        user_groups[user].append(ev)

    incidents = []
    inc_counter = 1

    for user, user_events in user_groups.items():
        # Sort chronologically
        user_events.sort(key=lambda x: str(x.get('timestamp', '')))
        
        inc_id = f"INC-00{inc_counter}"
        inc_counter += 1
        
        start_time = user_events[0].get('timestamp', '')
        end_time = user_events[-1].get('timestamp', '')
        
        # Calculate maximum risk score reached during the incident
        max_risk = max(int(e.get('risk_score', 0) or 0) for e in user_events)
        
        # Determine overall incident severity
        if max_risk >= 81:
            severity = 'CRITICAL'
        elif max_risk >= 61:
            severity = 'HIGH'
        elif max_risk >= 31:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
            
        # Collect distinct involved assets
        devices = list({str(e.get('device', '')) for e in user_events if e.get('device')})
        ips = list({str(e.get('ip', '')) for e in user_events if e.get('ip')})
        files = list({str(e.get('file', '')) for e in user_events if e.get('file')})
        
        # Detect attack stages present
        actions = [str(e.get('action', '')).upper() for e in user_events]
        event_types = [str(e.get('event_type', '')).upper() for e in user_events]
        
        stages = []
        if any('LOGIN' in et for et in event_types):
            stages.append("Initial Access / Brute Force Attempt")
        if any(f for f in files if f):
            stages.append(f"Credential / Sensitive Data Discovery ({', '.join(files)})")
        if any('TRANSFER' in et or 'UPLOAD' in act for et, act in zip(event_types, actions)):
            stages.append("Data Exfiltration")
        if any('PERMISSION' in et or 'CHANGED' in act for et, act in zip(event_types, actions)):
            stages.append("Privilege Escalation & Persistence")
            
        title = f"Unauthorized Account Compromise & Threat Activity - User: {user}"
        if "Data Exfiltration" in stages:
            title = f"Data Exfiltration & Security Breach - User: {user}"
            
        summary = (
            f"Incident {inc_id} involves user '{user}' operating across {len(user_events)} suspicious events "
            f"between {start_time} and {end_time}. Observed threat stages include: {', '.join(stages)}. "
            f"Involved IP addresses: {', '.join(ips)}; Target files: {', '.join(files) if files else 'None'}."
        )

        incident_record = {
            "incident_id": inc_id,
            "title": title,
            "start_time": start_time,
            "end_time": end_time,
            "risk_score": max_risk,
            "severity": severity,
            "summary": summary,
            "user": user,
            "devices": devices,
            "ips": ips,
            "files": files,
            "stages": stages,
            "event_count": len(user_events),
            "first_suspicious_event": user_events[0]
        }
        
        # Save incident to database
        db.insert_incident(incident_record)
        
        # Generate & save evidence links for this incident
        evidence_records = extract_evidence_from_events(inc_id, events)
        db.insert_evidence_batch(evidence_records)
        
        incidents.append(incident_record)

    return incidents
