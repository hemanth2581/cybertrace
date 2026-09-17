"""
CyberTrace Digital Forensics Time Machine Engine
------------------------------------------------
Reconstructs the precise chronological step-by-step history of a cyber incident.
"""

from typing import List, Dict, Any, Optional
import backend.database as db


def generate_forensic_timeline(events: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Creates an enriched timeline for the Forensics Time Machine player.
    """
    if events is None:
        events = db.get_events()
        
    if not events:
        return {
            "total_steps": 0,
            "first_suspicious_index": -1,
            "steps": []
        }

    # Sort events by timestamp order
    sorted_events = sorted(events, key=lambda x: str(x.get('timestamp', '')))
    
    steps = []
    first_suspicious_index = -1
    highest_risk_so_far = 0
    active_compromise = False

    for idx, ev in enumerate(sorted_events):
        risk = int(ev.get('risk_score', 0) or 0)
        is_suspicious = bool(ev.get('is_anomaly', False)) or risk >= 20
        
        if is_suspicious and first_suspicious_index == -1:
            first_suspicious_index = idx
            active_compromise = True

        if risk > highest_risk_so_far:
            highest_risk_so_far = risk

        # Build timeline step snapshot
        step_item = {
            "step_index": idx,
            "total_steps": len(sorted_events),
            "timestamp": ev.get('timestamp', ''),
            "user": ev.get('user', ''),
            "device": ev.get('device', ''),
            "ip": ev.get('ip', ''),
            "event_type": ev.get('event_type', ''),
            "action": ev.get('action', ''),
            "file": ev.get('file', ''),
            "data_size": ev.get('data_size', 0),
            "risk_score": risk,
            "severity": ev.get('severity', 'LOW'),
            "reason": ev.get('reason', 'Normal routine activity'),
            "is_anomaly": is_suspicious,
            "is_first_suspicious": (idx == first_suspicious_index),
            "cumulative_max_risk": highest_risk_so_far,
            "status_headline": get_step_headline(ev, idx == first_suspicious_index)
        }
        steps.append(step_item)

    return {
        "total_steps": len(steps),
        "first_suspicious_index": first_suspicious_index if first_suspicious_index != -1 else 0,
        "steps": steps
    }


def get_step_headline(event: Dict[str, Any], is_first_suspicious: bool) -> str:
    """
    Returns a human-readable title for the time machine card.
    """
    ev_type = str(event.get('event_type', '')).upper()
    act = str(event.get('action', '')).upper()
    user = event.get('user', 'User')
    file_name = event.get('file', '')
    data_size = event.get('data_size', 0)

    if is_first_suspicious:
        return f"🚨 FIRST SUSPICIOUS EVENT: {user} login from foreign IP {event.get('ip')}"
    elif ev_type == 'LOGIN' and act == 'SUCCESS' and int(event.get('risk_score', 0)) <= 30:
        return f"Normal Login: {user} authenticated successfully"
    elif ev_type == 'LOGIN' and act == 'FAILED':
        return f"Authentication Failed: Password attempt rejected for {user}"
    elif ev_type == 'LOGIN' and act == 'SUCCESS':
        return f"⚠️ Suspicious Login: {user} access granted from foreign IP"
    elif file_name:
        return f"File Access: {user} {act.lower()} sensitive file '{file_name}'"
    elif data_size and data_size > 0:
        return f"Data Transfer: {data_size} KB transferred outbound via {event.get('ip')}"
    elif 'PERMISSION' in ev_type or 'CHANGED' in act:
        return f"Privilege Escalation: Security permissions modified"
    else:
        return f"{ev_type}: {act} executed by {user}"
