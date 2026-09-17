"""
CyberTrace AI Anomaly Detection Module
---------------------------------------
This module evaluates security events to determine:
1. Risk Score (0 to 100)
2. Severity Level (LOW, MEDIUM, HIGH, CRITICAL)
3. Is Anomaly Flag (True / False)
4. List of Reasons (e.g. Unusual IP, Sensitive File Access)

Beginner Concepts:
- Rule-based detection: Checking explicit safety rules (like "is this IP foreign?", "did logins fail?").
- Risk Score: Numerical value from 0 to 100 representing the threat severity.
- Isolation Forest: A machine-learning algorithm from Scikit-Learn that spots rare outliers.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# Known sensitive files often targeted in cyber attacks
SENSITIVE_FILES = [
    'passwords.txt',
    'password.txt',
    'shadow',
    'id_rsa',
    'credentials.json',
    '.env',
    'customer_database_dump.sql',
    'database_dump.sql',
    'keys.pem',
    'secret.key',
    'config.php',
    'admin_hashes.csv'
]

# Known private/internal IP prefixes (local corporate network)
INTERNAL_IP_PREFIXES = ('192.168.', '10.', '172.16.', '127.0.0.1')


def is_unusual_ip(ip: str, baseline_ips: set = None) -> bool:
    """
    Checks if an IP address is external or unusual compared to normal internal company IPs.
    """
    ip = str(ip).strip()
    if not ip or ip == 'UNKNOWN':
        return False
    
    # If a baseline of known normal IPs was provided and this IP isn't in it
    if baseline_ips and len(baseline_ips) > 0:
        if ip not in baseline_ips and not ip.startswith(INTERNAL_IP_PREFIXES):
            return True
            
    # Check if it's an external/foreign public IP (e.g., 185.23.45.10, 103.21.244.2)
    return not ip.startswith(INTERNAL_IP_PREFIXES)


def calculate_severity(risk_score: int) -> str:
    """
    Maps numerical risk score (0-100) to human-readable severity level.
    0-30   = LOW
    31-60  = MEDIUM
    61-80  = HIGH
    81-100 = CRITICAL
    """
    if risk_score <= 30:
        return 'LOW'
    elif risk_score <= 60:
        return 'MEDIUM'
    elif risk_score <= 80:
        return 'HIGH'
    else:
        return 'CRITICAL'


def analyze_single_event(
    event: Dict[str, Any], 
    user_failed_attempts: int = 0,
    known_user_devices: set = None,
    known_user_ips: set = None
) -> Dict[str, Any]:
    """
    Applies beginner-friendly rule-based cybersecurity checks to a single event.
    
    Rule Points:
    - Unusual IP: +20
    - Multiple failed logins: +20
    - Single failed login: +10
    - New/Unknown device: +15
    - Sensitive file access: +20
    - Large data transfer (>500 or >100MB): +15
    - Permission change: +10
    """
    risk_score = 0
    reasons = []
    
    ip = str(event.get('ip', '')).strip()
    user = str(event.get('user', '')).strip()
    device = str(event.get('device', '')).strip()
    event_type = str(event.get('event_type', '')).upper().strip()
    action = str(event.get('action', '')).upper().strip()
    file_accessed = str(event.get('file', '')).lower().strip()
    data_size = int(event.get('data_size', 0) or 0)
    
    # 1. Check for Unusual External IP (+20)
    if is_unusual_ip(ip, known_user_ips):
        risk_score += 20
        reasons.append("Unusual External IP detected")
    
    # 2. Check for Failed Logins & Brute Force Patterns (+10 to +20)
    if event_type == 'LOGIN' and action == 'FAILED':
        if user_failed_attempts >= 1:
            risk_score += 20
            reasons.append("Multiple failed logins (Brute force indicator)")
        else:
            risk_score += 10
            reasons.append("Failed login attempt")
    elif user_failed_attempts >= 2 and action == 'SUCCESS':
        # Successful login right after multiple failures
        risk_score += 20
        reasons.append("Successful login immediately following multiple failed attempts")
    
    # 3. Check for New/Unknown Device (+15)
    if known_user_devices and device not in known_user_devices and len(known_user_devices) > 0:
        risk_score += 15
        reasons.append(f"Unrecognized device ({device}) for user {user}")
        
    # 4. Check for Sensitive File Access (+20)
    if file_accessed:
        if any(sens in file_accessed for sens in SENSITIVE_FILES):
            risk_score += 20
            reasons.append(f"Sensitive credential/system file accessed ({file_accessed})")
        elif 'admin' in file_accessed or 'secret' in file_accessed or 'dump' in file_accessed:
            risk_score += 15
            reasons.append(f"High-risk file accessed ({file_accessed})")
            
    # 5. Check for Large Data Transfer (+15)
    if event_type in ['DATA_TRANSFER', 'UPLOAD', 'EXFILTRATION'] or action in ['UPLOAD', 'DOWNLOAD']:
        if data_size >= 500:
            risk_score += 15
            reasons.append(f"Large data transfer volume detected ({data_size} units)")
        elif data_size > 100:
            risk_score += 10
            reasons.append(f"Unusual data volume transfer ({data_size} units)")
            
    # 6. Check for Permission Changes / Privilege Escalation (+10)
    if event_type in ['PERMISSION', 'PRIVILEGE', 'AUTH'] or action in ['CHANGED', 'ESCALATED', 'GRANT']:
        risk_score += 10
        reasons.append("System security permission or role modified")

    # If multiple indicators combine on a foreign IP, apply a compounding attack indicator bonus (+7)
    if len(reasons) >= 3 and is_unusual_ip(ip):
        risk_score += 7

    # Cap score at 100
    risk_score = min(risk_score, 100)
    
    severity = calculate_severity(risk_score)
    is_anomaly = risk_score >= 31  # MEDIUM, HIGH, or CRITICAL are flagged as anomalies
    
    return {
        'risk_score': risk_score,
        'severity': severity,
        'is_anomaly': is_anomaly,
        'reason': '; '.join(reasons) if reasons else 'Normal routine activity'
    }


def analyze_all_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Iterates through all events chronologically, maintaining state context
    (such as failed login tracking and known user baselines) to score every event.
    """
    analyzed_events = []
    
    # State trackers across the timeline
    user_failed_counters: Dict[str, int] = {}
    user_known_devices: Dict[str, set] = {}
    user_known_ips: Dict[str, set] = {}
    session_threat_history: Dict[Tuple[str, str], List[str]] = {} # (user, ip) -> list of previous threat indicators
    
    # First pass: learn baseline normal internal IPs/devices if any exist
    for ev in events:
        u = str(ev.get('user', '')).strip()
        d = str(ev.get('device', '')).strip()
        ip = str(ev.get('ip', '')).strip()
        act = str(ev.get('action', '')).upper().strip()
        
        if u not in user_known_devices:
            user_known_devices[u] = set()
            user_known_ips[u] = set()
            
        if not is_unusual_ip(ip) and act == 'SUCCESS':
            user_known_ips[u].add(ip)
            user_known_devices[u].add(d)

    # Second pass: compute progressive risk score and reasons for each event
    for event in events:
        u = str(event.get('user', '')).strip()
        ip = str(event.get('ip', '')).strip()
        d = str(event.get('device', '')).strip()
        act = str(event.get('action', '')).upper().strip()
        ev_type = str(event.get('event_type', '')).upper().strip()
        file_accessed = str(event.get('file', '')).lower().strip()
        data_size = int(event.get('data_size', 0) or 0)
        
        failed_count = user_failed_counters.get(u, 0)
        session_key = (u, ip)
        if session_key not in session_threat_history:
            session_threat_history[session_key] = []

        history = session_threat_history[session_key]
        
        # Base threat evaluation for this event
        risk_score = 0
        reasons = []

        # 1. Unusual External IP (+20)
        is_foreign = is_unusual_ip(ip, user_known_ips.get(u, set()))
        if is_foreign:
            risk_score += 20
            reasons.append("Unusual External IP detected")

        # 2. Failed logins & brute force patterns (+10 to +20)
        if ev_type == 'LOGIN' and act == 'FAILED':
            if failed_count >= 1 or "Multiple failed logins" in history:
                risk_score += 20
                reasons.append("Multiple failed logins (Brute force indicator)")
            else:
                risk_score += 10
                reasons.append("Failed login attempt")
        elif (failed_count >= 2 or "Multiple failed logins" in history) and is_foreign:
            risk_score += 20
            reasons.append("Multiple failed logins previously observed in attack session")

        # 3. New device (+15)
        known_devs = user_known_devices.get(u, set())
        if known_devs and d not in known_devs and len(known_devs) > 0:
            risk_score += 15
            reasons.append(f"Unrecognized device ({d}) for user {u}")

        # 4. Sensitive file access (+20)
        has_sensitive_file = False
        if file_accessed:
            if any(sens in file_accessed for sens in SENSITIVE_FILES):
                has_sensitive_file = True
                risk_score += 20
                reasons.append(f"Sensitive credential/system file accessed ({file_accessed})")
            elif 'admin' in file_accessed or 'secret' in file_accessed or 'dump' in file_accessed:
                has_sensitive_file = True
                risk_score += 15
                reasons.append(f"High-risk file accessed ({file_accessed})")
        elif "Sensitive file accessed" in history and is_foreign:
            risk_score += 20
            reasons.append("Sensitive file accessed in current breach session")

        # 5. Large data transfer (+15)
        has_large_transfer = False
        if ev_type in ['DATA_TRANSFER', 'UPLOAD', 'EXFILTRATION'] or act in ['UPLOAD', 'DOWNLOAD']:
            if data_size >= 500:
                has_large_transfer = True
                risk_score += 15
                reasons.append(f"Large data transfer volume detected ({data_size} units)")
            elif data_size > 100:
                has_large_transfer = True
                risk_score += 10
                reasons.append(f"Unusual data volume transfer ({data_size} units)")
        elif "Large data transfer" in history and is_foreign:
            risk_score += 15
            reasons.append("Data exfiltration previously executed in session")

        # 6. Permission change (+10)
        if ev_type in ['PERMISSION', 'PRIVILEGE', 'AUTH'] or act in ['CHANGED', 'ESCALATED', 'GRANT']:
            risk_score += 10
            reasons.append("System security permission or role modified")

        # Compounding multi-stage attack escalation bonus (+7)
        if is_foreign and len(reasons) >= 4:
            risk_score += 7
            reasons.append("Compounding multi-stage attack escalation")

        # Cap score at 100
        risk_score = min(risk_score, 100)
        severity = calculate_severity(risk_score)
        is_anomaly = risk_score >= 20 or len(reasons) > 0

        # Update session threat history
        if "Unusual External IP detected" in reasons and "Unusual External IP" not in history:
            history.append("Unusual External IP")
        if "Multiple failed logins" in " ".join(reasons) and "Multiple failed logins" not in history:
            history.append("Multiple failed logins")
        if has_sensitive_file and "Sensitive file accessed" not in history:
            history.append("Sensitive file accessed")
        if has_large_transfer and "Large data transfer" not in history:
            history.append("Large data transfer")

        # Update failed count state
        if ev_type == 'LOGIN':
            if act == 'FAILED':
                user_failed_counters[u] = failed_count + 1
            elif act == 'SUCCESS':
                # Preserve brute force history for the session
                user_failed_counters[u] = 0

        # Build enriched event
        enriched_event = dict(event)
        enriched_event['risk_score'] = risk_score
        enriched_event['severity'] = severity
        enriched_event['is_anomaly'] = is_anomaly
        enriched_event['reason'] = "; ".join(reasons) if reasons else "Normal routine activity"

        analyzed_events.append(enriched_event)

    return analyzed_events


def compute_ml_isolation_forest(events: List[Dict[str, Any]]) -> List[float]:
    """
    Optional Scikit-Learn Isolation Forest implementation for ML anomaly detection.
    Converts event features (data_size, action type, ip type) to numerical vectors and scores outliers.
    """
    if not SKLEARN_AVAILABLE or len(events) < 3:
        # Return fallback zero anomaly scores if dataset is too small
        return [0.0] * len(events)
        
    try:
        # Build numerical feature matrix: [data_size, is_foreign_ip, is_failed, is_sensitive_file]
        features = []
        for ev in events:
            ds = float(ev.get('data_size', 0) or 0)
            foreign_ip = 1.0 if is_unusual_ip(ev.get('ip', '')) else 0.0
            is_failed = 1.0 if str(ev.get('action', '')).upper() == 'FAILED' else 0.0
            file_name = str(ev.get('file', '')).lower()
            is_sens = 1.0 if any(s in file_name for s in SENSITIVE_FILES) else 0.0
            
            features.append([ds, foreign_ip, is_failed, is_sens])
            
        X = np.array(features)
        
        # Train Isolation Forest
        clf = IsolationForest(contamination=0.3, random_state=42)
        clf.fit(X)
        
        # decision_function gives anomaly score: lower values = more anomalous
        scores = clf.decision_function(X)
        
        # Normalize to 0.0 to 1.0 anomaly index
        min_s, max_s = scores.min(), scores.max()
        if max_s > min_s:
            normalized_scores = (scores - min_s) / (max_s - min_s)
            # Invert so 1.0 means highest anomaly
            ml_anomaly_scores = [round(float(1.0 - s), 2) for s in normalized_scores]
        else:
            ml_anomaly_scores = [0.5] * len(events)
            
        return ml_anomaly_scores
    except Exception:
        return [0.0] * len(events)
