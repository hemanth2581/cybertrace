"""
CyberTrace Database Module (Supabase PostgreSQL Client)
------------------------------------------------------
This file connects CyberTrace to Supabase PostgreSQL with an automatic
local in-memory fallback store.

Beginner Concepts:
- What is Supabase?
  Supabase is a cloud database powered by PostgreSQL. It allows us to store security logs and incident cases.
- What are Environment Variables?
  We store sensitive API keys in `.env` so they are never exposed in frontend JavaScript or public GitHub repos.
- Fallback In-Memory Store:
  If Supabase credentials are not entered yet, CyberTrace automatically uses a safe in-memory store
  so the prototype and Code-A-Thon demo work immediately without crashes!
"""

import os
import json
from typing import List, Dict, Any, Optional

try:
    # pyrefly: ignore [missing-import]
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(dotenv_path=None, override=False):
        """Built-in .env loader fallback if python-dotenv is not installed."""
        env_file = dotenv_path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip("'\"")
                            if override or k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass

# Initialize Supabase client state
supabase_client = None
is_supabase_connected = False
current_supabase_url = ""


def init_supabase_client(force_reload: bool = False) -> bool:
    """
    Initializes or re-checks the Supabase client connection from environment variables.
    Supports dynamic hot-reloading if the user adds or updates .env credentials.
    """
    global supabase_client, is_supabase_connected, current_supabase_url
    
    # Reload environment variables from .env
    load_dotenv(override=True)
    
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_KEY", "").strip()

    # If already connected to the same URL and not forced, keep connection
    if is_supabase_connected and supabase_client and url == current_supabase_url and not force_reload:
        return True

    if url and key and "your_supabase" not in url and len(url) > 10 and len(key) > 10:
        try:
            # pyrefly: ignore [missing-import]
            from supabase import create_client, Client
            supabase_client = create_client(url, key)
            current_supabase_url = url
            is_supabase_connected = True
            print(f"[Supabase] Connected to PostgreSQL at: {url}")
            return True
        except Exception as e:
            print(f"[Supabase Warning] Could not connect to Supabase ({e}). Using local in-memory store.")
            supabase_client = None
            is_supabase_connected = False
            return False
    else:
        # Fallback to in-memory store
        supabase_client = None
        is_supabase_connected = False
        return False


# Run initial check at import time
init_supabase_client()


# ========================================================
# IN-MEMORY DATABASE FALLBACK STORE
# ========================================================
class LocalForensicStore:
    def __init__(self):
        self.security_events: List[Dict[str, Any]] = []
        self.incidents: List[Dict[str, Any]] = []
        self.evidence: List[Dict[str, Any]] = []
        self.investigation_reports: List[Dict[str, Any]] = []
        self.next_event_id = 1
        self.next_incident_id = 1
        self.next_evidence_id = 1
        self.next_report_id = 1

    def clear(self):
        self.security_events.clear()
        self.incidents.clear()
        self.evidence.clear()
        self.investigation_reports.clear()
        self.next_event_id = 1
        self.next_incident_id = 1
        self.next_evidence_id = 1
        self.next_report_id = 1


local_db = LocalForensicStore()


# ========================================================
# DATABASE HELPER FUNCTIONS
# ========================================================

def get_connection_status() -> Dict[str, Any]:
    """
    Returns current database backend status for the UI indicator.
    Dynamically re-evaluates .env if credentials were recently added.
    """
    if not is_supabase_connected:
        init_supabase_client()

    return {
        "connected": is_supabase_connected,
        "type": "Supabase PostgreSQL" if is_supabase_connected else "Local In-Memory Store",
        "url": current_supabase_url if is_supabase_connected else "Local"
    }


def insert_events(events: List[Dict[str, Any]]) -> bool:
    """
    Inserts a batch of analyzed security events into the database.
    """
    global local_db
    if not events:
        return True

    # 1. Store in local fallback memory
    for ev in events:
        item = dict(ev)
        if 'id' not in item or not item['id']:
            item['id'] = local_db.next_event_id
            local_db.next_event_id += 1
        local_db.security_events.append(item)

    # 2. Store in Supabase PostgreSQL if active
    if is_supabase_connected and supabase_client:
        try:
            # Prepare payload matching table schema
            db_payload = []
            for ev in events:
                db_payload.append({
                    "timestamp": str(ev.get("timestamp", "")),
                    "user": str(ev.get("user", "")),
                    "device": str(ev.get("device", "")),
                    "ip": str(ev.get("ip", "")),
                    "event_type": str(ev.get("event_type", "")),
                    "action": str(ev.get("action", "")),
                    "file": str(ev.get("file", "") or ""),
                    "data_size": int(ev.get("data_size", 0) or 0),
                    "risk_score": int(ev.get("risk_score", 0) or 0),
                    "severity": str(ev.get("severity", "LOW")),
                    "reason": str(ev.get("reason", "")),
                    "is_anomaly": bool(ev.get("is_anomaly", False))
                })
            supabase_client.table("security_events").insert(db_payload).execute()
        except Exception as e:
            print(f"[Supabase Error] insert_events: {e}")
            return False

    return True


def get_events() -> List[Dict[str, Any]]:
    """
    Retrieves all stored security events.
    """
    if is_supabase_connected and supabase_client:
        try:
            response = supabase_client.table("security_events").select("*").order("id", desc=False).execute()
            if response.data:
                return response.data
        except Exception as e:
            print(f"[Supabase Error] get_events: {e}")

    # Return local storage copy
    return list(local_db.security_events)


def insert_incident(incident: Dict[str, Any]) -> bool:
    """
    Inserts or updates an incident record.
    Sanitizes payload so only columns defined in Supabase schema are sent to PostgreSQL.
    """
    global local_db
    # 1. Update local memory with full rich incident record
    existing_idx = next((i for i, inc in enumerate(local_db.incidents) if inc.get("incident_id") == incident.get("incident_id")), None)
    if existing_idx is not None:
        local_db.incidents[existing_idx] = dict(incident)
    else:
        item = dict(incident)
        item['id'] = local_db.next_incident_id
        local_db.next_incident_id += 1
        local_db.incidents.append(item)

    # 2. Update Supabase PostgreSQL with schema-safe columns
    if is_supabase_connected and supabase_client:
        try:
            db_incident = {
                "incident_id": str(incident.get("incident_id", "")),
                "title": str(incident.get("title", "")),
                "start_time": str(incident.get("start_time", "")),
                "end_time": str(incident.get("end_time", "")),
                "risk_score": int(incident.get("risk_score", 0) or 0),
                "severity": str(incident.get("severity", "LOW")),
                "summary": str(incident.get("summary", ""))
            }
            supabase_client.table("incidents").upsert(db_incident, on_conflict="incident_id").execute()
        except Exception as e:
            print(f"[Supabase Error] insert_incident: {e}")
            return False

    return True


def get_incidents() -> List[Dict[str, Any]]:
    """
    Retrieves all active incidents.
    """
    if is_supabase_connected and supabase_client:
        try:
            response = supabase_client.table("incidents").select("*").order("created_at", desc=True).execute()
            if response.data and len(response.data) > 0:
                # Merge with rich memory items if available
                db_incidents = []
                for row in response.data:
                    local_match = next((i for i in local_db.incidents if i.get("incident_id") == row.get("incident_id")), None)
                    if local_match:
                        merged = dict(local_match)
                        merged.update(row)
                        db_incidents.append(merged)
                    else:
                        db_incidents.append(row)
                return db_incidents
        except Exception as e:
            print(f"[Supabase Error] get_incidents: {e}")

    return list(local_db.incidents)


def insert_evidence_batch(evidence_list: List[Dict[str, Any]]) -> bool:
    """
    Saves evidence entity relationship links.
    """
    global local_db
    if not evidence_list:
        return True

    # 1. Update local memory
    for ev in evidence_list:
        item = dict(ev)
        item['id'] = local_db.next_evidence_id
        local_db.next_evidence_id += 1
        local_db.evidence.append(item)

    # 2. Update Supabase PostgreSQL
    if is_supabase_connected and supabase_client:
        try:
            db_payload = []
            for ev in evidence_list:
                db_payload.append({
                    "incident_id": str(ev.get("incident_id", "")),
                    "entity_type": str(ev.get("entity_type", "")),
                    "entity_value": str(ev.get("entity_value", "")),
                    "related_entity": str(ev.get("related_entity", "")),
                    "relationship": str(ev.get("relationship", ""))
                })
            supabase_client.table("evidence").insert(db_payload).execute()
        except Exception as e:
            print(f"[Supabase Error] insert_evidence: {e}")
            return False

    return True


def get_evidence(incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves evidence relationships for an incident or all items.
    """
    if is_supabase_connected and supabase_client:
        try:
            query = supabase_client.table("evidence").select("*")
            if incident_id:
                query = query.eq("incident_id", incident_id)
            response = query.execute()
            if response.data:
                return response.data
        except Exception as e:
            print(f"[Supabase Error] get_evidence: {e}")

    if incident_id:
        return [e for e in local_db.evidence if e.get("incident_id") == incident_id]
    return list(local_db.evidence)


def save_report(report_data: Dict[str, Any]) -> bool:
    """
    Stores an incident investigation report.
    Sanitizes columns for PostgreSQL schema while preserving full payload in memory.
    """
    global local_db
    # 1. Store rich report in local memory
    item = dict(report_data)
    item['id'] = local_db.next_report_id
    local_db.next_report_id += 1
    local_db.investigation_reports.append(item)

    # 2. Store in Supabase PostgreSQL
    if is_supabase_connected and supabase_client:
        try:
            db_payload = {
                "incident_id": str(report_data.get("incident_id", "INC-001")),
                "summary": str(report_data.get("summary", "")),
                "timeline": report_data.get("timeline", []),
                "evidence_summary": str(report_data.get("evidence_summary", "")),
                "ai_explanation": str(report_data.get("ai_explanation", ""))
            }
            supabase_client.table("investigation_reports").insert(db_payload).execute()
        except Exception as e:
            print(f"[Supabase Error] save_report: {e}")
            return False

    return True


def get_latest_report(incident_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves the most recent investigation report.
    """
    if is_supabase_connected and supabase_client:
        try:
            query = supabase_client.table("investigation_reports").select("*").order("created_at", desc=True).limit(1)
            if incident_id:
                query = query.eq("incident_id", incident_id)
            response = query.execute()
            if response.data and len(response.data) > 0:
                row = response.data[0]
                # Merge with rich memory structure if present
                local_match = next((r for r in local_db.investigation_reports if r.get("incident_id") == row.get("incident_id")), None)
                if local_match:
                    merged = dict(local_match)
                    merged.update(row)
                    return merged
                return row
        except Exception as e:
            print(f"[Supabase Error] get_latest_report: {e}")

    if local_db.investigation_reports:
        if incident_id:
            matching = [r for r in local_db.investigation_reports if r.get("incident_id") == incident_id]
            return matching[-1] if matching else local_db.investigation_reports[-1]
        return local_db.investigation_reports[-1]
    return None


def clear_database() -> bool:
    """
    Resets current log store when loading a new scenario or uploading a fresh CSV.
    """
    global local_db
    local_db.clear()

    if is_supabase_connected and supabase_client:
        try:
            # Delete in foreign-key cascade order
            supabase_client.table("investigation_reports").delete().neq("id", 0).execute()
            supabase_client.table("evidence").delete().neq("id", 0).execute()
            supabase_client.table("incidents").delete().neq("id", 0).execute()
            supabase_client.table("security_events").delete().neq("id", 0).execute()
        except Exception as e:
            print(f"[Supabase Error] clear_database: {e}")
            return False

    return True
