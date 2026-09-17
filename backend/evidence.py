"""
CyberTrace Evidence Relationship Module
----------------------------------------
Builds entity relationship graphs and forensic evidence links (User -> Device -> IP -> File -> Action).
"""

from typing import List, Dict, Any
import backend.database as db


def extract_evidence_from_events(incident_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Extracts structured evidence tuples for database persistence.
    """
    evidence_list = []
    seen_links = set()

    for ev in events:
        user = str(ev.get('user', '')).strip()
        device = str(ev.get('device', '')).strip()
        ip = str(ev.get('ip', '')).strip()
        file_name = str(ev.get('file', '')).strip()
        event_type = str(ev.get('event_type', '')).strip()
        action = str(ev.get('action', '')).strip()
        data_size = ev.get('data_size', 0)

        # 1. User -> Device
        if user and device:
            link_key = (incident_id, 'USER', user, device, 'OPERATED_ON')
            if link_key not in seen_links:
                seen_links.add(link_key)
                evidence_list.append({
                    "incident_id": incident_id,
                    "entity_type": "USER",
                    "entity_value": user,
                    "related_entity": device,
                    "relationship": "OPERATED_DEVICE"
                })

        # 2. User -> IP
        if user and ip:
            link_key = (incident_id, 'USER', user, ip, 'CONNECTED_FROM')
            if link_key not in seen_links:
                seen_links.add(link_key)
                evidence_list.append({
                    "incident_id": incident_id,
                    "entity_type": "USER",
                    "entity_value": user,
                    "related_entity": ip,
                    "relationship": "CONNECTED_FROM"
                })

        # 3. IP / Device -> File
        if file_name and (ip or device):
            origin = ip if ip else device
            link_key = (incident_id, 'IP', origin, file_name, 'ACCESSED_FILE')
            if link_key not in seen_links:
                seen_links.add(link_key)
                evidence_list.append({
                    "incident_id": incident_id,
                    "entity_type": "FILE",
                    "entity_value": file_name,
                    "related_entity": origin,
                    "relationship": f"{action}_FILE"
                })

        # 4. Data Transfer / Exfiltration
        if data_size and data_size > 0:
            transfer_name = f"Transfer ({data_size} KB/MB)"
            link_key = (incident_id, 'TRANSFER', transfer_name, ip or user, 'EXFILTRATED_TO')
            if link_key not in seen_links:
                seen_links.add(link_key)
                evidence_list.append({
                    "incident_id": incident_id,
                    "entity_type": "TRANSFER",
                    "entity_value": transfer_name,
                    "related_entity": ip or user,
                    "relationship": "EXFILTRATED_PAYLOAD"
                })

    return evidence_list


def get_evidence_graph() -> Dict[str, Any]:
    """
    Computes visual graph nodes and relationships for the frontend evidence explorer.
    Includes first seen, last seen, risk level, and detailed event connections.
    """
    events = db.get_events()
    if not events:
        return {"nodes": [], "links": [], "entities": {}}

    nodes = {}
    links = []
    seen_links = set()

    def touch_node(node_id: str, label: str, node_type: str, event_data: Dict[str, Any]):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "first_seen": event_data.get('timestamp', ''),
                "last_seen": event_data.get('timestamp', ''),
                "event_count": 0,
                "max_risk": int(event_data.get('risk_score', 0) or 0),
                "severity": event_data.get('severity', 'LOW'),
                "related_events": []
            }
        
        n = nodes[node_id]
        n["event_count"] += 1
        n["last_seen"] = event_data.get('timestamp', '')
        current_risk = int(event_data.get('risk_score', 0) or 0)
        if current_risk > n["max_risk"]:
            n["max_risk"] = current_risk
            n["severity"] = event_data.get('severity', 'LOW')
        n["related_events"].append(event_data)

    for ev in events:
        user = str(ev.get('user', '')).strip()
        device = str(ev.get('device', '')).strip()
        ip = str(ev.get('ip', '')).strip()
        file_name = str(ev.get('file', '')).strip()
        data_size = ev.get('data_size', 0)
        action = str(ev.get('action', '')).strip()

        # Nodes
        if user:
            user_id = f"user_{user}"
            touch_node(user_id, user, "USER", ev)

        if device:
            dev_id = f"device_{device}"
            touch_node(dev_id, device, "DEVICE", ev)

        if ip:
            ip_id = f"ip_{ip}"
            touch_node(ip_id, ip, "IP", ev)

        if file_name:
            file_id = f"file_{file_name}"
            touch_node(file_id, file_name, "FILE", ev)

        # Edges / Links
        if user and device:
            edge = (f"user_{user}", f"device_{device}", "Uses Device")
            if edge not in seen_links:
                seen_links.add(edge)
                links.append({"source": edge[0], "target": edge[1], "label": edge[2]})

        if device and ip:
            edge = (f"device_{device}", f"ip_{ip}", "Network Source")
            if edge not in seen_links:
                seen_links.add(edge)
                links.append({"source": edge[0], "target": edge[1], "label": edge[2]})

        if ip and file_name:
            edge = (f"ip_{ip}", f"file_{file_name}", f"{action} Action")
            if edge not in seen_links:
                seen_links.add(edge)
                links.append({"source": edge[0], "target": edge[1], "label": edge[2]})

        if data_size and data_size > 0:
            transfer_id = f"transfer_{data_size}KB"
            touch_node(transfer_id, f"Exfiltration ({data_size} KB)", "DATA_TRANSFER", ev)
            if file_name:
                edge = (f"file_{file_name}", transfer_id, "Payload")
            else:
                edge = (f"ip_{ip}", transfer_id, "Exfiltrated")
            if edge not in seen_links:
                seen_links.add(edge)
                links.append({"source": edge[0], "target": edge[1], "label": edge[2]})

    return {
        "nodes": list(nodes.values()),
        "links": links,
        "entities": nodes
    }
