"""
CyberTrace Incident Report Generator & ReportLab PDF Exporter
-------------------------------------------------------------
Builds professional digital forensics incident reports and exports downloadable PDFs.
"""

import os
from typing import Dict, Any, Optional
import backend.database as db
from backend.timeline import generate_forensic_timeline
from backend.correlation import correlate_events_into_incidents

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

import tempfile

BASE_REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "generated_reports")
try:
    os.makedirs(BASE_REPORTS_DIR, exist_ok=True)
    REPORTS_DIR = BASE_REPORTS_DIR
except Exception:
    REPORTS_DIR = tempfile.gettempdir()


def generate_incident_report(incident_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Synthesizes current database logs into a complete investigation report structure.
    """
    events = db.get_events()
    incidents = db.get_incidents()
    
    if not incidents and events:
        incidents = correlate_events_into_incidents(events)

    target_incident = None
    if incidents:
        if incident_id:
            target_incident = next((i for i in incidents if i.get('incident_id') == incident_id), incidents[0])
        else:
            target_incident = incidents[0]

    timeline_data = generate_forensic_timeline(events)
    steps = timeline_data.get('steps', [])
    first_suspicious_idx = timeline_data.get('first_suspicious_index', 0)
    first_suspicious = steps[first_suspicious_idx] if steps and first_suspicious_idx < len(steps) else None

    suspicious_events = [e for e in events if e.get('is_anomaly') or int(e.get('risk_score', 0) or 0) > 30]
    
    inc_id = target_incident.get('incident_id', 'INC-001') if target_incident else 'INC-001'
    max_risk = target_incident.get('risk_score', 0) if target_incident else (max([int(e.get('risk_score', 0) or 0) for e in events]) if events else 0)
    severity = target_incident.get('severity', 'LOW') if target_incident else 'LOW'
    
    users = list({str(e.get('user', '')) for e in events if e.get('user')})
    devices = list({str(e.get('device', '')) for e in events if e.get('device')})
    ips = list({str(e.get('ip', '')) for e in events if e.get('ip')})
    files = list({str(e.get('file', '')) for e in events if e.get('file')})
    
    start_time = steps[0].get('timestamp', '') if steps else 'N/A'
    end_time = steps[-1].get('timestamp', '') if steps else 'N/A'

    ai_explanation = (
        f"Forensic timeline reconstruction identifies an attack chain initiated at {first_suspicious.get('timestamp') if first_suspicious else start_time}. "
        f"Anomalous access from IP {first_suspicious.get('ip') if first_suspicious else 'N/A'} was followed by privilege exploitation and sensitive data access. "
        f"The incident reached a critical risk peak of {max_risk}/100. Recommended immediate containment: block suspicious source IPs and rotate credentials for affected accounts."
    )

    report_payload = {
        "incident_id": inc_id,
        "title": f"CYBERTRACE DIGITAL FORENSICS INCIDENT REPORT - {inc_id}",
        "severity": severity,
        "risk_score": max_risk,
        "start_time": start_time,
        "end_time": end_time,
        "users": users,
        "devices": devices,
        "ips": ips,
        "files": files,
        "total_events": len(events),
        "suspicious_events_count": len(suspicious_events),
        "first_suspicious_event": first_suspicious,
        "summary": target_incident.get('summary', 'Digital forensic log analysis completed.') if target_incident else 'Digital forensic log analysis completed.',
        "timeline": steps,
        "ai_explanation": ai_explanation,
        "remediation_steps": [
            "Immediately isolate affected host device(s).",
            "Block identified foreign IP address(es) on firewall / perimeter WAF.",
            "Revoke and rotate credentials for compromised user account(s).",
            "Audit permissions table for unauthorized role modifications.",
            "Validate integrity of targeted files."
        ]
    }

    # Store in database
    db.save_report(report_payload)
    
    return report_payload


def export_report_pdf(incident_id: Optional[str] = None) -> str:
    """
    Uses Python ReportLab to create a formatted PDF incident report.
    Returns the absolute path to the generated PDF.
    """
    report = generate_incident_report(incident_id)
    pdf_filename = f"cybertrace_report_{report['incident_id']}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0ea5e9'),
        alignment=TA_CENTER,
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor('#64748b'),
        alignment=TA_CENTER,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=6
    )

    story = []

    # 1. Header
    story.append(Paragraph("CYBERTRACE DIGITAL FORENSICS TIME MACHINE", title_style))
    story.append(Paragraph(f"Official Incident Investigation Report | Incident ID: <b>{report['incident_id']}</b>", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0ea5e9'), spaceAfter=15))

    # 2. Executive Overview Table
    sev_color = colors.HexColor('#ef4444') if report['severity'] == 'CRITICAL' else colors.HexColor('#f59e0b')
    
    overview_data = [
        [
            Paragraph("<b>Incident ID:</b>", body_style), Paragraph(str(report['incident_id']), body_style),
            Paragraph("<b>Risk Score:</b>", body_style), Paragraph(f"<font color='{sev_color}'><b>{report['risk_score']}/100</b></font>", body_style)
        ],
        [
            Paragraph("<b>Severity:</b>", body_style), Paragraph(f"<b>{report['severity']}</b>", body_style),
            Paragraph("<b>Time Window:</b>", body_style), Paragraph(f"{report['start_time']} - {report['end_time']}", body_style)
        ],
        [
            Paragraph("<b>Target Users:</b>", body_style), Paragraph(", ".join(report['users']) or 'None', body_style),
            Paragraph("<b>Devices:</b>", body_style), Paragraph(", ".join(report['devices']) or 'None', body_style)
        ],
        [
            Paragraph("<b>Involved IPs:</b>", body_style), Paragraph(", ".join(report['ips']) or 'None', body_style),
            Paragraph("<b>Accessed Files:</b>", body_style), Paragraph(", ".join(report['files']) or 'None', body_style)
        ]
    ]

    overview_table = Table(overview_data, colWidths=[90, 180, 90, 180])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 10))

    # 3. First Suspicious Event Callout
    story.append(Paragraph("First Suspicious Event Details", heading_style))
    fse = report.get('first_suspicious_event')
    if fse:
        fse_text = (
            f"<b>Timestamp:</b> {fse.get('timestamp')} | <b>User:</b> {fse.get('user')} | <b>IP:</b> {fse.get('ip')} | "
            f"<b>Action:</b> {fse.get('action')} | <b>Risk Score:</b> {fse.get('risk_score')}<br/>"
            f"<b>Reason:</b> {fse.get('reason')}"
        )
    else:
        fse_text = "No anomalous indicators identified in analyzed logs."
    story.append(Paragraph(fse_text, body_style))
    story.append(Spacer(1, 10))

    # 4. Forensic Timeline Table
    story.append(Paragraph("Forensic Incident Timeline Reconstruction", heading_style))
    
    table_rows = [
        [
            Paragraph("<b>Time</b>", body_style),
            Paragraph("<b>User</b>", body_style),
            Paragraph("<b>IP</b>", body_style),
            Paragraph("<b>Action</b>", body_style),
            Paragraph("<b>Risk</b>", body_style),
            Paragraph("<b>Forensic Reason</b>", body_style)
        ]
    ]

    for step in report['timeline']:
        r_score = step.get('risk_score', 0)
        r_color = '#ef4444' if r_score >= 80 else ('#f59e0b' if r_score >= 31 else '#10b981')
        table_rows.append([
            Paragraph(str(step.get('timestamp')), body_style),
            Paragraph(str(step.get('user')), body_style),
            Paragraph(str(step.get('ip')), body_style),
            Paragraph(f"{step.get('event_type')}<br/>{step.get('action')}", body_style),
            Paragraph(f"<font color='{r_color}'><b>{r_score}</b></font>", body_style),
            Paragraph(str(step.get('reason'))[:100], body_style)
        ])

    timeline_table = Table(table_rows, colWidths=[45, 60, 80, 80, 40, 235])
    timeline_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e0f2fe')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 12))

    # 5. AI Investigation Explanation & Remediation
    story.append(Paragraph("AI Digital Forensics Assessment", heading_style))
    story.append(Paragraph(report['ai_explanation'], body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Recommended Incident Remediation Actions", heading_style))
    for r in report['remediation_steps']:
        story.append(Paragraph(f"• {r}", body_style))

    # Build PDF document
    doc.build(story)
    
    return pdf_path
