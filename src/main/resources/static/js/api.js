/**
 * CyberTrace API Client
 * Facilitates REST communication between frontend and Spring Boot backend.
 */

const API_BASE = "";

async function analyzeCsvFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE}/api/events/analyze`, {
    method: "POST",
    body: formData
  });

  if (!response.ok) {
    const errJson = await response.json().catch(() => ({}));
    throw new Error(errJson.message || "Failed to analyze CSV log file.");
  }

  return await response.json();
}

async function analyzeCsvText(csvText) {
  const response = await fetch(`${API_BASE}/api/events/analyze-text`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: csvText
  });

  if (!response.ok) {
    const errJson = await response.json().catch(() => ({}));
    throw new Error(errJson.message || "Failed to analyze CSV content.");
  }

  return await response.json();
}

async function queryInvestigatorApi(question, events, evidence, incidents) {
  const payload = {
    question: question,
    events: events || getEvents(),
    evidence: evidence || getEvidence(),
    incidents: incidents || getIncidents()
  };

  const response = await fetch(`${API_BASE}/api/investigator/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error("Failed to query AI investigator reasoning engine.");
  }

  return await response.json();
}

async function downloadPdfReportApi(incidents, events, timeline, evidence) {
  const payload = {
    incidents: incidents || getIncidents(),
    events: events || getEvents(),
    timeline: timeline || getTimeline(),
    evidence: evidence || getEvidence()
  };

  const response = await fetch(`${API_BASE}/api/report/pdf`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error("Failed to compile incident PDF report.");
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const incId = (payload.incidents && payload.incidents[0]) ? payload.incidents[0].incidentId : "INC-001";
  a.download = `CyberTrace_Report_${incId}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}
