/**
 * CyberTrace LocalStorage Persistence Utility
 * Pure browser-side storage with zero external database dependencies.
 */

const STORAGE_KEYS = {
  EVENTS: "cybertrace_events",
  ANOMALIES: "cybertrace_anomalies",
  INCIDENTS: "cybertrace_incidents",
  EVIDENCE: "cybertrace_evidence",
  TIMELINE: "cybertrace_timeline",
  INVESTIGATIONS: "cybertrace_investigations",
  SETTINGS: "cybertrace_settings"
};

// --- EVENTS ---
function saveEvents(events) {
  try {
    localStorage.setItem(STORAGE_KEYS.EVENTS, JSON.stringify(events || []));
    window.dispatchEvent(new Event("cybertrace_storage_update"));
  } catch (e) {
    console.error("Error saving events to localStorage:", e);
  }
}

function getEvents() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.EVENTS);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    console.error("Error reading events from localStorage:", e);
    return [];
  }
}

// --- ANOMALIES ---
function saveAnomalies(anomalies) {
  try {
    localStorage.setItem(STORAGE_KEYS.ANOMALIES, JSON.stringify(anomalies || []));
  } catch (e) {
    console.error("Error saving anomalies to localStorage:", e);
  }
}

function getAnomalies() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.ANOMALIES);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    console.error("Error reading anomalies from localStorage:", e);
    return [];
  }
}

// --- INCIDENTS ---
function saveIncidents(incidents) {
  try {
    localStorage.setItem(STORAGE_KEYS.INCIDENTS, JSON.stringify(incidents || []));
  } catch (e) {
    console.error("Error saving incidents to localStorage:", e);
  }
}

function getIncidents() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.INCIDENTS);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    console.error("Error reading incidents from localStorage:", e);
    return [];
  }
}

// --- EVIDENCE ---
function saveEvidence(evidence) {
  try {
    localStorage.setItem(STORAGE_KEYS.EVIDENCE, JSON.stringify(evidence || null));
  } catch (e) {
    console.error("Error saving evidence to localStorage:", e);
  }
}

function getEvidence() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.EVIDENCE);
    return data ? JSON.parse(data) : null;
  } catch (e) {
    console.error("Error reading evidence from localStorage:", e);
    return null;
  }
}

// --- TIMELINE ---
function saveTimeline(timeline) {
  try {
    localStorage.setItem(STORAGE_KEYS.TIMELINE, JSON.stringify(timeline || []));
  } catch (e) {
    console.error("Error saving timeline to localStorage:", e);
  }
}

function getTimeline() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.TIMELINE);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    console.error("Error reading timeline from localStorage:", e);
    return [];
  }
}

// --- INVESTIGATIONS (Q&A HISTORY) ---
function saveInvestigations(history) {
  try {
    localStorage.setItem(STORAGE_KEYS.INVESTIGATIONS, JSON.stringify(history || []));
  } catch (e) {
    console.error("Error saving investigation history to localStorage:", e);
  }
}

function getInvestigations() {
  try {
    const data = localStorage.getItem(STORAGE_KEYS.INVESTIGATIONS);
    return data ? JSON.parse(data) : [];
  } catch (e) {
    console.error("Error reading investigation history from localStorage:", e);
    return [];
  }
}

function addInvestigationItem(question, answer) {
  const history = getInvestigations();
  history.push({
    question,
    answer,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  });
  saveInvestigations(history);
  return history;
}

// --- CLEAR DATA ---
function clearCyberTraceData() {
  try {
    localStorage.removeItem(STORAGE_KEYS.EVENTS);
    localStorage.removeItem(STORAGE_KEYS.ANOMALIES);
    localStorage.removeItem(STORAGE_KEYS.INCIDENTS);
    localStorage.removeItem(STORAGE_KEYS.EVIDENCE);
    localStorage.removeItem(STORAGE_KEYS.TIMELINE);
    localStorage.removeItem(STORAGE_KEYS.INVESTIGATIONS);
    localStorage.removeItem(STORAGE_KEYS.SETTINGS);
    window.dispatchEvent(new Event("cybertrace_storage_update"));
    return true;
  } catch (e) {
    console.error("Error clearing CyberTrace localStorage:", e);
    return false;
  }
}

// Severity badge generator helper
function getSeverityBadgeHtml(severity) {
  const sev = (severity || "NORMAL").toUpperCase();
  let badgeClass = "badge-normal";
  let icon = "bi-shield-check";

  if (sev === "CRITICAL") {
    badgeClass = "badge-critical";
    icon = "bi-radioactive";
  } else if (sev === "HIGH") {
    badgeClass = "badge-high";
    icon = "bi-exclamation-triangle-fill";
  } else if (sev === "MEDIUM") {
    badgeClass = "badge-medium";
    icon = "bi-exclamation-circle";
  } else if (sev === "LOW") {
    badgeClass = "badge-low";
    icon = "bi-info-circle";
  }

  return `<span class="cyber-badge ${badgeClass}"><i class="bi ${icon}"></i> ${sev}</span>`;
}
