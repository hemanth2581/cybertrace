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
    localStorage.removeItem("cybertrace_initialized");
    window.dispatchEvent(new Event("cybertrace_storage_update"));
    return true;
  } catch (e) {
    console.error("Error clearing CyberTrace localStorage:", e);
    return false;
  }
}

// --- DEFAULT SAMPLE DATA SEEDER ---
const DEFAULT_SAMPLE_EVENTS = [
  { id: "EVT-001", timestamp: "2026-09-17 10:01:00", user: "Rahul", device: "DEV01", ip: "192.168.1.10", action: "LOGIN", file: "", dataSize: 0, riskScore: 0, severity: "NORMAL", reason: "Routine internal enterprise baseline activity" },
  { id: "EVT-002", timestamp: "2026-09-17 10:03:00", user: "Rahul", device: "DEV01", ip: "185.23.45.10", action: "FAILED_LOGIN", file: "", dataSize: 0, riskScore: 40, severity: "LOW", reason: "Authentication failure / failed login detected (+20); External public IP origin: 185.23.45.10 (+20)" },
  { id: "EVT-003", timestamp: "2026-09-17 10:05:00", user: "Rahul", device: "DEV01", ip: "185.23.45.10", action: "FAILED_LOGIN", file: "", dataSize: 0, riskScore: 40, severity: "LOW", reason: "Authentication failure / failed login detected (+20); External public IP origin: 185.23.45.10 (+20)" },
  { id: "EVT-004", timestamp: "2026-09-17 10:08:00", user: "Rahul", device: "DEV01", ip: "185.23.45.10", action: "FILE_ACCESS", file: "passwords.txt", dataSize: 0, riskScore: 40, severity: "LOW", reason: "External public IP origin: 185.23.45.10 (+20); Sensitive credential/database file access: passwords.txt (+20)" },
  { id: "EVT-005", timestamp: "2026-09-17 10:12:00", user: "Rahul", device: "DEV01", ip: "185.23.45.10", action: "DATA_TRANSFER", file: "", dataSize: 850, riskScore: 35, severity: "LOW", reason: "External public IP origin: 185.23.45.10 (+20); Large outbound data transfer (850 MB) exceeding 500MB threshold (+15)" },
  { id: "EVT-006", timestamp: "2026-09-17 10:15:00", user: "Rahul", device: "DEV01", ip: "185.23.45.10", action: "PRIVILEGE_ESCALATION", file: "", dataSize: 0, riskScore: 30, severity: "LOW", reason: "External public IP origin: 185.23.45.10 (+20); Privilege escalation attempt detected (+10)" }
];

const DEFAULT_SAMPLE_ANOMALIES = [
  { id: "ANOM-001", eventId: "EVT-002", timestamp: "2026-09-17 10:03:00", user: "Rahul", ip: "185.23.45.10", action: "FAILED_LOGIN", riskScore: 40, severity: "LOW", reason: "Authentication failure / failed login detected (+20); External public IP origin: 185.23.45.10 (+20)", detectedAt: "2026-09-17T10:03:00Z" },
  { id: "ANOM-002", eventId: "EVT-003", timestamp: "2026-09-17 10:05:00", user: "Rahul", ip: "185.23.45.10", action: "FAILED_LOGIN", riskScore: 40, severity: "LOW", reason: "Authentication failure / failed login detected (+20); External public IP origin: 185.23.45.10 (+20)", detectedAt: "2026-09-17T10:05:00Z" },
  { id: "ANOM-003", eventId: "EVT-004", timestamp: "2026-09-17 10:08:00", user: "Rahul", ip: "185.23.45.10", action: "FILE_ACCESS", riskScore: 40, severity: "LOW", reason: "External public IP origin: 185.23.45.10 (+20); Sensitive credential/database file access: passwords.txt (+20)", detectedAt: "2026-09-17T10:08:00Z" },
  { id: "ANOM-004", eventId: "EVT-005", timestamp: "2026-09-17 10:12:00", user: "Rahul", ip: "185.23.45.10", action: "DATA_TRANSFER", riskScore: 35, severity: "LOW", reason: "External public IP origin: 185.23.45.10 (+20); Large outbound data transfer (850 MB) exceeding 500MB threshold (+15)", detectedAt: "2026-09-17T10:12:00Z" },
  { id: "ANOM-005", eventId: "EVT-006", timestamp: "2026-09-17 10:15:00", user: "Rahul", ip: "185.23.45.10", action: "PRIVILEGE_ESCALATION", riskScore: 30, severity: "LOW", reason: "External public IP origin: 185.23.45.10 (+20); Privilege escalation attempt detected (+10)", detectedAt: "2026-09-17T10:15:00Z" }
];

const DEFAULT_SAMPLE_INCIDENTS = [
  {
    incidentId: "INC-001",
    title: "Account Compromise Detected",
    severity: "HIGH",
    firstSuspiciousEvent: "FAILED_LOGIN from 185.23.45.10 at 2026-09-17 10:03:00",
    affectedUser: "Rahul",
    sourceIP: "185.23.45.10",
    suspiciousEventCount: 5,
    status: "OPEN",
    createdAt: "2026-09-17 10:03:00",
    recommendations: [
      "Immediately revoke active session tokens and reset password for user: Rahul",
      "Enforce firewall block rule on origin source IP: 185.23.45.10",
      "Quarantine host workstation (DEV01) for endpoint forensic triage",
      "Initiate data loss prevention (DLP) audit on compromised files & databases"
    ]
  }
];

const DEFAULT_SAMPLE_TIMELINE = [
  { timestamp: "2026-09-17 10:01:00", eventType: "LOGIN", description: "User Rahul logged in from 192.168.1.10", user: "Rahul", device: "DEV01", ip: "192.168.1.10", file: "", riskScore: 0, severity: "NORMAL", firstSuspicious: false },
  { timestamp: "2026-09-17 10:03:00", eventType: "FAILED_LOGIN", description: "Authentication failure for user Rahul from IP 185.23.45.10", user: "Rahul", device: "DEV01", ip: "185.23.45.10", file: "", riskScore: 40, severity: "LOW", firstSuspicious: true },
  { timestamp: "2026-09-17 10:05:00", eventType: "FAILED_LOGIN", description: "Authentication failure for user Rahul from IP 185.23.45.10", user: "Rahul", device: "DEV01", ip: "185.23.45.10", file: "", riskScore: 40, severity: "LOW", firstSuspicious: false },
  { timestamp: "2026-09-17 10:08:00", eventType: "FILE_ACCESS", description: "File access: passwords.txt by Rahul on DEV01", user: "Rahul", device: "DEV01", ip: "185.23.45.10", file: "passwords.txt", riskScore: 40, severity: "LOW", firstSuspicious: false },
  { timestamp: "2026-09-17 10:12:00", eventType: "DATA_TRANSFER", description: "Data transfer of 850 MB outbound to 185.23.45.10", user: "Rahul", device: "DEV01", ip: "185.23.45.10", file: "", riskScore: 35, severity: "LOW", firstSuspicious: false },
  { timestamp: "2026-09-17 10:15:00", eventType: "PRIVILEGE_ESCALATION", description: "Privilege escalation executed on DEV01", user: "Rahul", device: "DEV01", ip: "185.23.45.10", file: "", riskScore: 30, severity: "LOW", firstSuspicious: false }
];

const DEFAULT_SAMPLE_EVIDENCE = {
  user: "Rahul",
  device: "DEV01",
  ip: "185.23.45.10",
  file: "passwords.txt",
  dataTransfer: "850 MB",
  suspiciousNodes: ["USER:Rahul", "DEVICE:DEV01", "IP:185.23.45.10", "FILE:passwords.txt", "TRANSFER:850 MB"]
};

const DEFAULT_SAMPLE_INVESTIGATIONS = [
  {
    question: "What happened?",
    answer: "User Rahul was targeted in an Account Compromise security incident. The attack involved multiple failed login attempts from external IP 185.23.45.10, sensitive file access to 'passwords.txt', an 850 MB outbound data transfer, and unauthorized privilege escalation.",
    timestamp: "10:16:00"
  },
  {
    question: "What was the first suspicious event?",
    answer: "The first suspicious event was 'FAILED_LOGIN' detected at 2026-09-17 10:03:00 originating from external IP 185.23.45.10 (Risk Score: 40/100).",
    timestamp: "10:16:30"
  }
];

function seedDefaultSampleData() {
  saveEvents(DEFAULT_SAMPLE_EVENTS);
  saveAnomalies(DEFAULT_SAMPLE_ANOMALIES);
  saveIncidents(DEFAULT_SAMPLE_INCIDENTS);
  saveTimeline(DEFAULT_SAMPLE_TIMELINE);
  saveEvidence(DEFAULT_SAMPLE_EVIDENCE);
  saveInvestigations(DEFAULT_SAMPLE_INVESTIGATIONS);
}

// Auto-seed sample data on first visit if storage is empty
(function initStorage() {
  if (typeof window !== "undefined" && window.localStorage) {
    const initialized = localStorage.getItem("cybertrace_initialized");
    const existingEvents = getEvents();
    if (!initialized || !existingEvents || existingEvents.length === 0) {
      seedDefaultSampleData();
      localStorage.setItem("cybertrace_initialized", "true");
    }
  }
})();

// Global DOM text helper
function setText(elementId, text) {
  const el = document.getElementById(elementId);
  if (el) {
    el.textContent = (text !== null && text !== undefined) ? text : "";
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
