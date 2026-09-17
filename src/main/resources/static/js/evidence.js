/**
 * CyberTrace Evidence Graph Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  loadEvidenceData();
  window.addEventListener("cybertrace_storage_update", loadEvidenceData);
});

function loadEvidenceData() {
  const evidence = getEvidence();
  const allEvents = getEvents();

  const emptyStateEl = document.getElementById("evidence-empty-state");
  const contentEl = document.getElementById("evidence-content");

  if (!allEvents || allEvents.length === 0 || !evidence) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (contentEl) contentEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (contentEl) contentEl.classList.remove("d-none");

  // Render nodes
  setText("node-user", evidence.user || "N/A");
  setText("node-device", evidence.device || "N/A");
  setText("node-ip", evidence.ip || "N/A");
  setText("node-file", evidence.file || "None");
  setText("node-transfer", evidence.dataTransfer || "0 MB");

  // Highlight suspicious nodes
  const nodes = evidence.suspiciousNodes || [];
  highlightIfSuspicious("card-user", nodes.some(n => n.startsWith("USER:")));
  highlightIfSuspicious("card-device", nodes.some(n => n.startsWith("DEVICE:")));
  highlightIfSuspicious("card-ip", nodes.some(n => n.startsWith("IP:")));
  highlightIfSuspicious("card-file", nodes.some(n => n.startsWith("FILE:")));
  highlightIfSuspicious("card-transfer", nodes.some(n => n.startsWith("TRANSFER:")));
}

function setText(elementId, text) {
  const el = document.getElementById(elementId);
  if (el) el.textContent = text;
}

function highlightIfSuspicious(elementId, isSuspicious) {
  const el = document.getElementById(elementId);
  if (!el) return;

  if (isSuspicious) {
    el.classList.add("suspicious");
    el.style.borderColor = "rgba(239, 68, 68, 0.7)";
    el.style.backgroundColor = "rgba(239, 68, 68, 0.08)";
  } else {
    el.classList.remove("suspicious");
    el.style.borderColor = "var(--cyber-border)";
    el.style.backgroundColor = "rgba(15, 23, 42, 0.85)";
  }
}
