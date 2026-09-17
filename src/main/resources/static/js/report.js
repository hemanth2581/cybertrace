/**
 * CyberTrace Incident Report & PDF Generation Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  loadReportData();
  setupPdfButton();
  window.addEventListener("cybertrace_storage_update", loadReportData);
});

function loadReportData() {
  const incidents = getIncidents();
  const events = getEvents();
  const timeline = getTimeline();
  const evidence = getEvidence();

  const emptyStateEl = document.getElementById("report-empty-state");
  const contentEl = document.getElementById("report-content");

  if (!events || events.length === 0) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (contentEl) contentEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (contentEl) contentEl.classList.remove("d-none");

  const inc = (incidents && incidents.length > 0) ? incidents[0] : {
    incidentId: "INC-001",
    title: "Security Telemetry Assessment",
    severity: "NORMAL",
    affectedUser: evidence?.user || "N/A",
    sourceIP: evidence?.ip || "N/A",
    suspiciousEventCount: 0,
    firstSuspiciousEvent: "None",
    status: "CLOSED",
    recommendations: ["Maintain routine monitoring baseline."]
  };

  setText("rep-id", inc.incidentId);
  setText("rep-title", inc.title);
  setText("rep-user", inc.affectedUser);
  setText("rep-ip", inc.sourceIP);
  setText("rep-susp-count", `${inc.suspiciousEventCount} Flagged Events`);
  setText("rep-first-event", inc.firstSuspiciousEvent);
  setText("rep-date", new Date().toLocaleDateString());

  const sevBadgeContainer = document.getElementById("rep-severity-badge");
  if (sevBadgeContainer) {
    sevBadgeContainer.innerHTML = getSeverityBadgeHtml(inc.severity);
  }

  // Recommendations list
  const recList = document.getElementById("rep-recommendations-list");
  if (recList) {
    recList.innerHTML = (inc.recommendations || []).map(r => `
      <li class="list-group-item bg-transparent text-slate-300 border-slate-800 py-1.5 px-0 d-flex align-items-start gap-2 small">
        <i class="bi bi-shield-check text-cyan mt-0.5"></i>
        <span>${r}</span>
      </li>
    `).join("");
  }

  // Timeline preview table
  const tlBody = document.getElementById("rep-timeline-body");
  if (tlBody && timeline) {
    tlBody.innerHTML = timeline.map(t => `
      <tr>
        <td class="font-mono text-slate-300 text-xs">${t.timestamp}</td>
        <td class="text-white fw-bold text-xs">${t.eventType}</td>
        <td class="font-mono text-cyan text-xs">${t.ip}</td>
        <td>${getSeverityBadgeHtml(t.severity)}</td>
        <td class="text-slate-400 small">${t.description}</td>
      </tr>
    `).join("");
  }
}

function setupPdfButton() {
  const btn = document.getElementById("download-pdf-btn");
  if (!btn) return;

  btn.addEventListener("click", async () => {
    try {
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>Compiling PDF in Java...`;
      await downloadPdfReportApi();
    } catch (err) {
      alert("Error generating PDF: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="bi bi-file-earmark-pdf-fill me-1"></i> Download Official PDF Report`;
    }
  });
}
