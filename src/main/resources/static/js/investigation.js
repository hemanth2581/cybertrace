/**
 * CyberTrace Investigation Page Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  loadInvestigationData();
  window.addEventListener("cybertrace_storage_update", loadInvestigationData);
});

function loadInvestigationData() {
  const incidents = getIncidents();
  const allEvents = getEvents();

  const emptyStateEl = document.getElementById("investigation-empty-state");
  const contentEl = document.getElementById("investigation-content");
  const noIncidentsAlert = document.getElementById("no-incidents-alert");
  const incidentsList = document.getElementById("incidents-list");

  if (!allEvents || allEvents.length === 0) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (contentEl) contentEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (contentEl) contentEl.classList.remove("d-none");

  if (!incidents || incidents.length === 0) {
    if (noIncidentsAlert) noIncidentsAlert.classList.remove("d-none");
    if (incidentsList) incidentsList.innerHTML = "";
    return;
  }

  if (noIncidentsAlert) noIncidentsAlert.classList.add("d-none");

  if (incidentsList) {
    incidentsList.innerHTML = incidents.map(inc => `
      <div class="cyber-card mb-4" style="border-left: 4px solid var(--cyber-critical);">
        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 pb-3 mb-3 border-bottom" style="border-color: rgba(51, 65, 85, 0.4) !important;">
          <div class="d-flex align-items-center gap-2">
            <span class="badge bg-danger-subtle text-danger border border-danger-subtle font-mono fw-bold px-2 py-1">${inc.incidentId}</span>
            <h4 class="text-white fw-bold m-0">${inc.title}</h4>
          </div>
          ${getSeverityBadgeHtml(inc.severity)}
        </div>

        <div class="row g-3 mb-4">
          <div class="col-6 col-md-3">
            <div class="p-3 rounded bg-dark border border-slate-800">
              <span class="text-slate-500 d-block small">Target Identity</span>
              <strong class="text-white font-mono fs-6">${inc.affectedUser || "N/A"}</strong>
            </div>
          </div>
          <div class="col-6 col-md-3">
            <div class="p-3 rounded bg-dark border border-slate-800">
              <span class="text-slate-500 d-block small">Origin IP</span>
              <strong class="text-cyan font-mono fs-6">${inc.sourceIP || "N/A"}</strong>
            </div>
          </div>
          <div class="col-6 col-md-3">
            <div class="p-3 rounded bg-dark border border-slate-800">
              <span class="text-slate-500 d-block small">Flagged Vectors</span>
              <strong class="text-warning font-mono fs-6">${inc.suspiciousEventCount} Anomalies</strong>
            </div>
          </div>
          <div class="col-6 col-md-3">
            <div class="p-3 rounded bg-dark border border-slate-800">
              <span class="text-slate-500 d-block small">Case Status</span>
              <span class="badge bg-danger text-white px-2.5 py-1.5 mt-1">${inc.status}</span>
            </div>
          </div>
        </div>

        <div class="p-3 rounded bg-dark border border-slate-800 mb-4">
          <div class="d-flex align-items-center gap-2 mb-1">
            <i class="bi bi-clock-history text-danger"></i>
            <strong class="text-white small">Initial Infiltration Signature:</strong>
          </div>
          <p class="text-slate-300 font-mono small m-0">${inc.firstSuspiciousEvent || "No infiltration signature logged."}</p>
        </div>

        <div class="mb-4">
          <h6 class="text-white fw-bold d-flex align-items-center gap-2 mb-2">
            <i class="bi bi-shield-check text-cyan"></i> Recommended SOC Containment Playbook
          </h6>
          <div class="list-group list-group-flush bg-transparent">
            ${(inc.recommendations || []).map(rec => `
              <div class="list-group-item bg-transparent text-slate-300 border-slate-800 py-2 px-0 d-flex align-items-start gap-2 small">
                <i class="bi bi-check2-circle text-cyan mt-0.5"></i>
                <span>${rec}</span>
              </div>
            `).join("")}
          </div>
        </div>

        <div class="d-flex flex-wrap gap-2 justify-content-end pt-2 border-top" style="border-color: rgba(51, 65, 85, 0.4) !important;">
          <a href="timeline.html" class="btn btn-outline-info btn-sm d-flex align-items-center gap-1.5">
            <i class="bi bi-clock-history"></i> Step Attack Timeline
          </a>
          <a href="evidence.html" class="btn btn-outline-primary btn-sm d-flex align-items-center gap-1.5">
            <i class="bi bi-diagram-3"></i> View Evidence Chain
          </a>
          <a href="report.html" class="btn btn-primary btn-sm d-flex align-items-center gap-1.5">
            <i class="bi bi-file-earmark-pdf"></i> Generate PDF Case Report
          </a>
        </div>
      </div>
    `).join("");
  }
}
