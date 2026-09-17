/**
 * CyberTrace Anomalies Page Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  loadAnomaliesData();
  window.addEventListener("cybertrace_storage_update", loadAnomaliesData);
});

function loadAnomaliesData() {
  const anomalies = getAnomalies();
  const allEvents = getEvents();

  const emptyStateEl = document.getElementById("anomalies-empty-state");
  const contentEl = document.getElementById("anomalies-content");
  const noThreatsAlert = document.getElementById("no-threats-alert");

  if (!allEvents || allEvents.length === 0) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (contentEl) contentEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (contentEl) contentEl.classList.remove("d-none");

  const tbody = document.getElementById("anomalies-table-body");
  const badgeEl = document.getElementById("anomalies-count-badge");

  if (badgeEl) {
    badgeEl.textContent = `${anomalies.length} Flagged Anomalies`;
  }

  if (!anomalies || anomalies.length === 0) {
    if (noThreatsAlert) noThreatsAlert.classList.remove("d-none");
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-slate-400">All events comply with normal baseline. No anomalies detected.</td></tr>`;
    return;
  }

  if (noThreatsAlert) noThreatsAlert.classList.add("d-none");

  if (tbody) {
    tbody.innerHTML = anomalies.map(a => `
      <tr>
        <td class="font-mono text-slate-300 text-xs">${a.timestamp}</td>
        <td class="text-white fw-bold">${a.user}</td>
        <td class="font-mono text-cyan text-xs">${a.ip}</td>
        <td class="text-warning fw-semibold text-xs">${a.action}</td>
        <td class="font-mono text-danger fw-bold text-xs">${a.riskScore}/100</td>
        <td>${getSeverityBadgeHtml(a.severity)}</td>
        <td class="text-slate-300 small">${a.reason}</td>
      </tr>
    `).join("");
  }
}
