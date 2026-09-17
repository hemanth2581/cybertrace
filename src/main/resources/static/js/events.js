/**
 * CyberTrace Events Explorer Page Logic
 * Filterable, searchable data table reading directly from localStorage.
 */

let allEvents = [];

document.addEventListener("DOMContentLoaded", () => {
  loadEventsData();
  setupFilterListeners();
  window.addEventListener("cybertrace_storage_update", loadEventsData);
});

function loadEventsData() {
  allEvents = getEvents();

  const emptyStateEl = document.getElementById("events-empty-state");
  const tableContainerEl = document.getElementById("events-container");

  if (!allEvents || allEvents.length === 0) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (tableContainerEl) tableContainerEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (tableContainerEl) tableContainerEl.classList.remove("d-none");

  populateUserFilter(allEvents);
  renderEventsTable(allEvents);
  updateEventCount(allEvents.length, allEvents.length);
}

function populateUserFilter(events) {
  const userSelect = document.getElementById("user-filter");
  if (!userSelect) return;

  const users = [...new Set(events.map(e => e.user).filter(Boolean))];
  const currentVal = userSelect.value;

  userSelect.innerHTML = `<option value="">All Users (${users.length})</option>` +
    users.map(u => `<option value="${u}" ${currentVal === u ? 'selected' : ''}>${u}</option>`).join("");
}

function renderEventsTable(events) {
  const tbody = document.getElementById("events-table-body");
  if (!tbody) return;

  if (events.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="10" class="text-center text-slate-400 py-4">
          <i class="bi bi-search me-1"></i> No matching security events found for the active filter.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = events.map(e => `
    <tr>
      <td class="font-mono text-slate-300 text-xs">${e.timestamp}</td>
      <td class="text-white fw-bold">${e.user}</td>
      <td class="font-mono text-slate-300 text-xs">${e.device}</td>
      <td class="font-mono text-cyan text-xs">${e.ip}</td>
      <td class="text-info fw-semibold text-xs">${e.action}</td>
      <td class="font-mono text-slate-400 text-xs">${e.file || '<span class="text-slate-600">—</span>'}</td>
      <td class="font-mono text-slate-300 text-xs">${e.dataSize > 0 ? (e.dataSize + ' MB') : '<span class="text-slate-600">0</span>'}</td>
      <td class="font-mono text-warning fw-bold text-xs">${e.riskScore}/100</td>
      <td>${getSeverityBadgeHtml(e.severity)}</td>
      <td class="text-slate-400 small text-truncate" style="max-width: 240px;" title="${e.reason}">${e.reason}</td>
    </tr>
  `).join("");
}

function setupFilterListeners() {
  const searchInput = document.getElementById("search-input");
  const userSelect = document.getElementById("user-filter");
  const severitySelect = document.getElementById("severity-filter");
  const resetBtn = document.getElementById("reset-filters-btn");

  const filterHandler = () => {
    const q = (searchInput?.value || "").toLowerCase().trim();
    const userVal = userSelect?.value || "";
    const sevVal = severitySelect?.value || "";

    const filtered = allEvents.filter(e => {
      const matchQuery = !q ||
        (e.user && e.user.toLowerCase().includes(q)) ||
        (e.ip && e.ip.toLowerCase().includes(q)) ||
        (e.action && e.action.toLowerCase().includes(q)) ||
        (e.file && e.file.toLowerCase().includes(q)) ||
        (e.device && e.device.toLowerCase().includes(q)) ||
        (e.reason && e.reason.toLowerCase().includes(q));

      const matchUser = !userVal || e.user === userVal;
      const matchSev = !sevVal || (e.severity && e.severity.toUpperCase() === sevVal.toUpperCase());

      return matchQuery && matchUser && matchSev;
    });

    renderEventsTable(filtered);
    updateEventCount(filtered.length, allEvents.length);
  };

  if (searchInput) searchInput.addEventListener("input", filterHandler);
  if (userSelect) userSelect.addEventListener("change", filterHandler);
  if (severitySelect) severitySelect.addEventListener("change", filterHandler);

  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      if (searchInput) searchInput.value = "";
      if (userSelect) userSelect.value = "";
      if (severitySelect) severitySelect.value = "";
      filterHandler();
    });
  }
}

function updateEventCount(showing, total) {
  const countBadge = document.getElementById("event-count-badge");
  if (countBadge) {
    countBadge.textContent = showing === total ? `Showing all ${total} events` : `Showing ${showing} of ${total} events`;
  }
}
