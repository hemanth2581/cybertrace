/**
 * CyberTrace Security Command Center Dashboard
 * Renders live KPI metrics, active incident dossiers, severity distribution, and recent anomalies.
 */

document.addEventListener("DOMContentLoaded", () => {
  renderDashboard();

  window.addEventListener("cybertrace_storage_update", () => {
    renderDashboard();
  });

  const emptyDemoBtn = document.getElementById("empty-load-demo-btn");
  if (emptyDemoBtn) {
    emptyDemoBtn.addEventListener("click", async () => {
      try {
        const response = await fetch("demo/account_compromise.csv");
        if (response.ok) {
          const text = await response.text();
          const result = await analyzeCsvText(text);
          if (result && result.events) {
            saveEvents(result.events);
            saveAnomalies(result.anomalies || []);
            saveIncidents(result.incidents || []);
            saveTimeline(result.timeline || []);
            saveEvidence(result.evidence || null);
            renderDashboard();
            return;
          }
        }
      } catch (err) {
        console.warn("Could not fetch remote demo, falling back to local seeder:", err);
      }
      seedDefaultSampleData();
      renderDashboard();
    });
  }
});

function renderDashboard() {
  const events = getEvents();
  const emptyState = document.getElementById("empty-state");
  const dashboardContent = document.getElementById("dashboard-content");

  if (!events || events.length === 0) {
    if (emptyState) emptyState.classList.remove("d-none");
    if (dashboardContent) dashboardContent.classList.add("d-none");
    return;
  }

  if (emptyState) emptyState.classList.add("d-none");
  if (dashboardContent) dashboardContent.classList.remove("d-none");

  // Calculate Metrics
  const totalEvents = events.length;
  const suspiciousEvents = events.filter(e => (e.riskScore || 0) > 0 || (e.severity && e.severity !== "NORMAL"));
  const criticalThreats = events.filter(e => e.severity === "CRITICAL" || (e.riskScore || 0) >= 80);
  const highThreats = events.filter(e => e.severity === "HIGH");
  const mediumThreats = events.filter(e => e.severity === "MEDIUM");
  const lowThreats = events.filter(e => e.severity === "LOW");
  const normalEvents = events.filter(e => (!e.severity || e.severity === "NORMAL") && (e.riskScore || 0) === 0);

  const maxRisk = events.reduce((max, e) => Math.max(max, e.riskScore || 0), 0);
  const avgRisk = Math.round(events.reduce((sum, e) => sum + (e.riskScore || 0), 0) / (totalEvents || 1));
  const suspiciousPct = Math.round((suspiciousEvents.length / (totalEvents || 1)) * 100);

  // Update KPI Elements
  const kpiTotal = document.getElementById("kpi-total-events");
  if (kpiTotal) kpiTotal.textContent = totalEvents.toLocaleString();

  const kpiSuspicious = document.getElementById("kpi-suspicious-events");
  if (kpiSuspicious) kpiSuspicious.textContent = suspiciousEvents.length.toLocaleString();

  const kpiSuspiciousPct = document.getElementById("kpi-suspicious-pct");
  if (kpiSuspiciousPct) kpiSuspiciousPct.textContent = `${suspiciousPct}% anomaly rate`;

  const kpiCritical = document.getElementById("kpi-critical-threats");
  if (kpiCritical) kpiCritical.textContent = criticalThreats.length.toLocaleString();

  const kpiCriticalSub = document.getElementById("kpi-critical-sub");
  if (kpiCriticalSub) {
    kpiCriticalSub.textContent = criticalThreats.length > 0 
      ? `${criticalThreats.length} require urgent containment` 
      : (highThreats.length > 0 ? `${highThreats.length} High severity events` : "No critical threats");
  }

  const kpiRisk = document.getElementById("kpi-overall-risk");
  if (kpiRisk) {
    kpiRisk.textContent = `${maxRisk}/100`;
    kpiRisk.className = `kpi-value ${maxRisk >= 80 ? 'text-danger' : (maxRisk >= 50 ? 'text-warning' : (maxRisk >= 20 ? 'text-info' : 'text-cyan'))}`;
  }

  // Severity Distribution Breakdown
  renderSeverityProgressBar(totalEvents, normalEvents.length, lowThreats.length, mediumThreats.length, highThreats.length, criticalThreats.length);

  // Active Incident Dossier
  renderActiveIncident();

  // Recent Flagged Anomalies Table
  renderRecentAnomaliesTable(suspiciousEvents);
}

function renderSeverityProgressBar(total, normal, low, medium, high, critical) {
  const bar = document.getElementById("severity-progress-bar");
  if (!bar) return;

  const pctNormal = ((normal / total) * 100).toFixed(1);
  const pctLow = ((low / total) * 100).toFixed(1);
  const pctMed = ((medium / total) * 100).toFixed(1);
  const pctHigh = ((high / total) * 100).toFixed(1);
  const pctCrit = ((critical / total) * 100).toFixed(1);

  bar.innerHTML = `
    ${normal > 0 ? `<div class="progress-bar" role="progressbar" style="width: ${pctNormal}%; background-color: var(--cyber-normal);" title="Normal: ${normal} (${pctNormal}%)"></div>` : ''}
    ${low > 0 ? `<div class="progress-bar" role="progressbar" style="width: ${pctLow}%; background-color: var(--cyber-low);" title="Low: ${low} (${pctLow}%)"></div>` : ''}
    ${medium > 0 ? `<div class="progress-bar" role="progressbar" style="width: ${pctMed}%; background-color: var(--cyber-medium);" title="Medium: ${medium} (${pctMed}%)"></div>` : ''}
    ${high > 0 ? `<div class="progress-bar" role="progressbar" style="width: ${pctHigh}%; background-color: var(--cyber-high);" title="High: ${high} (${pctHigh}%)"></div>` : ''}
    ${critical > 0 ? `<div class="progress-bar" role="progressbar" style="width: ${pctCrit}%; background-color: var(--cyber-critical);" title="Critical: ${critical} (${pctCrit}%)"></div>` : ''}
  `;

  const cNormal = document.getElementById("count-normal");
  if (cNormal) cNormal.textContent = `Normal (${normal})`;

  const cLow = document.getElementById("count-low");
  if (cLow) cLow.textContent = `Low (${low})`;

  const cMed = document.getElementById("count-medium");
  if (cMed) cMed.textContent = `Medium (${medium})`;

  const cHigh = document.getElementById("count-high");
  if (cHigh) cHigh.textContent = `High (${high})`;

  const cCrit = document.getElementById("count-critical");
  if (cCrit) cCrit.textContent = `Critical (${critical})`;
}

function renderActiveIncident() {
  const container = document.getElementById("active-incident-container");
  if (!container) return;

  const incidents = getIncidents();
  if (!incidents || incidents.length === 0) {
    container.innerHTML = `
      <div class="cyber-card p-4 text-center">
        <i class="bi bi-shield-check text-success fs-3 mb-2 d-block"></i>
        <h6 class="text-white fw-bold m-0">No Active Security Incidents</h6>
        <p class="text-slate-400 small m-0 mt-1">All processed telemetry indicates standard operational activity.</p>
      </div>
    `;
    return;
  }

  const inc = incidents[0];
  const recommendationsHtml = (inc.recommendations || []).map(r => `
    <li class="d-flex align-items-start gap-2 text-slate-300 small mb-1.5">
      <i class="bi bi-arrow-right-circle text-cyan mt-0.5"></i>
      <span>${r}</span>
    </li>
  `).join("");

  container.innerHTML = `
    <div class="cyber-card p-4 border border-danger-subtle" style="background: rgba(239, 68, 68, 0.03);">
      <div class="d-flex flex-wrap align-items-start justify-content-between gap-3 mb-3">
        <div>
          <div class="d-flex align-items-center gap-2 mb-1">
            <span class="font-mono text-cyan fw-bold">${inc.incidentId || 'INC-001'}</span>
            ${getSeverityBadgeHtml(inc.severity || 'HIGH')}
            <span class="badge bg-danger text-white font-mono px-2">${inc.status || 'OPEN'}</span>
          </div>
          <h4 class="text-white fw-bold m-0">${inc.title || 'Security Incident Detected'}</h4>
        </div>
        <div class="text-end">
          <span class="text-slate-400 text-xs d-block">Detected At</span>
          <span class="font-mono text-slate-300 small">${inc.createdAt || 'N/A'}</span>
        </div>
      </div>

      <div class="row g-3 mb-3 p-3 rounded" style="background: rgba(15, 23, 42, 0.6); border: 1px solid var(--cyber-border);">
        <div class="col-12 col-md-4">
          <span class="text-slate-400 text-xs d-block">Affected User</span>
          <strong class="text-white font-mono"><i class="bi bi-person text-cyan me-1"></i>${inc.affectedUser || 'Unknown'}</strong>
        </div>
        <div class="col-12 col-md-4">
          <span class="text-slate-400 text-xs d-block">Source IP</span>
          <strong class="text-white font-mono"><i class="bi bi-globe text-danger me-1"></i>${inc.sourceIP || 'N/A'}</strong>
        </div>
        <div class="col-12 col-md-4">
          <span class="text-slate-400 text-xs d-block">Suspicious Vector Events</span>
          <strong class="text-warning font-mono"><i class="bi bi-exclamation-octagon text-warning me-1"></i>${inc.suspiciousEventCount || 0} correlated events</strong>
        </div>
      </div>

      <div class="mb-3">
        <span class="text-slate-400 text-xs d-block mb-1">First Suspicious Event (Root Cause Trigger)</span>
        <div class="p-2.5 rounded font-mono text-xs text-danger d-flex align-items-center gap-2" style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2);">
          <i class="bi bi-flag-fill"></i>
          <span>${inc.firstSuspiciousEvent || 'N/A'}</span>
        </div>
      </div>

      ${recommendationsHtml ? `
        <div>
          <span class="text-slate-400 text-xs d-block mb-2 fw-semibold">Recommended Containment Actions</span>
          <ul class="list-unstyled m-0 p-0">
            ${recommendationsHtml}
          </ul>
        </div>
      ` : ''}
    </div>
  `;
}

function renderRecentAnomaliesTable(suspiciousEvents) {
  const tbody = document.getElementById("recent-anomalies-table-body");
  if (!tbody) return;

  if (!suspiciousEvents || suspiciousEvents.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center text-slate-500 py-4">
          <i class="bi bi-shield-check text-success me-1"></i> No anomalies detected in current dataset.
        </td>
      </tr>
    `;
    return;
  }

  // Show first 5 anomalies
  const preview = suspiciousEvents.slice(0, 5);
  tbody.innerHTML = preview.map(e => `
    <tr>
      <td class="font-mono text-slate-400 text-xs">${e.timestamp || ''}</td>
      <td class="font-mono fw-semibold text-white">${e.user || ''}</td>
      <td class="font-mono text-slate-300 text-xs">${e.ip || ''}</td>
      <td class="font-mono text-cyan text-xs">${e.action || ''}</td>
      <td class="font-mono fw-bold ${e.riskScore >= 70 ? 'text-danger' : (e.riskScore >= 40 ? 'text-warning' : 'text-info')}">${e.riskScore || 0}/100</td>
      <td>${getSeverityBadgeHtml(e.severity)}</td>
      <td class="text-slate-300 text-xs text-truncate" style="max-width: 320px;" title="${e.reason || ''}">${e.reason || 'Heuristic anomaly detected'}</td>
    </tr>
  `).join("");
}
