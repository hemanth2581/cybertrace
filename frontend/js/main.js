/**
 * ========================================================
 * CYBERTRACE: AI DIGITAL FORENSICS TIME MACHINE
 * Master Frontend Controller (main.js)
 * ========================================================
 */

// Global State
let currentTimelineData = null;
let currentStepIndex = 0;
let isPlaying = false;
let playInterval = null;

// ========================================================
// CORE API HELPER
// ========================================================
async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(endpoint, options);
        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.message || `Server responded with status ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`[API Error] ${endpoint}:`, error);
        showToast(error.message || "Network error communicating with Python backend", "error");
        return null;
    }
}

// Toast Notification Helper
function showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.style.cssText = "position: fixed; bottom: 24px; right: 24px; z-index: 9999; display: flex; flex-direction: column; gap: 8px;";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    const bgColor = type === "error" ? "#ef4444" : (type === "success" ? "#10b981" : "#0284c7");
    toast.style.cssText = `background: ${bgColor}; color: white; padding: 12px 18px; border-radius: 8px; font-size: 0.85rem; font-weight: 600; box-shadow: 0 4px 20px rgba(0,0,0,0.5); transition: all 0.3s ease; transform: translateY(20px); opacity: 0;`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.transform = "translateY(0)";
        toast.style.opacity = "1";
    }, 10);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// System & Database Status Checker
async function checkSystemStatus() {
    const data = await fetchAPI("/api/status");
    if (!data) return;

    // Sidebar status
    const sbStatus = document.getElementById("sidebar-db-status");
    if (sbStatus && data.database) {
        const isConnected = data.database.connected;
        sbStatus.innerHTML = `
            <div class="status-row">
                <span style="color: var(--text-muted);">Database:</span>
                <span class="status-indicator">
                    <span class="status-dot ${isConnected ? '' : 'offline'}"></span>
                    <span style="color: ${isConnected ? 'var(--color-normal)' : 'var(--color-medium)'}; font-weight: 700;">
                        ${isConnected ? 'CONNECTED' : 'LOCAL STORE'}
                    </span>
                </span>
            </div>
        `;
    }

    // Topbar status pill
    const topStatus = document.getElementById("topbar-system-status");
    if (topStatus) {
        topStatus.innerHTML = `
            <span class="status-dot"></span>
            <span>SYSTEM ONLINE</span>
        `;
    }
}

// Refresh Current View
function refreshCurrentView() {
    showToast("Refreshing security data...", "info");
    const path = window.location.pathname;
    if (path.includes("timeline")) loadTimeline();
    else if (path.includes("anomalies")) loadAnomalies();
    else if (path.includes("events")) loadEvents();
    else if (path.includes("evidence")) loadEvidence();
    else if (path.includes("investigation")) loadInvestigation();
    else if (path.includes("report")) loadReport();
    else loadDashboard();
}

// ========================================================
// 1. DASHBOARD CONTROLLER (index.html)
// ========================================================
async function loadDashboard() {
    const stats = await fetchAPI("/api/stats");
    const incidentsData = await fetchAPI("/api/incidents");
    const eventsData = await fetchAPI("/api/events");

    if (!stats) return;

    // 1. Update KPI Values
    const elTotal = document.getElementById("stat-total-events");
    const elCritical = document.getElementById("stat-critical-threats");
    const elIncidents = document.getElementById("stat-active-incidents");
    const elRisk = document.getElementById("stat-overall-risk");

    if (elTotal) elTotal.textContent = stats.total_events || 0;
    if (elCritical) elCritical.textContent = stats.critical_events || 0;
    if (elIncidents) elIncidents.textContent = stats.active_incidents || 0;
    if (elRisk) elRisk.textContent = `${stats.avg_risk_score || 0}/100`;

    // 2. Render Threat Severity Breakdown
    const elSeverityContainer = document.getElementById("threat-severity-breakdown");
    if (elSeverityContainer && stats.risk_distribution) {
        const total = stats.total_events || 1;
        const crit = stats.risk_distribution.CRITICAL || 0;
        const high = stats.risk_distribution.HIGH || 0;
        const med = stats.risk_distribution.MEDIUM || 0;
        const low = stats.risk_distribution.LOW || 0;

        const critPct = Math.round((crit / total) * 100);
        const highPct = Math.round((high / total) * 100);
        const medPct = Math.round((med / total) * 100);
        const lowPct = Math.round((low / total) * 100);

        elSeverityContainer.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 4px;">
                        <span style="color: var(--color-critical); font-weight: 700;">🔴 Critical Severity (${crit})</span>
                        <span class="code-font">${critPct}%</span>
                    </div>
                    <div style="height: 6px; background: var(--bg-surface); border-radius: 3px; overflow: hidden;">
                        <div style="width: ${critPct}%; height: 100%; background: var(--color-critical);"></div>
                    </div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 4px;">
                        <span style="color: var(--color-high); font-weight: 700;">🟠 High Severity (${high})</span>
                        <span class="code-font">${highPct}%</span>
                    </div>
                    <div style="height: 6px; background: var(--bg-surface); border-radius: 3px; overflow: hidden;">
                        <div style="width: ${highPct}%; height: 100%; background: var(--color-high);"></div>
                    </div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 4px;">
                        <span style="color: var(--color-medium); font-weight: 700;">🟡 Medium Severity (${med})</span>
                        <span class="code-font">${medPct}%</span>
                    </div>
                    <div style="height: 6px; background: var(--bg-surface); border-radius: 3px; overflow: hidden;">
                        <div style="width: ${medPct}%; height: 100%; background: var(--color-medium);"></div>
                    </div>
                </div>

                <div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 4px;">
                        <span style="color: var(--color-normal); font-weight: 700;">🟢 Normal / Low (${low})</span>
                        <span class="code-font">${lowPct}%</span>
                    </div>
                    <div style="height: 6px; background: var(--bg-surface); border-radius: 3px; overflow: hidden;">
                        <div style="width: ${lowPct}%; height: 100%; background: var(--color-normal);"></div>
                    </div>
                </div>
            </div>
        `;
    }

    // 3. Highlight Active Incident Card
    const elIncidentCard = document.getElementById("active-incident-highlight-card");
    if (elIncidentCard) {
        if (incidentsData && incidentsData.incidents && incidentsData.incidents.length > 0) {
            const inc = incidentsData.incidents[0];
            const isCrit = inc.severity === 'CRITICAL';
            elIncidentCard.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                    <div>
                        <span class="badge ${isCrit ? 'badge-critical' : 'badge-high'}" style="margin-bottom: 6px;">
                            ${inc.incident_id} • ${inc.severity}
                        </span>
                        <h3 style="font-size: 1.2rem; color: var(--text-primary); font-weight: 800;">${inc.title}</h3>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 0.7rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Peak Threat Risk</div>
                        <div style="font-size: 1.6rem; font-weight: 800; font-family: var(--font-mono); color: ${isCrit ? 'var(--color-critical)' : 'var(--color-high)'};">
                            ${inc.risk_score}/100
                        </div>
                    </div>
                </div>
                <p style="color: var(--text-secondary); font-size: 0.85rem; line-height: 1.5; margin-bottom: 1.25rem;">
                    ${inc.summary}
                </p>
                <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                    <a href="timeline.html" class="btn btn-primary btn-sm">⏱️ Open Time Machine</a>
                    <a href="evidence.html" class="btn btn-secondary btn-sm">🔗 Inspect Evidence</a>
                    <a href="report.html" class="btn btn-outline btn-sm">📄 View Report</a>
                </div>
            `;
        } else {
            elIncidentCard.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🛡️</div>
                    <div style="font-weight: 700; color: var(--color-normal); margin-bottom: 4px;">No Active Security Incidents</div>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">Current log stream is operating within normal corporate baseline.</div>
                </div>
            `;
        }
    }

    // 4. Render Recent Security Events Table
    const elTable = document.getElementById("recent-events-table-body");
    if (elTable && eventsData) {
        const events = (eventsData.events || []).slice(0, 8);
        if (events.length === 0) {
            elTable.innerHTML = `<tr><td colspan="6" class="empty-state">No events found. Upload a CSV log file to begin.</td></tr>`;
        } else {
            elTable.innerHTML = events.map(ev => {
                const sev = (ev.severity || 'LOW').toLowerCase();
                return `
                    <tr>
                        <td class="code-font">${ev.timestamp}</td>
                        <td><b>${ev.user}</b></td>
                        <td>${ev.event_type} <span style="color: var(--text-muted);">(${ev.action})</span></td>
                        <td class="code-font">${ev.ip}</td>
                        <td><span class="badge badge-${sev}">${ev.severity}</span></td>
                        <td><span class="code-font" style="font-weight: 700;">${ev.risk_score}</span></td>
                    </tr>
                `;
            }).join("");
        }
    }
}

// Load Demo Scenario Action
async function loadDemoScenario(scenarioName) {
    showToast(`Loading demo scenario: ${scenarioName.replace('_', ' ')}...`, "info");
    const res = await fetchAPI("/api/demo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario: scenarioName })
    });

    if (res && res.status === "success") {
        showToast(res.message, "success");
        refreshCurrentView();
    }
}

// ========================================================
// 2. LOG UPLOAD CONTROLLER (upload.html)
// ========================================================
function setupUploadPage() {
    const uploadForm = document.getElementById("csv-upload-form");
    const fileInput = document.getElementById("csv-file-input");
    const pasteArea = document.getElementById("csv-paste-textarea");
    const dropzone = document.getElementById("upload-dropzone-box");

    if (dropzone && fileInput) {
        dropzone.addEventListener("click", () => fileInput.click());
        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });
        dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                const fileName = e.dataTransfer.files[0].name;
                dropzone.querySelector(".dropzone-text").textContent = `Selected: ${fileName}`;
            }
        });

        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                const fileName = fileInput.files[0].name;
                dropzone.querySelector(".dropzone-text").textContent = `Selected: ${fileName}`;
            }
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            
            let csvText = "";
            if (fileInput && fileInput.files.length > 0) {
                const file = fileInput.files[0];
                csvText = await file.text();
            } else if (pasteArea && pasteArea.value.trim().length > 0) {
                csvText = pasteArea.value.trim();
            } else {
                showToast("Please select a CSV file or paste CSV log text", "error");
                return;
            }

            showToast("Ingesting and analyzing logs with Python Pandas...", "info");
            const res = await fetchAPI("/api/upload", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ csv: csvText })
            });

            if (res && res.status === "success") {
                showToast(res.message, "success");
                setTimeout(() => {
                    window.location.href = "timeline.html";
                }, 900);
            }
        });
    }
}

// ========================================================
// 3. ALL EVENTS CONTROLLER (events.html)
// ========================================================
async function loadEvents() {
    const data = await fetchAPI("/api/events");
    const tableBody = document.getElementById("all-events-table-body");
    const searchInput = document.getElementById("event-search-input");
    const severityFilter = document.getElementById("severity-filter");
    const countBadge = document.getElementById("events-count-badge");

    if (!tableBody || !data) return;

    let eventsList = data.events || [];
    if (countBadge) countBadge.textContent = `${eventsList.length} Total Records`;

    function renderTable(items) {
        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="8" class="empty-state">No events match your filter criteria.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(ev => {
            const sev = (ev.severity || 'LOW').toLowerCase();
            return `
                <tr>
                    <td class="code-font">${ev.timestamp}</td>
                    <td><b>${ev.user}</b></td>
                    <td>${ev.event_type} <span style="color: var(--text-muted);">(${ev.action})</span></td>
                    <td class="code-font">${ev.ip}</td>
                    <td class="code-font">${ev.device}</td>
                    <td>${ev.file ? `<span class="code-font">${ev.file}</span>` : '<span style="color: var(--text-muted);">-</span>'}</td>
                    <td><span class="code-font" style="font-weight: 700;">${ev.risk_score}</span></td>
                    <td><span class="badge badge-${sev}">${ev.severity}</span></td>
                </tr>
            `;
        }).join("");
    }

    renderTable(eventsList);

    function filterEvents() {
        const query = (searchInput?.value || "").toLowerCase().trim();
        const sev = (severityFilter?.value || "").toUpperCase().trim();

        const filtered = eventsList.filter(e => {
            const matchesQuery = !query || 
                e.user.toLowerCase().includes(query) ||
                e.ip.toLowerCase().includes(query) ||
                (e.file && e.file.toLowerCase().includes(query)) ||
                e.event_type.toLowerCase().includes(query) ||
                e.device.toLowerCase().includes(query);
            const matchesSev = !sev || e.severity === sev;
            return matchesQuery && matchesSev;
        });

        renderTable(filtered);
    }

    if (searchInput) searchInput.addEventListener("input", filterEvents);
    if (severityFilter) severityFilter.addEventListener("change", filterEvents);
}

// ========================================================
// 4. ANOMALIES CONTROLLER (anomalies.html)
// ========================================================
async function loadAnomalies() {
    const data = await fetchAPI("/api/anomalies");
    const tableBody = document.getElementById("anomalies-table-body");
    const summaryCard = document.getElementById("anomalies-summary-stats");

    if (!data) return;

    if (summaryCard) {
        summaryCard.innerHTML = `
            <div class="kpi-grid" style="margin-bottom: 0;">
                <div class="kpi-card critical">
                    <div class="kpi-header"><span class="kpi-label">Total Flagged Anomalies</span><span class="kpi-icon">⚠️</span></div>
                    <div class="kpi-value">${data.total_anomalies || 0}</div>
                    <div class="kpi-desc">Threat events exceeding threshold</div>
                </div>
                <div class="kpi-card critical">
                    <div class="kpi-header"><span class="kpi-label">Critical Severity</span><span class="kpi-icon">🔴</span></div>
                    <div class="kpi-value">${data.critical_count || 0}</div>
                    <div class="kpi-desc">Score ≥ 81/100</div>
                </div>
                <div class="kpi-card high">
                    <div class="kpi-header"><span class="kpi-label">High Severity</span><span class="kpi-icon">🟠</span></div>
                    <div class="kpi-value">${data.high_count || 0}</div>
                    <div class="kpi-desc">Score 61 - 80</div>
                </div>
                <div class="kpi-card medium">
                    <div class="kpi-header"><span class="kpi-label">Medium Severity</span><span class="kpi-icon">🟡</span></div>
                    <div class="kpi-value">${data.medium_count || 0}</div>
                    <div class="kpi-desc">Score 31 - 60</div>
                </div>
            </div>
        `;
    }

    if (tableBody) {
        if (!data.anomalies || data.anomalies.length === 0) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <div class="empty-state-icon">🛡️</div>
                        <div style="font-weight: 700; color: var(--color-normal);">No Anomalies Detected</div>
                        <div style="font-size: 0.8rem; color: var(--text-muted);">Current security logs do not show any policy or anomaly violations.</div>
                    </td>
                </tr>
            `;
            return;
        }

        tableBody.innerHTML = data.anomalies.map(ev => {
            const sev = (ev.severity || 'LOW').toLowerCase();
            return `
                <tr>
                    <td class="code-font">${ev.timestamp}</td>
                    <td><b>${ev.user}</b></td>
                    <td class="code-font">${ev.ip}</td>
                    <td>${ev.event_type} <span style="color: var(--text-muted);">(${ev.action})</span></td>
                    <td><span class="badge badge-${sev}">${ev.risk_score} - ${ev.severity}</span></td>
                    <td>
                        <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                            ${(ev.reason || '').split(';').map(r => `
                                <span style="background: var(--bg-critical); color: var(--color-critical); font-size: 0.75rem; font-weight: 600; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border-critical);">
                                    ⚠️ ${r.trim()}
                                </span>
                            `).join('')}
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    }
}

// ========================================================
// 5. INVESTIGATION CASES CONTROLLER (investigation.html)
// ========================================================
async function loadInvestigation() {
    const data = await fetchAPI("/api/incidents");
    const container = document.getElementById("active-incidents-container");
    if (!data || !container) return;

    if (!data.incidents || data.incidents.length === 0) {
        container.innerHTML = `
            <div class="card empty-state">
                <div class="empty-state-icon">🛡️</div>
                <div style="font-size: 1.1rem; font-weight: 700; color: var(--color-normal); margin-bottom: 4px;">No Active Security Incidents</div>
                <div style="font-size: 0.85rem; color: var(--text-muted);">CyberTrace has not identified any correlated multi-stage cyber breaches.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = data.incidents.map(inc => {
        const isCrit = inc.severity === 'CRITICAL';
        return `
            <div class="card" style="border-left: 4px solid ${isCrit ? 'var(--color-critical)' : 'var(--color-high)'};">
                <div class="card-header">
                    <div>
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <span class="code-font" style="font-weight: 800; font-size: 1.1rem; color: var(--text-accent);">${inc.incident_id}</span>
                            <span class="badge ${isCrit ? 'badge-critical' : 'badge-high'}">${inc.severity}</span>
                            <span style="font-size: 0.75rem; color: var(--text-muted);">• ${inc.start_time} to ${inc.end_time}</span>
                        </div>
                        <h3 class="card-title">${inc.title}</h3>
                    </div>
                    <div style="text-align: right;">
                        <span class="inspector-label">Peak Risk</span>
                        <div style="font-size: 1.75rem; font-weight: 800; font-family: var(--font-mono); color: ${isCrit ? 'var(--color-critical)' : 'var(--color-high)'};">
                            ${inc.risk_score}/100
                        </div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; background: var(--bg-surface); padding: 1rem; border-radius: var(--radius-sm); margin-bottom: 1.25rem;">
                    <div><span class="inspector-label">Primary Account</span><div><b>${inc.user || 'Unknown'}</b></div></div>
                    <div><span class="inspector-label">Host Device</span><div class="code-font">${(inc.devices || []).join(', ') || 'N/A'}</div></div>
                    <div><span class="inspector-label">Involved IPs</span><div class="code-font">${(inc.ips || []).join(', ') || 'N/A'}</div></div>
                    <div><span class="inspector-label">Targeted Files</span><div class="code-font">${(inc.files || []).join(', ') || 'None'}</div></div>
                </div>

                <h4 style="font-size: 0.85rem; font-weight: 700; text-transform: uppercase; color: var(--text-accent); margin-bottom: 0.5rem;">Incident Dossier Synopsis</h4>
                <p style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.6; margin-bottom: 1.25rem;">
                    ${inc.summary}
                </p>

                ${inc.stages && inc.stages.length > 0 ? `
                    <div style="margin-bottom: 1.25rem;">
                        <span class="inspector-label" style="display: block; margin-bottom: 6px;">Identified Attack Stages:</span>
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                            ${inc.stages.map(st => `<span style="background: var(--bg-surface); border: 1px solid var(--border-medium); color: var(--text-primary); font-size: 0.75rem; padding: 3px 8px; border-radius: 4px;">⚔️ ${st}</span>`).join('')}
                        </div>
                    </div>
                ` : ''}

                <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                    <a href="timeline.html" class="btn btn-primary btn-sm">⏱️ Replay in Time Machine</a>
                    <a href="evidence.html" class="btn btn-secondary btn-sm">🔗 View Evidence Chain</a>
                    <a href="report.html" class="btn btn-outline btn-sm">📄 View Report</a>
                </div>
            </div>
        `;
    }).join('');
}

// ========================================================
// 6. FORENSICS TIME MACHINE CONTROLLER (timeline.html)
// ========================================================
async function loadTimeline() {
    const data = await fetchAPI("/api/timeline");
    if (!data || !data.steps || data.steps.length === 0) return;

    currentTimelineData = data;
    currentStepIndex = 0;

    const slider = document.getElementById("timeline-slider");
    if (slider) {
        slider.max = data.steps.length - 1;
        slider.value = 0;
        slider.addEventListener("input", (e) => {
            pauseTimeline();
            seekStep(parseInt(e.target.value));
        });
    }

    renderTimelineTrack();
    updateStepView(0);
}

function renderTimelineTrack() {
    const track = document.getElementById("timeline-track-items");
    if (!track || !currentTimelineData) return;

    track.innerHTML = currentTimelineData.steps.map((step, idx) => {
        const isAnom = step.is_anomaly;
        const isCrit = step.severity === 'CRITICAL';
        const color = isCrit ? 'var(--color-critical)' : (isAnom ? 'var(--color-high)' : 'var(--color-normal)');
        
        return `
            <div onclick="seekStep(${idx})" class="timeline-step-node ${idx === currentStepIndex ? 'active' : ''}" style="cursor: pointer; padding: 12px 14px; border-left: 3px solid ${color}; background: var(--bg-surface); margin-bottom: 8px; border-radius: var(--radius-sm); transition: all 0.2s;" id="step-node-${idx}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="code-font" style="font-weight: 700;">${step.timestamp}</span>
                    <span class="badge badge-${(step.severity || 'low').toLowerCase()}">${step.risk_score} pts</span>
                </div>
                <div style="font-size: 0.85rem; margin-top: 4px; color: ${idx === currentStepIndex ? 'var(--color-cyan)' : 'var(--text-primary)'}; font-weight: ${idx === currentStepIndex ? '700' : '400'};">
                    ${step.status_headline}
                </div>
            </div>
        `;
    }).join("");
}

function updateStepView(index) {
    if (!currentTimelineData || !currentTimelineData.steps[index]) return;
    currentStepIndex = index;
    const step = currentTimelineData.steps[index];

    // Slider & Counters
    const slider = document.getElementById("timeline-slider");
    if (slider) slider.value = index;

    const counter = document.getElementById("timeline-step-counter");
    if (counter) counter.textContent = `Event ${index + 1} of ${currentTimelineData.steps.length}`;

    // Active Inspector Fields
    const inspTimestamp = document.getElementById("insp-timestamp");
    const inspUser = document.getElementById("insp-user");
    const inspDevice = document.getElementById("insp-device");
    const inspIP = document.getElementById("insp-ip");
    const inspEvent = document.getElementById("insp-event");
    const inspFile = document.getElementById("insp-file");
    const inspRisk = document.getElementById("insp-risk");
    const inspReason = document.getElementById("insp-reason");
    const inspHeadline = document.getElementById("insp-headline");

    if (inspTimestamp) inspTimestamp.textContent = step.timestamp;
    if (inspUser) inspUser.textContent = step.user;
    if (inspDevice) inspDevice.textContent = step.device;
    if (inspIP) inspIP.textContent = step.ip;
    if (inspEvent) inspEvent.textContent = `${step.event_type} (${step.action})`;
    if (inspFile) inspFile.textContent = step.file ? `${step.file} (${step.data_size || 0} KB)` : 'None';
    if (inspRisk) {
        inspRisk.innerHTML = `<span class="badge badge-${(step.severity || 'low').toLowerCase()}">${step.risk_score}/100 - ${step.severity}</span>`;
    }
    if (inspReason) inspReason.textContent = step.reason;
    if (inspHeadline) inspHeadline.innerHTML = step.status_headline;

    // Highlight in track
    document.querySelectorAll(".timeline-step-node").forEach((node, i) => {
        if (i === index) {
            node.style.background = "var(--bg-elevated)";
            node.style.boxShadow = "0 0 15px rgba(0, 242, 254, 0.15)";
        } else {
            node.style.background = "var(--bg-surface)";
            node.style.boxShadow = "none";
        }
    });
}

function seekStep(index) {
    if (!currentTimelineData) return;
    if (index >= 0 && index < currentTimelineData.steps.length) {
        updateStepView(index);
    }
}

function nextStep() {
    if (!currentTimelineData) return;
    if (currentStepIndex < currentTimelineData.steps.length - 1) {
        seekStep(currentStepIndex + 1);
    } else {
        pauseTimeline();
    }
}

function prevStep() {
    if (!currentTimelineData) return;
    if (currentStepIndex > 0) {
        seekStep(currentStepIndex - 1);
    }
}

function jumpToFirstSuspicious() {
    if (!currentTimelineData) return;
    pauseTimeline();
    seekStep(currentTimelineData.first_suspicious_index || 0);
    showToast("Jumped to First Suspicious Event (10:15)", "info");
}

function playTimeline() {
    if (isPlaying) return;
    isPlaying = true;
    const playBtn = document.getElementById("btn-play");
    if (playBtn) playBtn.innerHTML = "⏸️ Pause";

    playInterval = setInterval(() => {
        if (currentStepIndex >= currentTimelineData.steps.length - 1) {
            pauseTimeline();
        } else {
            nextStep();
        }
    }, 1100);
}

function pauseTimeline() {
    isPlaying = false;
    if (playInterval) clearInterval(playInterval);
    const playBtn = document.getElementById("btn-play");
    if (playBtn) playBtn.innerHTML = "▶️ Play";
}

// ========================================================
// 7. EVIDENCE GRAPH CONTROLLER (evidence.html)
// ========================================================
async function loadEvidence() {
    const data = await fetchAPI("/api/evidence");
    if (!data) return;

    const chainContainer = document.getElementById("evidence-visual-chain");
    const cardInspector = document.getElementById("evidence-details-card");

    if (chainContainer && data.nodes) {
        chainContainer.innerHTML = data.nodes.map(node => `
            <div class="evidence-node ${node.severity === 'CRITICAL' ? 'critical' : ''}" onclick="inspectEvidenceNode('${node.id}')" id="node-${node.id}">
                <div style="font-size: 0.7rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">${node.type}</div>
                <div style="font-size: 1.05rem; font-weight: 800; color: var(--text-primary); margin: 4px 0;" class="code-font">${node.label}</div>
                <span class="badge badge-${(node.severity || 'low').toLowerCase()}">${node.max_risk} pts</span>
            </div>
        `).join('<div class="evidence-arrow">➔</div>');
    }

    window.evidenceNodesMap = data.entities || {};
    if (data.nodes.length > 0) {
        inspectEvidenceNode(data.nodes[0].id);
    }
}

function inspectEvidenceNode(nodeId) {
    const node = window.evidenceNodesMap ? window.evidenceNodesMap[nodeId] : null;
    const card = document.getElementById("evidence-details-card");
    if (!node || !card) return;

    card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
            <div>
                <span style="font-size: 0.75rem; text-transform: uppercase; color: var(--color-cyan); font-weight: 700;">${node.type} ENTITY DOSSIER</span>
                <h3 style="font-size: 1.4rem; color: var(--text-primary); font-weight: 800;" class="code-font">${node.label}</h3>
            </div>
            <span class="badge badge-${(node.severity || 'low').toLowerCase()}">${node.max_risk}/100 - ${node.severity}</span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; background: var(--bg-surface); padding: 1.25rem; border-radius: var(--radius-sm);">
            <div><span class="inspector-label">First Seen:</span><div class="code-font" style="font-size: 1rem;">${node.first_seen}</div></div>
            <div><span class="inspector-label">Last Seen:</span><div class="code-font" style="font-size: 1rem;">${node.last_seen}</div></div>
            <div><span class="inspector-label">Linked Incident Events:</span><div class="code-font" style="font-size: 1rem;">${node.event_count} Records</div></div>
        </div>
    `;

    document.querySelectorAll(".evidence-node").forEach(n => n.classList.remove("selected"));
    const selectedEl = document.getElementById(`node-${nodeId}`);
    if (selectedEl) selectedEl.classList.add("selected");
}

// ========================================================
// 8. AI INVESTIGATOR CONTROLLER (investigator.html)
// ========================================================
async function askInvestigator(questionText = null) {
    const input = document.getElementById("investigator-input");
    const question = questionText || (input ? input.value.trim() : "");
    if (!question) return;

    if (input && questionText) input.value = questionText;

    const respContainer = document.getElementById("investigator-response-container");
    if (respContainer) {
        respContainer.innerHTML = `
            <div class="response-card" style="display: flex; align-items: center; gap: 10px; color: var(--color-low);">
                <span>⏳ Analyzing digital forensic logs and reconstructing incident facts...</span>
            </div>
        `;
    }

    const res = await fetchAPI("/api/investigate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question })
    });

    if (res && respContainer) {
        let formattedAnswer = res.answer
            .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
            .replace(/\n\n/g, '<br/><br/>')
            .replace(/- (.*?)<br\/>/g, '• $1<br/>');

        respContainer.innerHTML = `
            <div class="response-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.85rem;">
                    <span style="font-weight: 800; color: var(--color-cyan); font-size: 0.95rem;">🛡️ AI Digital Forensic Investigator</span>
                    <span class="badge badge-normal">Confidence: ${Math.round((res.confidence || 0.95) * 100)}%</span>
                </div>
                <div style="color: var(--text-primary); font-size: 0.95rem; line-height: 1.6;">${formattedAnswer}</div>
                ${res.evidence_used && res.evidence_used.length > 0 ? `
                    <div style="margin-top: 1.25rem; border-top: 1px solid var(--border-subtle); padding-top: 0.85rem;">
                        <span class="inspector-label" style="display: block; margin-bottom: 6px;">Corroborating Forensic Log Records:</span>
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                            ${res.evidence_used.map(e => `
                                <span class="badge badge-${(e.risk_score > 30 ? 'critical' : 'low')}" style="font-size: 0.7rem;">
                                    ${e.timestamp} | ${e.user} | ${e.ip} | ${e.action} (Risk: ${e.risk_score})
                                </span>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }
}

// ========================================================
// 9. INCIDENT REPORT CONTROLLER (report.html)
// ========================================================
async function loadReport() {
    const report = await fetchAPI("/api/report");
    const container = document.getElementById("incident-report-view");
    if (!report || !container) return;

    container.innerHTML = `
        <div class="card" style="border-top: 4px solid var(--color-cyan);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem;">
                <div>
                    <h2 style="font-size: 1.5rem; color: var(--text-primary); font-weight: 800;">${report.title}</h2>
                    <p style="color: var(--text-muted); font-size: 0.85rem;">Generated by CyberTrace AI Digital Forensics Engine</p>
                </div>
                <div style="display: flex; gap: 0.75rem; align-items: center;">
                    <span class="badge badge-${(report.severity || 'low').toLowerCase()}">${report.risk_score}/100 - ${report.severity}</span>
                    <a href="/api/report/pdf" class="btn btn-primary" download>↓ DOWNLOAD PDF REPORT</a>
                </div>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; background: var(--bg-surface); padding: 1.25rem; border-radius: var(--radius-sm); margin-bottom: 1.5rem;">
                <div><span class="inspector-label">Incident ID</span><div class="code-font" style="font-size: 1.1rem; font-weight: 800;">${report.incident_id}</div></div>
                <div><span class="inspector-label">Time Window</span><div class="code-font">${report.start_time} - ${report.end_time}</div></div>
                <div><span class="inspector-label">Target Accounts</span><div><b>${report.users.join(', ') || 'None'}</b></div></div>
                <div><span class="inspector-label">Involved IPs</span><div class="code-font">${report.ips.join(', ') || 'None'}</div></div>
            </div>

            <h3 style="font-size: 1.05rem; color: var(--text-accent); margin-bottom: 0.5rem; font-weight: 700;">Executive Forensic Summary</h3>
            <p style="color: var(--text-secondary); line-height: 1.6; margin-bottom: 1.5rem;">${report.ai_explanation}</p>

            <h3 style="font-size: 1.05rem; color: var(--text-accent); margin-bottom: 0.75rem; font-weight: 700;">Chronological Incident Timeline</h3>
            <div class="table-responsive" style="margin-bottom: 1.5rem;">
                <table class="table">
                    <thead>
                        <tr><th>Time</th><th>User</th><th>IP Address</th><th>Action</th><th>Risk</th><th>Forensic Rule Violation</th></tr>
                    </thead>
                    <tbody>
                        ${report.timeline.map(s => `
                            <tr>
                                <td class="code-font">${s.timestamp}</td>
                                <td><b>${s.user}</b></td>
                                <td class="code-font">${s.ip}</td>
                                <td>${s.event_type} (${s.action})</td>
                                <td><span class="badge badge-${(s.severity || 'low').toLowerCase()}">${s.risk_score}</span></td>
                                <td style="font-size: 0.8rem;">${s.reason}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>

            <h3 style="font-size: 1.05rem; color: var(--text-accent); margin-bottom: 0.5rem; font-weight: 700;">Recommended Incident Remediation Actions</h3>
            <ul style="color: var(--text-secondary); padding-left: 1.5rem; line-height: 1.8;">
                ${report.remediation_steps.map(r => `<li>${r}</li>`).join('')}
            </ul>
        </div>
    `;
}

// ========================================================
// MOBILE NAVIGATION & RESPONSIVE DRAWER CONTROLLER
// ========================================================
function initMobileNavigation() {
    // 1. Ensure backdrop exists
    let backdrop = document.getElementById("sidebar-backdrop");
    if (!backdrop) {
        backdrop = document.createElement("div");
        backdrop.id = "sidebar-backdrop";
        backdrop.className = "sidebar-backdrop";
        document.body.appendChild(backdrop);
    }

    // 2. Ensure topbar toggle hamburger exists in topbar
    const topbars = document.querySelectorAll(".topbar");
    topbars.forEach(topbar => {
        if (!topbar.querySelector(".sidebar-toggle-btn")) {
            const toggleBtn = document.createElement("button");
            toggleBtn.className = "sidebar-toggle-btn";
            toggleBtn.setAttribute("aria-label", "Toggle Navigation Menu");
            toggleBtn.innerHTML = "☰";
            toggleBtn.onclick = toggleSidebar;
            topbar.insertBefore(toggleBtn, topbar.firstChild);
        }
    });

    // 3. Close sidebar when clicking backdrop or pressing Escape
    backdrop.onclick = closeSidebar;
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeSidebar();
    });

    // 4. Auto-close mobile sidebar when clicking any navigation link
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            if (window.innerWidth <= 1024) closeSidebar();
        });
    });
}

function toggleSidebar() {
    document.body.classList.toggle("sidebar-open");
    const toggleBtns = document.querySelectorAll(".sidebar-toggle-btn");
    const isOpen = document.body.classList.contains("sidebar-open");
    toggleBtns.forEach(btn => {
        btn.innerHTML = isOpen ? "✕" : "☰";
    });
}

function closeSidebar() {
    document.body.classList.remove("sidebar-open");
    const toggleBtns = document.querySelectorAll(".sidebar-toggle-btn");
    toggleBtns.forEach(btn => {
        btn.innerHTML = "☰";
    });
}

// Auto-run status check & mobile navigation initialization on page load
document.addEventListener("DOMContentLoaded", () => {
    initMobileNavigation();
    checkSystemStatus();
});

