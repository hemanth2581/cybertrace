/**
 * CyberTrace Forensic Time Machine Logic
 * Chronological attack progression with auto-play animation and first suspicious event detection.
 */

let timelineEvents = [];
let currentIndex = 0;
let playInterval = null;

document.addEventListener("DOMContentLoaded", () => {
  loadTimelineData();
  setupPlaybackControls();
  window.addEventListener("cybertrace_storage_update", loadTimelineData);
});

function loadTimelineData() {
  timelineEvents = getTimeline();
  const allEvents = getEvents();

  const emptyStateEl = document.getElementById("timeline-empty-state");
  const contentEl = document.getElementById("timeline-content");

  if (!allEvents || allEvents.length === 0 || !timelineEvents || timelineEvents.length === 0) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (contentEl) contentEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (contentEl) contentEl.classList.remove("d-none");

  currentIndex = 0;
  renderTimelineList();
  selectTimelineEvent(0);
}

function renderTimelineList() {
  const container = document.getElementById("timeline-items-container");
  if (!container) return;

  container.innerHTML = timelineEvents.map((t, idx) => {
    const isSusp = t.riskScore > 20 || t.severity !== "NORMAL";
    const isFirst = t.firstSuspicious;
    
    return `
      <div class="timeline-step-item p-3 mb-2 rounded border cursor-pointer transition-all ${idx === currentIndex ? 'border-cyan bg-slate-800' : 'border-slate-800 bg-slate-900/60'}" 
           id="timeline-step-${idx}"
           onclick="selectTimelineEvent(${idx})"
           style="cursor: pointer;">
        <div class="d-flex align-items-center justify-content-between mb-1">
          <span class="font-mono text-xs ${isFirst ? 'text-danger fw-bold' : 'text-slate-400'}">${t.timestamp}</span>
          ${isFirst ? '<span class="badge bg-danger text-white font-mono px-2 py-0.5" style="font-size: 0.65rem;">FIRST SUSPICIOUS EVENT</span>' : ''}
        </div>
        <div class="d-flex align-items-center justify-content-between">
          <strong class="text-white small">${t.eventType}</strong>
          ${getSeverityBadgeHtml(t.severity)}
        </div>
        <div class="text-slate-400 text-xs mt-1 text-truncate">${t.description}</div>
      </div>
    `;
  }).join("");
}

function selectTimelineEvent(index) {
  if (index < 0 || index >= timelineEvents.length) return;
  currentIndex = index;

  // Highlight step in list
  timelineEvents.forEach((_, idx) => {
    const el = document.getElementById(`timeline-step-${idx}`);
    if (el) {
      if (idx === currentIndex) {
        el.style.borderColor = "var(--cyber-cyan)";
        el.style.backgroundColor = "rgba(30, 41, 59, 0.9)";
      } else {
        el.style.borderColor = "rgba(51, 65, 85, 0.5)";
        el.style.backgroundColor = "rgba(15, 23, 42, 0.6)";
      }
    }
  });

  const evt = timelineEvents[currentIndex];
  renderSelectedEventDetail(evt);
  updateSliderProgress();
}

function renderSelectedEventDetail(evt) {
  const detailEl = document.getElementById("timeline-detail-pane");
  if (!detailEl || !evt) return;

  detailEl.innerHTML = `
    <div class="cyber-card ${evt.firstSuspicious ? 'border-danger' : ''}">
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 pb-3 mb-3 border-bottom" style="border-color: rgba(51, 65, 85, 0.4) !important;">
        <div>
          <span class="text-slate-500 font-mono small d-block">EVENT #${currentIndex + 1} OF ${timelineEvents.length}</span>
          <h4 class="text-white fw-bold m-0">${evt.eventType}</h4>
        </div>
        <div class="d-flex align-items-center gap-2">
          ${evt.firstSuspicious ? '<span class="badge bg-danger text-white px-2 py-1"><i class="bi bi-shield-slash-fill me-1"></i> INITIAL INFILTRATION</span>' : ''}
          ${getSeverityBadgeHtml(evt.severity)}
        </div>
      </div>

      <div class="row g-3 mb-4">
        <div class="col-6 col-md-3">
          <span class="text-slate-500 small d-block">Timestamp</span>
          <strong class="text-white font-mono small">${evt.timestamp}</strong>
        </div>
        <div class="col-6 col-md-3">
          <span class="text-slate-500 small d-block">User Identity</span>
          <strong class="text-cyan font-mono small">${evt.user}</strong>
        </div>
        <div class="col-6 col-md-3">
          <span class="text-slate-500 small d-block">Endpoint Device</span>
          <strong class="text-white font-mono small">${evt.device}</strong>
        </div>
        <div class="col-6 col-md-3">
          <span class="text-slate-500 small d-block">Network IP</span>
          <strong class="text-warning font-mono small">${evt.ip}</strong>
        </div>
      </div>

      <div class="p-3 rounded bg-dark border border-slate-800 mb-3">
        <span class="text-slate-400 small d-block mb-1">Forensic Description:</span>
        <p class="text-slate-200 m-0 small leading-relaxed">${evt.description}</p>
      </div>

      <div class="d-flex justify-content-between align-items-center text-xs text-slate-400">
        <span>Evaluated Threat Score: <strong class="text-warning">${evt.riskScore}/100</strong></span>
        ${evt.file ? `<span>Target Asset: <strong class="text-cyan font-mono">${evt.file}</strong></span>` : ''}
      </div>
    </div>
  `;
}

function updateSliderProgress() {
  const slider = document.getElementById("timeline-slider");
  const stepLabel = document.getElementById("timeline-step-label");

  if (slider) {
    slider.max = Math.max(0, timelineEvents.length - 1);
    slider.value = currentIndex;
  }
  if (stepLabel) {
    stepLabel.textContent = `Event ${currentIndex + 1} of ${timelineEvents.length}`;
  }
}

function setupPlaybackControls() {
  const prevBtn = document.getElementById("timeline-prev-btn");
  const nextBtn = document.getElementById("timeline-next-btn");
  const playBtn = document.getElementById("timeline-play-btn");
  const slider = document.getElementById("timeline-slider");

  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      stopPlayback();
      if (currentIndex > 0) selectTimelineEvent(currentIndex - 1);
    });
  }

  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      stopPlayback();
      if (currentIndex < timelineEvents.length - 1) selectTimelineEvent(currentIndex + 1);
    });
  }

  if (playBtn) {
    playBtn.addEventListener("click", () => {
      if (playInterval) {
        stopPlayback();
      } else {
        startPlayback();
      }
    });
  }

  if (slider) {
    slider.addEventListener("input", (e) => {
      stopPlayback();
      selectTimelineEvent(parseInt(e.target.value, 10));
    });
  }
}

function startPlayback() {
  const playBtn = document.getElementById("timeline-play-btn");
  if (playBtn) {
    playBtn.innerHTML = `<i class="bi bi-pause-fill"></i> Pause`;
    playBtn.classList.replace("btn-info", "btn-warning");
  }

  if (currentIndex >= timelineEvents.length - 1) {
    currentIndex = -1;
  }

  playInterval = setInterval(() => {
    if (currentIndex < timelineEvents.length - 1) {
      selectTimelineEvent(currentIndex + 1);
    } else {
      stopPlayback();
    }
  }, 1200);
}

function stopPlayback() {
  if (playInterval) {
    clearInterval(playInterval);
    playInterval = null;
  }
  const playBtn = document.getElementById("timeline-play-btn");
  if (playBtn) {
    playBtn.innerHTML = `<i class="bi bi-play-fill"></i> Play`;
    playBtn.classList.replace("btn-warning", "btn-info");
  }
}
