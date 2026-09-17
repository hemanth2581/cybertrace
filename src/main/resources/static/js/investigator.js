/**
 * CyberTrace AI Investigator Q&A Logic
 * Evidence-grounded reasoning without external AI hallucinations.
 */

document.addEventListener("DOMContentLoaded", () => {
  loadInvestigationChat();
  setupChatHandlers();
  window.addEventListener("cybertrace_storage_update", loadInvestigationChat);
});

function loadInvestigationChat() {
  const events = getEvents();
  const emptyStateEl = document.getElementById("investigator-empty-state");
  const contentEl = document.getElementById("investigator-content");

  if (!events || events.length === 0) {
    if (emptyStateEl) emptyStateEl.classList.remove("d-none");
    if (contentEl) contentEl.classList.add("d-none");
    return;
  }

  if (emptyStateEl) emptyStateEl.classList.add("d-none");
  if (contentEl) contentEl.classList.remove("d-none");

  renderChatHistory();
}

function renderChatHistory() {
  const history = getInvestigations();
  const chatContainer = document.getElementById("chat-messages-container");
  if (!chatContainer) return;

  if (history.length === 0) {
    chatContainer.innerHTML = `
      <div class="chat-bubble-ai mb-3">
        <div class="d-flex align-items-center gap-2 mb-1">
          <i class="bi bi-robot text-cyan"></i>
          <strong class="text-cyan small">CyberTrace Forensic Investigator</strong>
        </div>
        <p class="m-0 small">
          Hello! I am your evidence-grounded digital forensics assistant. Ask me questions about the investigated security events, attack vector timeline, source IPs, or involved user identities.
        </p>
      </div>
    `;
    return;
  }

  chatContainer.innerHTML = history.map(item => `
    <div class="chat-bubble-user mb-2">
      <div class="small fw-semibold">${item.question}</div>
      <div class="text-slate-300 text-xs text-end mt-1 font-mono">${item.timestamp || ''}</div>
    </div>
    <div class="chat-bubble-ai mb-3">
      <div class="d-flex align-items-center gap-2 mb-1">
        <i class="bi bi-robot text-cyan"></i>
        <strong class="text-cyan small">Forensic Analysis (100% Evidence-Grounded)</strong>
      </div>
      <p class="m-0 small leading-relaxed">${item.answer}</p>
    </div>
  `).join("");

  chatContainer.scrollTop = chatContainer.scrollHeight;
}

function setupChatHandlers() {
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const clearBtn = document.getElementById("clear-chat-btn");
  const pills = document.querySelectorAll(".suggestion-pill");

  if (form && input) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (!q) return;

      input.value = "";
      await executeQuery(q);
    });
  }

  pills.forEach(pill => {
    pill.addEventListener("click", async () => {
      const q = pill.getAttribute("data-question");
      if (q) await executeQuery(q);
    });
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      saveInvestigations([]);
      renderChatHistory();
    });
  }
}

async function executeQuery(question) {
  const chatContainer = document.getElementById("chat-messages-container");
  const sendBtn = document.getElementById("chat-send-btn");

  // Add temporary loading indicator
  if (chatContainer) {
    chatContainer.innerHTML += `
      <div class="chat-bubble-user mb-2">
        <div class="small fw-semibold">${question}</div>
      </div>
      <div class="chat-bubble-ai mb-3 text-slate-400 small" id="temp-loading-bubble">
        <span class="spinner-border spinner-border-sm text-cyan me-2"></span> Analyzing telemetry evidence...
      </div>
    `;
    chatContainer.scrollTop = chatContainer.scrollHeight;
  }

  if (sendBtn) sendBtn.disabled = true;

  try {
    const res = await queryInvestigatorApi(question);
    addInvestigationItem(question, res.answer);
    renderChatHistory();
  } catch (err) {
    addInvestigationItem(question, "Error communicating with Java reasoning engine: " + err.message);
    renderChatHistory();
  } finally {
    if (sendBtn) sendBtn.disabled = false;
  }
}
