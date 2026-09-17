/**
 * CyberTrace Ingestion & Demo Scenario Handler
 * Supports RFC4180 CSV drag-and-drop uploading and pre-built codeathon demo attack datasets.
 */

document.addEventListener("DOMContentLoaded", () => {
  setupFileUpload();
  setupDemoButtons();
});

function setupFileUpload() {
  const dropzone = document.getElementById("upload-dropzone");
  const fileInput = document.getElementById("csv-file-input");
  const chooseBtn = document.getElementById("choose-file-btn");

  if (!dropzone || !fileInput) return;

  if (chooseBtn) {
    chooseBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      fileInput.click();
    });
  }

  dropzone.addEventListener("click", () => {
    fileInput.click();
  });

  // Drag & drop highlight
  ["dragenter", "dragover"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    }, false);
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    }, false);
  });

  dropzone.addEventListener("drop", (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
      handleFile(files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });
}

async function handleFile(file) {
  if (!file) return;

  if (!file.name.endsWith(".csv") && file.type !== "text/csv" && file.type !== "application/vnd.ms-excel") {
    showError("Please upload a valid .csv file containing security audit logs.");
    return;
  }

  showStatus(true);
  hideAlerts();

  try {
    const result = await analyzeCsvFile(file);
    processAnalysisSuccess(result, `Successfully ingested ${result.totalEvents || 0} events from "${file.name}"!`);
  } catch (err) {
    console.error("Upload error:", err);
    showError(err.message || "Failed to process CSV log file. Ensure required headers are present: timestamp, user, device, ip, action.");
  } finally {
    showStatus(false);
  }
}

function setupDemoButtons() {
  const scenarios = [
    { btnId: "demo-compromise-btn", file: "demo/account_compromise.csv", name: "Account Compromise" },
    { btnId: "demo-exfiltration-btn", file: "demo/data_exfiltration.csv", name: "Data Exfiltration" },
    { btnId: "demo-insider-btn", file: "demo/insider_threat.csv", name: "Insider Threat" },
    { btnId: "demo-normal-btn", file: "demo/normal_activity.csv", name: "Normal Activity" }
  ];

  scenarios.forEach(s => {
    const btn = document.getElementById(s.btnId);
    if (!btn) return;

    btn.addEventListener("click", async () => {
      showStatus(true);
      hideAlerts();

      try {
        const response = await fetch(s.file);
        if (!response.ok) {
          throw new Error(`Failed to load ${s.name} demo file from server.`);
        }
        const text = await response.text();
        const result = await analyzeCsvText(text);
        processAnalysisSuccess(result, `Successfully loaded "${s.name}" demo scenario (${result.totalEvents || 0} events)!`);
      } catch (err) {
        console.error("Demo scenario error:", err);
        showError(`Could not load demo scenario: ${err.message}`);
      } finally {
        showStatus(false);
      }
    });
  });
}

function processAnalysisSuccess(result, message) {
  if (!result || !result.events) {
    showError("Received empty or invalid analysis response from backend.");
    return;
  }

  // Persist to browser localStorage
  saveEvents(result.events || []);
  saveAnomalies(result.anomalies || []);
  saveIncidents(result.incidents || []);
  saveTimeline(result.timeline || []);
  saveEvidence(result.evidence || null);

  showSuccess(`${message} Redirecting to Command Center in 2 seconds...`);

  setTimeout(() => {
    window.location.href = "index.html";
  }, 1800);
}

function showStatus(visible) {
  const status = document.getElementById("upload-status");
  if (status) {
    if (visible) status.classList.remove("d-none");
    else status.classList.add("d-none");
  }
}

function hideAlerts() {
  const errAlert = document.getElementById("upload-error-alert");
  const succAlert = document.getElementById("upload-success-alert");
  if (errAlert) errAlert.classList.add("d-none");
  if (succAlert) succAlert.classList.add("d-none");
}

function showError(msg) {
  const errAlert = document.getElementById("upload-error-alert");
  const errMsg = document.getElementById("upload-error-msg");
  if (errAlert && errMsg) {
    errMsg.textContent = msg;
    errAlert.classList.remove("d-none");
  }
}

function showSuccess(msg) {
  const succAlert = document.getElementById("upload-success-alert");
  const succMsg = document.getElementById("upload-success-msg");
  if (succAlert && succMsg) {
    succMsg.textContent = msg;
    succAlert.classList.remove("d-none");
  }
}
