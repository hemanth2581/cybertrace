/**
 * CyberTrace Navigation Component & App Shell
 * Generates unified sidebar, topbar, and mobile offcanvas drawer.
 */

document.addEventListener("DOMContentLoaded", () => {
  renderSidebar();
  renderTopNavbar();
  setupClearDataHandler();
});

function getNavLinks() {
  const currentPath = window.location.pathname.split("/").pop() || "index.html";
  
  const links = [
    { name: "Dashboard", href: "index.html", icon: "bi-grid-1x2-fill" },
    { name: "Upload Logs", href: "upload.html", icon: "bi-cloud-arrow-up-fill" },
    { name: "Events Explorer", href: "events.html", icon: "bi-list-columns-reverse" },
    { name: "Anomalies", href: "anomalies.html", icon: "bi-shield-exclamation" },
    { name: "Investigation", href: "investigation.html", icon: "bi-folder-check" },
    { name: "Forensic Timeline", href: "timeline.html", icon: "bi-clock-history" },
    { name: "Evidence Graph", href: "evidence.html", icon: "bi-diagram-3-fill" },
    { name: "AI Investigator", href: "investigator.html", icon: "bi-robot" },
    { name: "Incident Report", href: "report.html", icon: "bi-file-earmark-pdf-fill" },
    { name: "How It Works", href: "how-it-works.html", icon: "bi-info-circle-fill" }
  ];

  return links.map(link => {
    const isActive = (currentPath === link.href) || 
                     (currentPath === "" && link.href === "index.html") ||
                     (currentPath === "/" && link.href === "index.html");
    return `
      <a href="${link.href}" class="nav-link-item ${isActive ? 'active' : ''}">
        <i class="bi ${link.icon}"></i>
        <span>${link.name}</span>
      </a>
    `;
  }).join("");
}

function renderSidebar() {
  const sidebarContainer = document.getElementById("sidebar-container");
  if (!sidebarContainer) return;

  sidebarContainer.innerHTML = `
    <div class="desktop-sidebar">
      <div class="brand-header">
        <img src="images/logo.png" alt="CyberTrace Logo" class="brand-logo-img">
        <div>
          <h1 class="brand-title">CYBERTRACE</h1>
          <p class="brand-subtitle">AI Forensics SOC</p>
        </div>
      </div>

      <nav class="nav-menu">
        ${getNavLinks()}
      </nav>

      <div class="p-3 border-top" style="border-color: rgba(51, 65, 85, 0.4) !important;">
        <button id="clear-data-btn" class="btn btn-outline-danger btn-sm w-100 d-flex align-items-center justify-content-center gap-2" style="border-radius: 10px;">
          <i class="bi bi-trash3"></i>
          <span>Clear Local Data</span>
        </button>
      </div>
    </div>
  `;
}

function renderTopNavbar() {
  const navbarContainer = document.getElementById("navbar-container");
  if (!navbarContainer) return;

  navbarContainer.innerHTML = `
    <header class="top-navbar">
      <div class="d-flex align-items-center gap-3">
        <!-- Mobile Menu Toggle Button -->
        <button class="btn btn-dark d-lg-none d-flex align-items-center justify-content-center" 
                type="button" 
                data-bs-toggle="offcanvas" 
                data-bs-target="#mobileOffcanvas" 
                aria-label="Toggle navigation"
                style="width: 40px; height: 40px; background: rgba(30, 41, 59, 0.8); border: 1px solid var(--cyber-border); border-radius: 10px;">
          <i class="bi bi-list fs-5 text-cyan"></i>
        </button>

        <div class="d-flex align-items-center gap-2">
          <img src="images/logo.png" alt="CyberTrace Logo" class="d-lg-none brand-logo-img" style="width: 30px; height: 30px;">
          <span class="d-lg-none text-white fw-bold tracking-wide">CYBERTRACE</span>
          <span class="d-none d-lg-inline text-slate-400 small">Security Command Center <span class="text-cyan">• Active Telemetry</span></span>
        </div>
      </div>

      <div class="d-flex align-items-center gap-2">
        <a href="upload.html" class="btn btn-primary btn-sm d-flex align-items-center gap-2 px-3 py-1.5" style="border-radius: 10px; font-weight: 600; background: linear-gradient(135deg, #0284c7, #06b6d4); border: none;">
          <i class="bi bi-cloud-upload-fill"></i>
          <span class="d-none d-sm-inline">+ Upload Logs</span>
        </a>

        <button onclick="location.reload()" class="btn btn-outline-secondary btn-sm d-flex align-items-center justify-content-center" 
                title="Refresh Workspace"
                style="width: 36px; height: 36px; border-radius: 10px; border-color: var(--cyber-border); color: #94a3b8;">
          <i class="bi bi-arrow-clockwise"></i>
        </button>
      </div>
    </header>

    <!-- Mobile Navigation Offcanvas Drawer -->
    <div class="offcanvas offcanvas-start text-bg-dark" tabindex="-1" id="mobileOffcanvas" style="background-color: #0f172a !important; width: 280px; border-right: 1px solid var(--cyber-border);">
      <div class="offcanvas-header border-bottom" style="border-color: rgba(51, 65, 85, 0.4) !important;">
        <div class="d-flex align-items-center gap-2">
          <img src="images/logo.png" alt="CyberTrace Logo" class="brand-logo-img" style="width: 32px; height: 32px;">
          <div>
            <h5 class="offcanvas-title text-white fw-bold m-0" style="font-size: 1.1rem;">CYBERTRACE</h5>
            <small class="text-cyan" style="font-size: 0.65rem;">SOC MOBILE COMMAND</small>
          </div>
        </div>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas" aria-label="Close"></button>
      </div>
      <div class="offcanvas-body p-0 d-flex flex-column">
        <nav class="nav-menu p-3">
          ${getNavLinks()}
        </nav>
        <div class="mt-auto p-3 border-top" style="border-color: rgba(51, 65, 85, 0.4) !important;">
          <button id="mobile-clear-data-btn" class="btn btn-outline-danger btn-sm w-100 d-flex align-items-center justify-content-center gap-2" style="border-radius: 10px;">
            <i class="bi bi-trash3"></i>
            <span>Clear Local Data</span>
          </button>
        </div>
      </div>
    </div>
  `;
}

function setupClearDataHandler() {
  const handler = () => {
    if (confirm("Are you sure you want to delete all CyberTrace investigation data from your browser?")) {
      clearCyberTraceData();
      alert("All local investigation data cleared.");
      window.location.href = "index.html";
    }
  };

  const desktopBtn = document.getElementById("clear-data-btn");
  if (desktopBtn) desktopBtn.addEventListener("click", handler);

  const mobileBtn = document.getElementById("mobile-clear-data-btn");
  if (mobileBtn) mobileBtn.addEventListener("click", handler);
}
