/**
 * ForgeGuard AI — Client-Side Application JS
 */

document.addEventListener("DOMContentLoaded", function () {
  // 1. Polling for Unread Notifications
  const notifBadge = document.getElementById("notifBadge");
  const notifList = document.getElementById("notifList");

  function fetchNotifications() {
    if (!notifBadge) return;
    fetch("/api/notifications/unread-count")
      .then((res) => res.json())
      .then((data) => {
        if (data.count > 0) {
          notifBadge.textContent = data.count > 99 ? "99+" : data.count;
          notifBadge.classList.remove("d-none");
        } else {
          notifBadge.classList.add("d-none");
        }

        if (notifList && data.recent) {
          if (data.recent.length === 0) {
            notifList.innerHTML = '<div class="py-2 text-center text-muted">No new alerts</div>';
          } else {
            notifList.innerHTML = data.recent
              .map(
                (n) => `
                <a href="${n.link}" class="d-block p-2 text-decoration-none rounded mb-1 text-white hover-bg">
                  <div class="d-flex justify-content-between align-items-center">
                    <strong class="text-truncate" style="max-width: 180px;">${n.title}</strong>
                    <span class="text-secondary" style="font-size: 0.65rem;">${n.time}</span>
                  </div>
                  <div class="text-secondary small text-truncate">${n.message}</div>
                </a>
              `
              )
              .join("");
          }
        }
      })
      .catch((err) => console.debug("Notif check:", err));
  }

  fetchNotifications();
  setInterval(fetchNotifications, 15000);

  // 2. Configure Global Chart.js Dark Mode Options
  if (typeof Chart !== "undefined") {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.borderColor = "rgba(255, 255, 255, 0.08)";
    Chart.defaults.plugins.tooltip.backgroundColor = "#0d121f";
    Chart.defaults.plugins.tooltip.titleColor = "#f8fafc";
    Chart.defaults.plugins.tooltip.bodyColor = "#cbd5e1";
    Chart.defaults.plugins.tooltip.borderColor = "rgba(255, 255, 255, 0.15)";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 6;
  }
});

// Finding Details Modal Fetcher
function openFindingModal(findingId) {
  const modalEl = document.getElementById("findingDetailModal");
  if (!modalEl) return;
  const modal = new bootstrap.Modal(modalEl);

  document.getElementById("modalFindingTitle").textContent = "Loading finding details...";
  document.getElementById("modalFindingSnippet").textContent = "";
  document.getElementById("modalTechExplanation").textContent = "";
  document.getElementById("modalWhyMatters").textContent = "";
  document.getElementById("modalDiff").textContent = "";

  fetch(`/findings/${findingId}`)
    .then((res) => res.json())
    .then((f) => {
      document.getElementById("modalFindingTitle").textContent = f.title;
      document.getElementById("modalFindingRule").textContent = f.rule_id;
      document.getElementById("modalFindingSeverity").textContent = f.severity.toUpperCase();
      document.getElementById("modalFindingSeverity").className = `fg-badge-sev sev-${f.severity.toLowerCase()}`;
      document.getElementById("modalFindingLocation").textContent = `${f.file_path}:${f.line_number || "—"}`;
      document.getElementById("modalFindingSnippet").textContent = f.code_snippet || "No source preview available";
      document.getElementById("modalTechExplanation").textContent = f.technical_explanation;
      document.getElementById("modalWhyMatters").textContent = f.why_it_matters;
      document.getElementById("modalRecommendation").textContent = f.recommendation;
      document.getElementById("modalDiff").textContent = f.proposed_diff || f.suggested_fix || "No automated diff";
      
      const form = document.getElementById("statusUpdateForm");
      if (form) {
        form.action = `/findings/${f.id}/status`;
      }
      modal.show();
    })
    .catch((err) => {
      console.error(err);
      alert("Failed to load finding details.");
    });
}
