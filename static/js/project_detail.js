(function () {
  const buttons = document.querySelectorAll("[data-find-info-btn]");

  const setButtonState = (btn, isLoading) => {
    const spinner = btn.querySelector(".spinner-border");
    const label = btn.querySelector(".label-text");
    if (isLoading) {
      btn.disabled = true;
      if (spinner) spinner.classList.remove("d-none");
      if (label) label.textContent = "Finding…";
    } else {
      btn.disabled = false;
      if (spinner) spinner.classList.add("d-none");
      if (label) label.textContent = "Find Information";
    }
  };

  const showAlert = (section, message, variant = "secondary") => {
    const target = document.querySelector(`[data-section-alert="${section}"]`);
    if (!target) return;
    target.classList.remove("d-none", "alert-secondary", "alert-danger", "alert-success", "alert-warning");
    target.classList.add(`alert-${variant}`);
    target.textContent = message;
  };

  const getCsrf = (btn) => btn.getAttribute("data-csrf") || "";

  buttons.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const section = btn.getAttribute("data-section");
      const projectId = btn.getAttribute("data-project-id");
      const endpoint = btn.getAttribute("data-endpoint");
      const missingRaw = btn.getAttribute("data-missing") || "[]";
      let missingFields = [];
      try {
        missingFields = JSON.parse(missingRaw);
      } catch (err) {
        showAlert(section, "Invalid missing fields payload", "danger");
        return;
      }

      if (!endpoint || !projectId || !section || !missingFields.length) {
        showAlert(section, "Cannot start fetch: missing parameters", "danger");
        return;
      }

      setButtonState(btn, true);
      showAlert(section, "", "secondary");

      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCsrf(btn),
            "X-CSRF-Token": getCsrf(btn),
          },
          credentials: "same-origin",
          body: JSON.stringify({
            project_id: projectId,
            section_name: section,
            missing_fields: missingFields,
          }),
        });

        const text = await res.text();
        let data;
        try {
          data = text ? JSON.parse(text) : {};
        } catch (err) {
          data = { error: text || "Unexpected response" };
        }

        if (!res.ok) {
          throw new Error(data.error || text || "Unable to fetch information");
        }

        showAlert(section, "Section updated. Refreshing…", "success");
        setTimeout(() => window.location.reload(), 600);
      } catch (err) {
        showAlert(section, err.message || "Request failed", "danger");
      } finally {
        setButtonState(btn, false);
      }
    });
  });

  const initSnapshots = () => {
    const slider = document.getElementById("snapshot-slider");
    const img = document.getElementById("snapshot-image");
    const label = document.getElementById("snapshot-label");
    if (!slider || !img || !label || !window.TIMELAPSE_FRAMES) return;
    slider.addEventListener("input", () => {
      const idx = parseInt(slider.value, 10) || 0;
      const frameId = window.TIMELAPSE_FRAMES[idx];
      const frameLabel = window.TIMELAPSE_LABELS[idx];
      if (frameId) {
        img.src = `/projects/snapshots/${frameId}`;
        label.textContent = frameLabel;
      }
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    initSnapshots();
  });
})();
