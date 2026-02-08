(function () {
  const allowedMimes = ["image/jpeg", "image/png", "image/webp"];

  function toBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  function offlineReference() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return `offline-${Date.now()}`;
  }

  function attachSpinner(buttonId, spinnerId, statusId, statusMessage) {
    const btn = document.getElementById(buttonId);
    const spinner = document.getElementById(spinnerId);
    const status = document.getElementById(statusId);
    if (!btn || !spinner) return () => {};
    return () => {
      btn.disabled = true;
      spinner.classList.remove("d-none");
      if (status && statusMessage) status.textContent = statusMessage;
    };
  }

  function validateFileInput(input) {
    if (!input) return true;
    const files = input.files || [];
    if (!files.length) return true;
    const file = files[0];
    const maxBytes = parseInt(input.dataset.maxBytes || "0", 10) || 8 * 1024 * 1024;
    if (!allowedMimes.includes(file.type)) {
      alert("Only JPG, PNG, or WEBP images are allowed.");
      return false;
    }
    if (file.size === 0 || file.size > maxBytes) {
      alert("File is empty or exceeds the allowed size.");
      return false;
    }
    return true;
  }

  document.addEventListener("DOMContentLoaded", () => {
    const analyzeForm = document.querySelector("form[enctype='multipart/form-data']");
    if (analyzeForm) {
      const startSpinner = attachSpinner("analyze-btn", "analyze-spinner", "analyze-status", "Running AI analysis…");
      analyzeForm.addEventListener("submit", async (evt) => {
        const fileInput = analyzeForm.querySelector("input[type='file']");
        if (!validateFileInput(fileInput)) {
          evt.preventDefault();
          return;
        }
        if (!navigator.onLine) {
          evt.preventDefault();
          const file = fileInput.files[0];
          if (!file) return;
          const projectIdField = analyzeForm.querySelector("input[name='project_id']");
          const payload = {
            project_id: projectIdField ? projectIdField.value : null,
            complaint_type: analyzeForm.querySelector("select[name='complaint_type']")?.value,
            title: analyzeForm.querySelector("textarea[name='description']")?.value?.slice(0, 120) || "Offline Complaint",
            description: analyzeForm.querySelector("textarea[name='description']")?.value || "",
            severity_level: "MEDIUM",
            image_mime: file.type,
            image_b64: await toBase64(file),
            client_reference: offlineReference(),
            location_snapshot: {},
          };
          if (window.queueComplaint) {
            window.queueComplaint(payload);
            alert("Saved offline. It will sync automatically when you are online.");
          }
          return;
        }
        startSpinner();
      });
    }

    const finalizeForm = document.querySelector("form[action$='/complaints/submit']");
    if (finalizeForm) {
      const startSpinner = attachSpinner("submit-complaint-btn", "submit-complaint-spinner", "submit-complaint-status", "Submitting securely…");
      finalizeForm.addEventListener("submit", (evt) => {
        startSpinner();
      });
    }

    const supportForms = document.querySelectorAll("form[action*='/support']");
    supportForms.forEach((form) => {
      form.addEventListener("submit", (evt) => {
        const fileInput = form.querySelector("input[type='file']");
        if (!validateFileInput(fileInput)) {
          evt.preventDefault();
        }
      });
    });
  });
})();
