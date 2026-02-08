document.addEventListener("DOMContentLoaded", () => {
  const forms = document.querySelectorAll("form");

  forms.forEach((form) => {
    form.addEventListener("submit", (event) => {
      const submitter = event.submitter;
      if (!submitter || submitter.type !== "submit") return;
      if (submitter.classList.contains("loading")) return;
      submitter.classList.add("btn-loading", "loading");
      submitter.setAttribute("aria-busy", "true");
      submitter.setAttribute("disabled", "disabled");
    });
  });
});
