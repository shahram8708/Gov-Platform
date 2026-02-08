const OFFLINE_KEY = "offlineComplaints";

function getOfflineQueue() {
  try {
    return JSON.parse(localStorage.getItem(OFFLINE_KEY) || "[]");
  } catch (e) {
    return [];
  }
}

function saveOfflineQueue(list) {
  localStorage.setItem(OFFLINE_KEY, JSON.stringify(list));
}

async function syncOfflineComplaints() {
  const queue = getOfflineQueue();
  if (!navigator.onLine || !queue.length) {
    return;
  }
  try {
    const res = await fetch("/complaints/offline-sync", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ complaints: queue }),
    });
    if (res.ok) {
      saveOfflineQueue([]);
      updateOfflineBanner();
    }
  } catch (err) {
    console.warn("Offline sync failed", err);
  }
}

function updateOfflineBanner() {
  const banner = document.getElementById("offline-banner");
  const syncBtn = document.getElementById("offline-sync-btn");
  const hasQueue = getOfflineQueue().length > 0;
  if (!banner) return;
  if (!navigator.onLine || hasQueue) {
    banner.classList.remove("d-none");
  } else {
    banner.classList.add("d-none");
  }
  if (syncBtn) {
    syncBtn.onclick = syncOfflineComplaints;
  }
}

async function queueComplaint(payload) {
  const queue = getOfflineQueue();
  queue.push(payload);
  saveOfflineQueue(queue);
  updateOfflineBanner();
}

window.queueComplaint = queueComplaint;
window.syncOfflineComplaints = syncOfflineComplaints;

document.addEventListener("DOMContentLoaded", () => {
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    form.addEventListener("submit", () => {
      form.querySelectorAll("input, textarea").forEach((el) => {
        if (typeof el.value === "string") {
          el.value = el.value.trim();
        }
      });
    });
  });

  updateOfflineBanner();
  window.addEventListener("online", () => {
    updateOfflineBanner();
    syncOfflineComplaints();
  });
  window.addEventListener("offline", updateOfflineBanner);
});
