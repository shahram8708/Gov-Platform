(function () {
  const gpsButton = document.getElementById("use-gps-btn");
  const latitudeInput = document.getElementById("latitude");
  const longitudeInput = document.getElementById("longitude");
  const locationStatus = document.getElementById("location-status");
  const manualLocationInput = document.getElementById("manual_location");
  const submitBtn = document.getElementById("submit-btn");
  const submitSpinner = document.getElementById("submit-spinner");
  const submitStatus = document.getElementById("submit-status");
  const form = document.getElementById("project-discovery-form");
  const mapContainer = document.getElementById("project-map");

  let leafletMap = null;
  let leafletMarker = null;

  const loadLeafletFallback = () =>
    new Promise((resolve, reject) => {
      const cssId = "leaflet-fallback-css";
      if (!document.getElementById(cssId)) {
        const css = document.createElement("link");
        css.id = cssId;
        css.rel = "stylesheet";
        css.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
        document.head.appendChild(css);
      }

      const existing = document.querySelector('script[data-leaflet-fallback="true"]');
      if (existing) {
        existing.addEventListener("load", () => (window.L ? resolve(window.L) : reject(new Error("Leaflet missing after fallback"))), { once: true });
        existing.addEventListener("error", () => reject(new Error("Leaflet fallback failed")), { once: true });
        return;
      }

      const script = document.createElement("script");
      script.src = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
      script.async = true;
      script.dataset.leafletFallback = "true";
      script.onload = () => (window.L ? resolve(window.L) : reject(new Error("Leaflet missing after fallback")));
      script.onerror = () => reject(new Error("Leaflet fallback failed"));
      document.body.appendChild(script);
    });

  const ensureLeafletReady = () => {
    if (!mapContainer) {
      return Promise.resolve();
    }
    if (window.L) {
      return Promise.resolve(window.L);
    }

    const primaryScript = document.querySelector('script[src*="leaflet"]');
    if (primaryScript) {
      return new Promise((resolve, reject) => {
        let settled = false;
        const finish = () => {
          if (settled) return;
          settled = true;
          window.L ? resolve(window.L) : reject(new Error("Leaflet failed to load"));
        };
        const timer = setTimeout(() => finish(), 2000);
        primaryScript.addEventListener(
          "load",
          () => {
            clearTimeout(timer);
            finish();
          },
          { once: true }
        );
        primaryScript.addEventListener(
          "error",
          () => {
            clearTimeout(timer);
            reject(new Error("Leaflet CDN blocked"));
          },
          { once: true }
        );
      }).catch(() => loadLeafletFallback());
    }

    return loadLeafletFallback();
  };

  const setStatus = (message, variant = "muted") => {
    if (locationStatus) {
      locationStatus.textContent = message;
      locationStatus.className = `text-${variant} small`;
    }
  };

  const reverseGeocode = async (lat, lng) => {
    const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}&addressdetails=1&zoom=19&extratags=1&namedetails=1`;
    const res = await fetch(url, {
      headers: {
        Accept: "application/json",
        "Accept-Language": "en",
      },
    });
    if (!res.ok) {
      throw new Error(`Reverse geocode failed: ${res.status}`);
    }
    const data = await res.json();
    const addr = data.address || {};
    const parts = [
      addr.house_number,
      addr.building,
      addr.residential,
      addr.road,
      addr.neighbourhood,
      addr.suburb,
      addr.hamlet,
      addr.village,
      addr.town,
      addr.city,
      addr.county,
      addr.state_district,
      addr.state,
      addr.postcode,
      addr.country,
    ].filter(Boolean);

    // Prefer constructed parts when they offer more granularity than display_name.
    const joined = parts.join(", ");
    const displayName = (data.display_name || "").trim();
    if (joined && (!displayName || joined.length > displayName.length)) {
      return joined;
    }
    return displayName || joined;
  };

  const ensureLeafletMarker = (lat, lng, title = "Query location") => {
    const latNum = Number.parseFloat(lat);
    const lngNum = Number.parseFloat(lng);
      if (!mapContainer || Number.isNaN(latNum) || Number.isNaN(lngNum) || !window.L) {
        console.warn("Leaflet marker skipped", { hasMap: !!mapContainer, hasLeaflet: !!window.L, lat, lng });
      return;
    }

    if (!leafletMap) {
      leafletMap = L.map(mapContainer, {
        zoomControl: true,
        attributionControl: true,
      });
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 19,
        attribution: "© OpenStreetMap contributors",
      }).addTo(leafletMap);
        leafletMap.on("tileerror", (e) => {
          console.error("Leaflet tile load error", e);
          if (mapContainer) {
            mapContainer.insertAdjacentHTML(
              "beforeend",
              '<div class="text-center text-danger small py-2">Map tiles blocked by network/CSP</div>'
            );
          }
        });
        leafletMap.on("load", () => {
          console.info("Leaflet map loaded", { lat: latNum, lng: lngNum });
        });
      // Ensure Leaflet recalculates dimensions when first mounted so tiles render.
      setTimeout(() => {
        try {
          leafletMap.invalidateSize();
        } catch (err) {
          console.warn("Leaflet invalidateSize failed", err);
        }
      }, 50);
    }

    leafletMap.setView([latNum, lngNum], 12);

    if (leafletMarker) {
      leafletMarker.remove();
    }

    leafletMarker = L.marker([latNum, lngNum], { title }).addTo(leafletMap);
  };

  const initMap = () => {
    let payload = {};

    try {
      payload = mapContainer?.dataset.map ? JSON.parse(mapContainer.dataset.map) : {};
    } catch (err) {
      console.warn("Failed to parse map payload", err);
    }

    const loc = payload.location || {};
    const lat = loc.latitude ?? latitudeInput?.value;
    const lng = loc.longitude ?? longitudeInput?.value;
    if (mapContainer) {
      mapContainer.style.minHeight = mapContainer.style.minHeight || "320px";
      mapContainer.style.width = mapContainer.style.width || "100%";
    }
    console.info("Map init payload", {
      lat,
      lng,
      loc,
      size: mapContainer ? { w: mapContainer.offsetWidth, h: mapContainer.offsetHeight } : null,
    });

    if (lat && lng) {
      ensureLeafletMarker(lat, lng, loc.name || "Query location");
      return;
    }

    // Default center over India so the user sees a meaningful map without credentials.
    ensureLeafletMarker(20.5937, 78.9629, "Map ready");
  };

  const relabelMarkdownLinks = () => {
    const linkifyTextNode = (node) => {
      const urlRegex = /(https?:\/\/[^\s<]+)/g;
      const parts = node.textContent.split(urlRegex);
      if (parts.length === 1) return [node];

      const fragments = [];
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (i % 2 === 1) {
          const a = document.createElement("a");
          a.href = part;
          a.textContent = "Click here";
          a.target = "_blank";
          a.rel = "noopener noreferrer";
          fragments.push(a);
        } else if (part) {
          fragments.push(document.createTextNode(part));
        }
      }
      return fragments;
    };

    document.querySelectorAll(".markdown-body").forEach((section) => {
      const walker = document.createTreeWalker(section, NodeFilter.SHOW_TEXT, null);
      const textNodes = [];
      while (walker.nextNode()) {
        textNodes.push(walker.currentNode);
      }

      textNodes.forEach((textNode) => {
        if (textNode.parentNode && textNode.parentNode.closest && textNode.parentNode.closest("a")) {
          return; // Skip text already inside an anchor
        }
        const replacements = linkifyTextNode(textNode);
        if (replacements.length === 1 && replacements[0] === textNode) {
          return;
        }
        const parent = textNode.parentNode;
        replacements.forEach((n) => parent.insertBefore(n, textNode));
        parent.removeChild(textNode);
      });

      section.querySelectorAll("a").forEach((link) => {
        link.textContent = "Click here";
        link.setAttribute("target", "_blank");
        link.setAttribute("rel", "noopener noreferrer");
      });
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    if (mapContainer) {
      ensureLeafletReady()
        .then(() => initMap())
        .catch((err) => {
          console.warn("Leaflet unavailable; showing placeholder map", err);
          mapContainer.innerHTML = '<div class="text-center text-muted small py-4">Map unavailable</div>';
        });
    }
    relabelMarkdownLinks();
  });

  if (gpsButton) {
    gpsButton.addEventListener("click", () => {
      if (!navigator.geolocation) {
        setStatus("Geolocation is not supported on this browser.", "danger");
        return;
      }
      setStatus("Requesting location permission…", "primary");
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          const { latitude, longitude } = pos.coords;
          latitudeInput.value = latitude.toFixed(6);
          longitudeInput.value = longitude.toFixed(6);
          setStatus(`Location captured: ${latitude.toFixed(4)}, ${longitude.toFixed(4)}. Resolving full address…`, "primary");
          ensureLeafletMarker(latitude, longitude, "Your location");
          reverseGeocode(latitude, longitude)
            .then((address) => {
              const resolved = address && address.trim();
              if (resolved && manualLocationInput) {
                manualLocationInput.value = resolved;
              }
              setStatus(resolved ? `Address: ${resolved}` : `Location captured: ${latitude.toFixed(4)}, ${longitude.toFixed(4)}`, resolved ? "success" : "warning");
            })
            .catch((err) => {
              console.warn("Reverse geocode failed", err);
              setStatus(`Location captured: ${latitude.toFixed(4)}, ${longitude.toFixed(4)} (address lookup unavailable)`, "warning");
              if (manualLocationInput && !manualLocationInput.value) {
                manualLocationInput.value = `${latitude.toFixed(4)}, ${longitude.toFixed(4)}`;
              }
            });
        },
        (err) => {
          setStatus(`Location access denied (${err.code})`, "danger");
        },
        { enableHighAccuracy: true, timeout: 10000 }
      );
    });
  }

  if (form) {
    form.addEventListener("submit", () => {
      if (submitBtn && submitSpinner && submitStatus) {
        submitBtn.disabled = true;
        submitSpinner.classList.remove("d-none");
        submitStatus.textContent = "Fetching verified projects…";
      }
    });
  }
})();
