(() => {
  const dataEl = document.getElementById('transparency-data');
  if (!dataEl) return;

  const parseJSON = (value) => {
    try {
      return value ? JSON.parse(value) : {};
    } catch (err) {
      console.error('Failed to parse transparency data payload.', err);
      return {};
    }
  };

  const cityData = parseJSON(dataEl.dataset.cityOverview);
  const contractorMetrics = parseJSON(dataEl.dataset.contractorMetrics);
  const departmentMetrics = parseJSON(dataEl.dataset.departmentMetrics);

  const destroyExistingChart = (canvasEl) => {
    if (!canvasEl || typeof Chart === 'undefined') return;
    const existing = Chart.getChart(canvasEl);
    if (existing) existing.destroy();
  };

  const renderCharts = () => {
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js not available; charts will not render.');
      return;
    }

    const cityLabels = Object.keys(cityData);
    const cityActive = cityLabels.map((key) => cityData[key]?.active_complaints || 0);
    const cityResolved = cityLabels.map((key) => cityData[key]?.resolved || 0);
    const cityCanvas = document.getElementById('cityComplaintsChart');
    if (cityCanvas) {
      destroyExistingChart(cityCanvas);
      new Chart(cityCanvas, {
        type: 'bar',
        data: {
          labels: cityLabels,
          datasets: [
            { label: 'Active', data: cityActive, backgroundColor: '#0d6efd' },
            { label: 'Resolved', data: cityResolved, backgroundColor: '#6c757d' },
          ],
        },
        options: { responsive: true, plugins: { legend: { position: 'bottom' } } },
      });
    }

    const contractorIds = Object.keys(contractorMetrics);
    const contractorLabels = contractorIds.map((id) => contractorMetrics[id]?.name || id);
    const contractorComplaints = contractorIds.map((id) => contractorMetrics[id]?.total_complaints || 0);
    const contractorCanvas = document.getElementById('contractorChart');
    if (contractorCanvas) {
      destroyExistingChart(contractorCanvas);
      new Chart(contractorCanvas, {
        type: 'bar',
        data: {
          labels: contractorLabels,
          datasets: [{ label: 'Complaints', data: contractorComplaints, backgroundColor: '#6610f2' }],
        },
        options: { responsive: true, plugins: { legend: { display: false } } },
      });
    }

    const resolutionRates = contractorIds.map((id) => contractorMetrics[id]?.resolution_rate || 0);
    const resolutionCanvas = document.getElementById('resolutionTrendChart');
    if (resolutionCanvas) {
      destroyExistingChart(resolutionCanvas);
      new Chart(resolutionCanvas, {
        type: 'line',
        data: {
          labels: contractorLabels,
          datasets: [{ label: 'Resolution %', data: resolutionRates, borderColor: '#198754', backgroundColor: '#19875433', tension: 0.2 }],
        },
        options: { responsive: true, plugins: { legend: { display: false } } },
      });
    }

    const deptIds = Object.keys(departmentMetrics);
    const deptLabels = deptIds.map((id) => departmentMetrics[id]?.name || id);
    const deptComplaints = deptIds.map((id) => departmentMetrics[id]?.complaints_received || 0);
    const deptResolved = deptIds.map((id) => departmentMetrics[id]?.complaints_resolved || 0);
    const deptCanvas = document.getElementById('departmentChart');
    if (deptCanvas) {
      destroyExistingChart(deptCanvas);
      new Chart(deptCanvas, {
        type: 'bar',
        data: {
          labels: deptLabels,
          datasets: [
            { label: 'Received', data: deptComplaints, backgroundColor: '#fd7e14' },
            { label: 'Resolved', data: deptResolved, backgroundColor: '#20c997' },
          ],
        },
        options: { responsive: true, plugins: { legend: { position: 'bottom' } } },
      });
    }
  };

  renderCharts();

  window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
      renderCharts();
    }
  });

  const recalcForm = document.getElementById('recalc-analytics-form');
  if (recalcForm) {
    recalcForm.addEventListener('submit', (event) => {
      const confirmMessage = recalcForm.dataset.confirm || 'Recalculate analytics now?';
      if (!window.confirm(confirmMessage)) {
        event.preventDefault();
      }
    });
  }

  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((el) => new bootstrap.Tooltip(el));
  }
})();
