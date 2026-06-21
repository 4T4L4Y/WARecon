function toggleOptions() {
  const selected = Array.from(document.querySelectorAll('input[name="choices"]:checked'))
    .map((el) => el.value);

  document.getElementById('naabuOptions').classList.toggle('visible', selected.includes('1'));
  document.getElementById('subdomainOptions').classList.toggle('visible', selected.includes('2'));
  document.getElementById('waybackOptions').classList.toggle('visible', selected.includes('3'));
  document.getElementById('httpxOptions').classList.toggle('visible', selected.includes('4'));
  document.getElementById('nucleiOptions').classList.toggle('visible', selected.includes('5'));
}

function toggleSubdomainOption() {
  const known = document.getElementById('waybackKnownUrls').checked;
  document.getElementById('includeSubdomainsContainer').style.display = known ? 'flex' : 'none';
}

function applyPreset(preset) {
  document.querySelectorAll('input[name="choices"]').forEach((el) => {
    el.checked = false;
  });

  const presets = {
    quick: ['2', '4'],
    deep: ['2', '3', '4'],
    full: ['1', '2', '3', '4', '5'],
  };

  (presets[preset] || []).forEach((value) => {
    const input = document.querySelector(`input[name="choices"][value="${value}"]`);
    if (input) input.checked = true;
  });

  toggleOptions();
}

function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.tab-panel');

  if (!tabs.length) return;

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      tabs.forEach((t) => t.classList.toggle('active', t === tab));
      panels.forEach((p) => p.classList.toggle('active', p.id === `tab-${target}`));
    });
  });
}

function fetchNucleiDataAndRenderChart(domain) {
  if (!domain) return;

  fetch(`/outputs/${domain}_nuclei.json`)
    .then((response) => {
      if (!response.ok) throw new Error('No nuclei data');
      return response.json();
    })
    .then((data) => {
      if (!Array.isArray(data) || !data.length) return;
      renderNucleiChart(data);
      renderSeverityLegend();
      document.getElementById('chartSection').style.display = 'block';
    })
    .catch(() => {});
}

function renderSeverityLegend() {
  const container = document.getElementById('severityLegendContainer');
  container.innerHTML = `
    <div class="severity-legend">
      <span class="legend-item"><span class="color-box" style="background:#ef4444"></span> Critical</span>
      <span class="legend-item"><span class="color-box" style="background:#f97316"></span> High</span>
      <span class="legend-item"><span class="color-box" style="background:#eab308"></span> Medium</span>
      <span class="legend-item"><span class="color-box" style="background:#22c55e"></span> Low</span>
      <span class="legend-item"><span class="color-box" style="background:#3b82f6"></span> Info</span>
    </div>
  `;
}

function severityColor(severity) {
  const map = {
    critical: 'rgba(239, 68, 68, 0.75)',
    high: 'rgba(249, 115, 22, 0.75)',
    medium: 'rgba(234, 179, 8, 0.75)',
    low: 'rgba(34, 197, 94, 0.75)',
    info: 'rgba(59, 130, 246, 0.75)',
  };
  return map[severity] || 'rgba(148, 163, 184, 0.75)';
}

function severityValue(severity) {
  const map = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };
  return map[severity] || 0;
}

function renderNucleiChart(data) {
  const canvas = document.getElementById('nucleiChart');
  const ctx = canvas.getContext('2d');
  const labels = data.map((item) => item.info.name);
  const values = data.map((item) => severityValue(item.info.severity));
  const colors = data.map((item) => severityColor(item.info.severity));

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Önem Derecesi',
        data: values,
        backgroundColor: colors,
        borderColor: colors.map((c) => c.replace('0.75', '1')),
        borderWidth: 1,
        borderRadius: 6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
      },
      scales: {
        y: {
          beginAtZero: true,
          max: 5,
          ticks: {
            stepSize: 1,
            color: '#8b97ab',
            callback: (v) => ['', 'Info', 'Low', 'Medium', 'High', 'Critical'][v] || '',
          },
          grid: { color: 'rgba(42, 53, 72, 0.8)' },
        },
        x: {
          ticks: { color: '#8b97ab', maxRotation: 45 },
          grid: { display: false },
        },
      },
    },
  });
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('input[name="choices"]').forEach((el) => {
    el.addEventListener('change', toggleOptions);
  });

  toggleOptions();
  initTabs();

  const domain = document.body.dataset.domain;
  if (domain) fetchNucleiDataAndRenderChart(domain);

  document.querySelector('form').addEventListener('submit', (e) => {
    const checked = document.querySelectorAll('input[name="choices"]:checked');
    if (!checked.length) {
      e.preventDefault();
      alert('Lütfen en az bir tarama modülü seçin.');
      return;
    }
    document.getElementById('loading').classList.add('visible');
  });
});
