let nucleiTemplatesCache = [];

function syncNucleiTemplateHidden() {
  const hidden = document.getElementById('nucleiTemplates');
  if (!hidden) return;
  const ids = Array.from(document.querySelectorAll('input[name="nucleiTemplateIds"]:checked'))
    .map((el) => el.value);
  hidden.value = ids.join(',');
}

function renderNucleiTemplatePicker(filter = '') {
  const box = document.getElementById('nucleiTemplatePicker');
  if (!box) return;
  const q = filter.trim().toLowerCase();
  const items = nucleiTemplatesCache.filter((t) => {
    if (!q) return true;
    return t.id.toLowerCase().includes(q) || (t.path || '').toLowerCase().includes(q);
  }).slice(0, 200);

  if (!items.length) {
    box.innerHTML = '<p class="text-muted small mb-0">Şablon bulunamadı.</p>';
    return;
  }

  box.innerHTML = items.map((t) => `
    <div class="nuclei-template-item custom-control custom-checkbox">
      <input class="custom-control-input" type="checkbox" name="nucleiTemplateIds"
             value="${t.id}" id="tpl-${t.id.replace(/[^a-z0-9_-]/gi, '_')}">
      <label class="custom-control-label" for="tpl-${t.id.replace(/[^a-z0-9_-]/gi, '_')}">${t.id}</label>
    </div>
  `).join('');

  box.querySelectorAll('input[name="nucleiTemplateIds"]').forEach((el) => {
    el.addEventListener('change', syncNucleiTemplateHidden);
  });
}

function loadNucleiTemplates() {
  const box = document.getElementById('nucleiTemplatePicker');
  if (!box || nucleiTemplatesCache.length) return;
  box.innerHTML = '<p class="text-muted small mb-0">Şablonlar yükleniyor…</p>';
  fetch('/api/nuclei-templates/')
    .then((r) => r.json())
    .then((data) => {
      nucleiTemplatesCache = data.templates || [];
      renderNucleiTemplatePicker(document.getElementById('nucleiTemplateSearch')?.value || '');
    })
    .catch(() => {
      box.innerHTML = '<p class="text-muted small mb-0">Şablon listesi alınamadı.</p>';
    });
}

function toggleOptions() {
  const selected = Array.from(document.querySelectorAll('input[name="choices"]:checked'))
    .map((el) => el.value);

  const map = {
    1: 'naabuOptions',
    2: 'subdomainOptions',
    3: 'waybackOptions',
    4: 'httpxOptions',
    5: 'nucleiOptions',
    7: 'katanaOptions',
  };

  Object.entries(map).forEach(([value, id]) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('d-none', !selected.includes(value));
  });

  if (selected.includes('5')) {
    loadNucleiTemplates();
  }
}

function toggleSubdomainOption() {
  const known = document.getElementById('waybackKnownUrls').checked;
  const container = document.getElementById('includeSubdomainsContainer');
  container.classList.toggle('d-none', !known);
}

function applyPreset(preset) {
  document.querySelectorAll('input[name="choices"]').forEach((el) => {
    el.checked = false;
  });

  const presets = {
    quick: ['2', '4'],
    deep: ['2', '6', '3', '4'],
    full: ['1', '2', '6', '3', '4', '7', '5'],
  };

  (presets[preset] || []).forEach((value) => {
    const input = document.querySelector(`input[name="choices"][value="${value}"]`);
    if (input) input.checked = true;
  });

  toggleOptions();
}

function fetchNucleiDataAndRenderChart(domain) {
  if (!domain) return;
  const scanId = document.body.dataset.scanId;
  const url = scanId ? `/scan/${scanId}/nuclei.json` : `/outputs/${domain}_nuclei.json/json`;

  fetch(url)
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
      <span class="legend-item"><span class="color-box" style="background:#d63939"></span> Critical</span>
      <span class="legend-item"><span class="color-box" style="background:#f76707"></span> High</span>
      <span class="legend-item"><span class="color-box" style="background:#f59f00"></span> Medium</span>
      <span class="legend-item"><span class="color-box" style="background:#2fb344"></span> Low</span>
      <span class="legend-item"><span class="color-box" style="background:#206bc4"></span> Info</span>
    </div>
  `;
}

function severityColor(severity) {
  const map = {
    critical: 'rgba(214, 57, 57, 0.75)',
    high: 'rgba(247, 103, 7, 0.75)',
    medium: 'rgba(245, 159, 0, 0.75)',
    low: 'rgba(47, 179, 68, 0.75)',
    info: 'rgba(32, 107, 196, 0.75)',
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
      plugins: { legend: { display: false } },
      scales: {
        y: {
          beginAtZero: true,
          max: 5,
          ticks: {
            stepSize: 1,
            callback: (v) => ['', 'Info', 'Low', 'Medium', 'High', 'Critical'][v] || '',
          },
        },
        x: { ticks: { maxRotation: 45 } },
      },
    },
  });
}

function showLoadingModal() {
  const modalEl = document.getElementById('loadingModal');
  if (modalEl && window.jQuery) {
    jQuery(modalEl).modal('show');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('input[name="choices"]').forEach((el) => {
    el.addEventListener('change', toggleOptions);
  });

  toggleOptions();

  const tplSearch = document.getElementById('nucleiTemplateSearch');
  if (tplSearch) {
    tplSearch.addEventListener('input', () => renderNucleiTemplatePicker(tplSearch.value));
  }

  const domain = document.body.dataset.domain;
  if (domain) fetchNucleiDataAndRenderChart(domain);

  const form = document.getElementById('scanForm');
  if (form) {
    form.addEventListener('submit', (e) => {
      const checked = document.querySelectorAll('input[name="choices"]:checked');
      if (!checked.length) {
        e.preventDefault();
        alert('Lütfen en az bir tarama modülü seçin.');
        return;
      }
      showLoadingModal();
    });
  }
});
