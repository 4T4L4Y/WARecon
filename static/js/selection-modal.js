/**
 * Filtrelenebilir tik kutulu seçim listesi (alt alan / port modalları).
 */
function initFilterableSelectionList(options) {
  const {
    listEl,
    filterInput,
    selectAllBtn,
    clearAllBtn,
    checkboxClass,
    onFilter,
  } = options;

  function allRows() {
    return listEl.querySelectorAll(`.${checkboxClass}`);
  }

  function visibleRows() {
    return listEl.querySelectorAll(`.${checkboxClass}:not(.d-none)`);
  }

  function applyFilter() {
    const q = (filterInput?.value || '').trim().toLowerCase();
    allRows().forEach((row) => {
      const label = row.dataset.label || '';
      const match = !q || label.toLowerCase().includes(q);
      row.classList.toggle('d-none', !match);
    });
    if (onFilter) onFilter();
  }

  filterInput?.addEventListener('input', applyFilter);

  selectAllBtn?.addEventListener('click', () => {
    visibleRows().forEach((row) => {
      const cb = row.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = true;
    });
  });

  clearAllBtn?.addEventListener('click', () => {
    visibleRows().forEach((row) => {
      const cb = row.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = false;
    });
  });

  return {
    getSelectedValues() {
      const values = [];
      allRows().forEach((row) => {
        const cb = row.querySelector('input[type="checkbox"]');
        if (cb?.checked) values.push(cb.value);
      });
      return values;
    },
    setItems(html) {
      listEl.innerHTML = html;
      applyFilter();
    },
    applyFilter,
  };
}

function getCsrfToken() {
  const match = document.cookie.match(/csrftoken=([^;]+)/);
  if (match) return match[1];
  const input = document.querySelector('input[name="csrfmiddlewaretoken"]');
  return input ? input.value : '';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function buildHostCheckbox(host, index, checked) {
  const id = `host-pick-${index}`;
  return `
    <label class="selection-list-item selection-tick-row" data-label="${escapeHtml(host)}" for="${id}">
      <input class="selection-tick-input" type="checkbox"
             name="subdomains" value="${escapeHtml(host)}" id="${id}"
             ${checked ? 'checked' : ''}>
      <span class="selection-tick-box" aria-hidden="true"></span>
      <span class="selection-tick-text">${escapeHtml(host)}</span>
    </label>`;
}

function buildPortCheckbox(item, index, checked) {
  const label = `${item.host}:${item.port}`;
  const id = `port-pick-${index}`;
  return `
    <label class="selection-list-item selection-tick-row"
           data-label="${escapeHtml(label)} ${escapeHtml(item.host)}" for="${id}">
      <input class="selection-tick-input" type="checkbox"
             name="ports" value="${escapeHtml(item.id)}" id="${id}"
             ${checked ? 'checked' : ''}>
      <span class="selection-tick-box" aria-hidden="true"></span>
      <span class="selection-tick-text">
        <span class="text-info">${escapeHtml(item.host)}</span>
        <span class="text-muted">:</span>
        <span class="output-port open">${escapeHtml(item.port)}</span>
      </span>
    </label>`;
}

document.addEventListener('DOMContentLoaded', () => {
  const subdomainModal = document.getElementById('subdomainSelectModal');
  const portModal = document.getElementById('portSelectModal');
  if (!subdomainModal && !portModal) return;

  let subdomainListCtrl = null;
  let portListCtrl = null;

  if (subdomainModal) {
    subdomainListCtrl = initFilterableSelectionList({
      listEl: document.getElementById('subdomainSelectList'),
      filterInput: document.getElementById('subdomainFilter'),
      selectAllBtn: document.getElementById('subdomainSelectAll'),
      clearAllBtn: document.getElementById('subdomainClearAll'),
      checkboxClass: 'selection-list-item',
    });

    document.getElementById('subdomainSelectSubmit')?.addEventListener('click', async () => {
      const selected = subdomainListCtrl.getSelectedValues();
      if (!selected.length) {
        alert('En az bir alt alan seçmelisiniz.');
        return;
      }
      const body = new URLSearchParams();
      selected.forEach((h) => body.append('subdomains', h));
      ['run_wayback', 'run_httpx', 'run_nuclei', 'run_katana'].forEach((name) => {
        const el = document.getElementById(name);
        if (el?.checked) body.append(name, 'on');
      });
      const res = await fetch(window.SCAN_SUBDOMAIN_API, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken(), 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      const data = await res.json();
      if (!data.ok) {
        alert(data.error || 'Kaydedilemedi.');
        return;
      }
      $(subdomainModal).modal('hide');
      window.location.reload();
    });
  }

  if (portModal) {
    portListCtrl = initFilterableSelectionList({
      listEl: document.getElementById('portSelectList'),
      filterInput: document.getElementById('portFilter'),
      selectAllBtn: document.getElementById('portSelectAll'),
      clearAllBtn: document.getElementById('portClearAll'),
      checkboxClass: 'selection-list-item',
    });

    document.getElementById('portSelectSubmit')?.addEventListener('click', async () => {
      const selected = portListCtrl.getSelectedValues();
      const runNmap = document.getElementById('runNmapToggle')?.checked;
      if (runNmap && !selected.length) {
        alert('Nmap için en az bir port seçin veya Nmap\'i devre dışı bırakın.');
        return;
      }
      const body = new URLSearchParams();
      selected.forEach((p) => body.append('ports', p));
      if (runNmap) body.append('run_nmap', 'on');
      const res = await fetch(window.SCAN_PORT_API, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken(), 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      const data = await res.json();
      if (!data.ok) {
        alert(data.error || 'Kaydedilemedi.');
        return;
      }
      $(portModal).modal('hide');
      window.location.reload();
    });
  }

  window.openSubdomainSelectModal = async function openSubdomainSelectModal() {
    if (!subdomainModal || !subdomainListCtrl) return;
    const res = await fetch(window.SCAN_SUBDOMAIN_API);
    const data = await res.json();
    const html = (data.hosts || []).map((host, i) => buildHostCheckbox(host, i, i < 20)).join('');
    subdomainListCtrl.setItems(html || '<p class="text-muted mb-0">Alt alan yok.</p>');
    ['run_wayback', 'run_httpx', 'run_nuclei', 'run_katana'].forEach((id) => {
      const el = document.getElementById(id);
      if (el && data.web_flags) {
        const key = id.replace('run_', '');
        el.closest('.col-sm-6')?.classList.toggle('d-none', !data.web_flags[key]);
        el.checked = !!data.web_flags[key];
      }
    });
    document.getElementById('webModuleToggles')?.classList.toggle(
      'd-none',
      !data.web_flags || !Object.values(data.web_flags).some(Boolean),
    );
    $(subdomainModal).modal({ backdrop: 'static', keyboard: false, show: true });
  };

  window.openPortSelectModal = async function openPortSelectModal() {
    if (!portModal || !portListCtrl) return;
    const res = await fetch(window.SCAN_PORT_API);
    const data = await res.json();
    const html = (data.ports || []).map((item, i) => buildPortCheckbox(item, i, true)).join('');
    portListCtrl.setItems(html || '<p class="text-muted mb-0">Port bulunamadı.</p>');
    const runToggle = document.getElementById('runNmapToggle');
    if (runToggle) runToggle.checked = true;
    $(portModal).modal({ backdrop: 'static', keyboard: false, show: true });
  };
});
