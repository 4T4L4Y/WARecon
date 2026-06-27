/**
 * Filtrelenebilir checkbox seçim listesi (alt alan / port modalları).
 */
function initFilterableSelectionList(options) {
  const {
    modalEl,
    listEl,
    filterInput,
    selectAllBtn,
    clearAllBtn,
    checkboxClass,
    onFilter,
  } = options;

  function allCheckboxes() {
    return listEl.querySelectorAll(`.${checkboxClass}`);
  }

  function visibleCheckboxes() {
    return listEl.querySelectorAll(`.${checkboxClass}:not(.d-none)`);
  }

  function applyFilter() {
    const q = (filterInput?.value || '').trim().toLowerCase();
    allCheckboxes().forEach((wrap) => {
      const label = wrap.dataset.label || '';
      const match = !q || label.toLowerCase().includes(q);
      wrap.classList.toggle('d-none', !match);
    });
    if (onFilter) onFilter();
  }

  filterInput?.addEventListener('input', applyFilter);

  // Satır boşluğuna tıklanınca seç (label/input kendi hâlinde çalışır)
  listEl.addEventListener('click', (event) => {
    const item = event.target.closest('.selection-list-item');
    if (!item || !listEl.contains(item) || event.target !== item) return;
    const cb = item.querySelector('input[type="checkbox"]');
    if (cb) cb.checked = !cb.checked;
  });

  selectAllBtn?.addEventListener('click', () => {
    visibleCheckboxes().forEach((wrap) => {
      const cb = wrap.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = true;
    });
  });

  clearAllBtn?.addEventListener('click', () => {
    visibleCheckboxes().forEach((wrap) => {
      const cb = wrap.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = false;
    });
  });

  return {
    getSelectedValues() {
      const values = [];
      allCheckboxes().forEach((wrap) => {
        const cb = wrap.querySelector('input[type="checkbox"]');
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
    <div class="selection-list-item form-check" data-label="${escapeHtml(host)}">
      <input class="form-check-input host-pick" type="checkbox"
             name="subdomains" value="${escapeHtml(host)}" id="${id}"
             ${checked ? 'checked' : ''}>
      <label class="form-check-label" for="${id}">${escapeHtml(host)}</label>
    </div>`;
}

function buildPortCheckbox(item, index, checked) {
  const label = `${item.host}:${item.port}`;
  const id = `port-pick-${index}`;
  return `
    <div class="selection-list-item form-check"
         data-label="${escapeHtml(label)} ${escapeHtml(item.host)}">
      <input class="form-check-input port-pick" type="checkbox"
             name="ports" value="${escapeHtml(item.id)}" id="${id}"
             ${checked ? 'checked' : ''}>
      <label class="form-check-label" for="${id}">
        <span class="text-info">${escapeHtml(item.host)}</span>
        <span class="text-muted">:</span>
        <span class="output-port open">${escapeHtml(item.port)}</span>
      </label>
    </div>`;
}

document.addEventListener('DOMContentLoaded', () => {
  const subdomainModal = document.getElementById('subdomainSelectModal');
  const portModal = document.getElementById('portSelectModal');
  if (!subdomainModal && !portModal) return;

  let subdomainListCtrl = null;
  let portListCtrl = null;

  if (subdomainModal) {
    subdomainListCtrl = initFilterableSelectionList({
      modalEl: subdomainModal,
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
      modalEl: portModal,
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
