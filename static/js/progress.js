document.addEventListener('DOMContentLoaded', () => {
  const bar = document.getElementById('progressBar');
  const msg = document.getElementById('progressMessage');
  const pct = document.getElementById('progressPercent');
  const badge = document.getElementById('statusBadge');
  const moduleInfo = document.getElementById('moduleInfo');
  const liveLog = document.getElementById('liveLog');
  const logCount = document.getElementById('logCount');
  const moduleSteps = document.getElementById('moduleSteps');
  const navActions = document.getElementById('progressNavActions');

  let totalLogs = 0;
  const initialEl = document.getElementById('initial-logs-data');
  if (initialEl) {
    try {
      JSON.parse(initialEl.textContent).forEach(appendLog);
    } catch (e) {}
  }

  function appendLog(entry) {
    if (!liveLog || !entry.message) return;
    const line = document.createElement('div');
    line.className = `live-log-line live-log-${entry.level || 'info'}`;
    const time = entry.time ? `[${entry.time}] ` : '';
    const module = entry.module ? `{${entry.module}} ` : '';
    line.textContent = `${time}${module}${entry.message}`;
    liveLog.appendChild(line);
    liveLog.scrollTop = liveLog.scrollHeight;
    totalLogs += 1;
    if (logCount) logCount.textContent = `${totalLogs} satır`;
  }

  function updateModules(modules) {
    if (!moduleSteps || !Array.isArray(modules)) return;
    modules.forEach((mod) => {
      const el = moduleSteps.querySelector(`[data-module-id="${mod.id}"]`);
      if (!el) return;
      el.classList.remove(
        'module-step-pending',
        'module-step-running',
        'module-step-done',
        'module-step-failed',
      );
      el.classList.add(`module-step-${mod.state}`);
      const icon = el.querySelector('.module-step-icon i');
      if (!icon) return;
      icon.className = 'tim-icons ' + ({
        pending: 'icon-minimal-down',
        running: 'icon-refresh-01',
        done: 'icon-check-2',
        failed: 'icon-simple-remove',
        skipped: 'icon-minimal-down',
      }[mod.state] || 'icon-minimal-down');
    });
  }

  function showNavActions(status) {
    if (!navActions) return;
    navActions.classList.remove('d-none');
    const selectBtn = document.getElementById('goSelectSubdomains');
    const portBtn = document.getElementById('goSelectPorts');
    const resultsBtn = document.getElementById('goResults');
    if (selectBtn) {
      selectBtn.classList.toggle('d-none', status !== 'awaiting_subdomains');
    }
    if (portBtn) {
      portBtn.classList.toggle('d-none', status !== 'awaiting_ports');
    }
    if (resultsBtn) {
      resultsBtn.classList.toggle('d-none', status !== 'completed');
    }
  }

  function openSelectionModal(status) {
    if (status === 'awaiting_subdomains' && window.openSubdomainSelectModal) {
      window.openSubdomainSelectModal();
    }
    if (status === 'awaiting_ports' && window.openPortSelectModal) {
      window.openPortSelectModal();
    }
  }

  function handleStatus(data) {
    if (data.status === 'awaiting_subdomains') {
      badge.textContent = 'Alt Alan Seçimi';
      badge.className = 'badge badge-warning';
      msg.textContent = data.message || 'Alt alan seçimi bekleniyor…';
      showNavActions('awaiting_subdomains');
      source.close();
      setTimeout(() => openSelectionModal('awaiting_subdomains'), 400);
      return;
    }
    if (data.status === 'awaiting_ports') {
      badge.textContent = 'Port Seçimi';
      badge.className = 'badge badge-warning';
      msg.textContent = data.message || 'Nmap port seçimi bekleniyor…';
      showNavActions('awaiting_ports');
      source.close();
      setTimeout(() => openSelectionModal('awaiting_ports'), 400);
      return;
    }
    if (data.status === 'completed') {
      badge.textContent = 'Tamamlandı';
      badge.className = 'badge badge-success';
      showNavActions('completed');
      source.close();
      return;
    }
    if (data.status === 'cancelled') {
      badge.textContent = 'İptal Edildi';
      badge.className = 'badge badge-secondary';
      source.close();
      return;
    }
    if (data.status === 'failed') {
      badge.textContent = 'Başarısız';
      badge.className = 'badge badge-danger';
      msg.textContent = data.error || data.message || 'Tarama başarısız.';
      source.close();
    }
  }

  const source = new EventSource(window.SCAN_EVENTS_URL);

  source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    bar.style.width = `${data.percent}%`;
    pct.textContent = `${data.percent}%`;
    msg.textContent = data.message || 'İşleniyor…';
    if (data.module) {
      moduleInfo.textContent = `Aktif modül: ${data.module}`;
    }
    if (data.logs && data.logs.length) {
      data.logs.forEach(appendLog);
    }
    if (data.modules) {
      updateModules(data.modules);
    }
    if (data.skip_available) {
      const skipForm = document.getElementById('skipModuleForm');
      if (skipForm) skipForm.classList.remove('d-none');
    }
    handleStatus(data);
  };

  source.onerror = () => {
    source.close();
  };

  const initialStatus = document.getElementById('initial-scan-status');
  if (initialStatus) {
    const st = initialStatus.dataset.status;
    showNavActions(st);
    if (st === 'awaiting_subdomains' || st === 'awaiting_ports') {
      setTimeout(() => openSelectionModal(st), 500);
    }
  }

  document.getElementById('goSelectSubdomains')?.addEventListener('click', () => {
    openSelectionModal('awaiting_subdomains');
  });
  document.getElementById('goSelectPorts')?.addEventListener('click', () => {
    openSelectionModal('awaiting_ports');
  });
});
