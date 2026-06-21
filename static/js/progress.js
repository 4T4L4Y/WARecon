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
    const resultsBtn = document.getElementById('goResults');
    if (selectBtn) {
      selectBtn.classList.toggle('d-none', status !== 'awaiting_subdomains');
    }
    if (resultsBtn) {
      resultsBtn.classList.toggle('d-none', status !== 'completed');
    }
  }

  function handleStatus(data) {
    if (data.status === 'awaiting_subdomains') {
      badge.textContent = 'Alt Alan Seçimi';
      badge.className = 'badge badge-warning';
      msg.textContent = data.message || 'Alt alan seçimi bekleniyor…';
      showNavActions('awaiting_subdomains');
      source.close();
      if (window.SCAN_SELECT_URL) {
        setTimeout(() => { window.location.href = window.SCAN_SELECT_URL; }, 800);
      }
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
    showNavActions(initialStatus.dataset.status);
  }
});
